"""Passive HTML, HTTP, structured-resource, and JavaScript relationship extraction."""

import hashlib
import json
import logging
import os
import posixpath
import re
import subprocess
import time
from http.cookies import CookieError, SimpleCookie
from urllib.parse import parse_qsl, urlsplit

from bs4 import BeautifulSoup
from lxml import etree

from shyhurricane.command_image import unix_command_image
from shyhurricane.graph.analyzer_diagnostics import stderr_summary
from shyhurricane.graph.artifacts import recovered_sources
from shyhurricane.graph.discovery_manifest import archive_ir, markup_emitter
from shyhurricane.graph.markup import scan_markup, scan_svg
from shyhurricane.graph.model import MAX_BYTES, Projection, identity, web_url
from shyhurricane.graph.policy import ANALYZER_VERSION, library_analysis
from shyhurricane.graph.svg import extract_svg, is_svg, svg_root
from shyhurricane.source_maps import javascript_url_from_map, source_map_url

logger = logging.getLogger(__name__)


def _successful_control(tag):
    """Controls included by FormData(form), without an explicit submitter."""
    if tag.name not in {"input", "select", "textarea"} or not tag.get("name") or tag.has_attr("disabled"):
        return False
    for fieldset in tag.find_parents("fieldset", disabled=True):
        legend = fieldset.find("legend", recursive=False)
        if legend is None or not any(parent is legend for parent in tag.parents):
            return False
    kind = tag.get("type", "").lower()
    return tag.name != "input" or (
        kind not in {"submit", "button", "reset", "image"}
        and (kind not in {"checkbox", "radio"} or tag.has_attr("checked"))
    )


def run_javascript(source: str, filename: str, mode=None, *, capture_id=None) -> dict:
    image = unix_command_image()
    mode = library_analysis(mode)
    started = time.monotonic()
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                *(["--name", os.environ["_SHYHURRICANE_PARSE_CONTAINER"]]
                  if "_SHYHURRICANE_PARSE_CONTAINER" in os.environ else []),
                "--network=none",
                "--memory=3g",
                "--cpus=2",
                "-i",
                image,
                "node",
                "--max-old-space-size=2048",
                "/opt/graph-analysis/analyze.cjs",
            ],
            input=json.dumps({"source": source, "filename": filename, "mode": mode}),
            text=True,
            capture_output=True,
            timeout=240,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        logger.warning(
            "JavaScript analyzer filename=%s image=%s mode=%s source_bytes=%s seconds=%.3f "
            "capture=%s error=%s exit_status=%s timeout=%s stderr=%s",
            filename.split("?", 1)[0].split("#", 1)[0], image, mode, len(source.encode("utf-8")),
            time.monotonic() - started, capture_id, type(error).__name__,
            error.returncode if isinstance(error, subprocess.CalledProcessError) else None,
            error.timeout if isinstance(error, subprocess.TimeoutExpired) else None,
            stderr_summary(error.stderr if isinstance(error, (subprocess.CalledProcessError,
                                                               subprocess.TimeoutExpired)) else None, source),
        )
        raise

    return json.loads(result.stdout)


def extract(
    event: dict, artifacts=None, *, open_world=False, javascript_runner=run_javascript, document_contexts=None,
    markup_offset=0, markup_limit=10000, record_discovery=True,
) -> Projection:
    mode = library_analysis(event.get("library_analysis"))
    runner = (
        (lambda source, filename: run_javascript(source, filename, mode, capture_id=event["id"]))
        if javascript_runner is run_javascript
        else javascript_runner
    )
    graph = Projection(event)
    graph.library_analysis = mode
    data = event["data"]
    page = graph.resource(graph.url, data["method"])
    origin_url = f"{urlsplit(graph.url).scheme}://{urlsplit(graph.url).netloc}/"
    origin = graph.node("origin", origin_url, url=origin_url, name=origin_url)
    graph.fact(page, origin, "HOSTED_AT", "http.resource", classification="observed")
    request_headers = {key.lower(): value for key, value in (data.get("request_headers") or {}).items()}
    response_headers = {key.lower(): value for key, value in (data.get("response_headers") or {}).items()}
    mime = response_headers.get("content-type", "").lower().split(";")[0]
    body = data.get("response_body") or ""
    refs = []

    def reference(
        value,
        kind,
        rule,
        *,
        base=None,
        method="GET",
        source=page,
        classification="declared",
        location="",
        context_capture_id=None,
    ):
        target_url = web_url(value, base or graph.url, fragment=kind == "NAVIGATES_TO")
        if not target_url:
            return None
        refs.append(target_url)
        if artifacts and record_discovery:
            artifacts.manifest.dependency(event["id"], target_url, kind)
        target = graph.resource(target_url, method)
        graph.fact(
            source,
            target,
            kind,
            rule,
            classification=classification,
            location=location,
            context_capture_id=context_capture_id,
        )
        return target

    referer = request_headers.get("referer")
    if referer:
        origin_only = urlsplit(referer).path in {"", "/"} and not urlsplit(referer).query
        referring_url = web_url(referer)
        if referring_url:
            source = graph.resource(referring_url)
            # A root URL may be a page or an origin-only Referer. Never assert a journey from it.
            navigate = request_headers.get("sec-fetch-mode") == "navigate" and not origin_only
            graph.fact(
                source,
                page,
                "NAVIGATES_TO" if navigate else "REFERRED_REQUEST",
                "http.referer",
                classification="observed",
                location="request.headers.Referer",
            )
    if request_headers.get("origin"):
        reference(request_headers["origin"], "REQUEST_ORIGIN", "http.origin", classification="observed")
    for value, response in ((request_headers.get("cookie"), False), (response_headers.get("set-cookie"), True)):
        if not value:
            continue
        try:
            cookies = SimpleCookie()
            cookies.load(value)
            for name, morsel in cookies.items():
                cookie = graph.node(
                    "cookie",
                    identity(event["id"], name, response),
                    name=name,
                    role="sink" if response else "source",
                    domain=morsel["domain"],
                    path=morsel["path"],
                    secure=bool(morsel["secure"]),
                    http_only=bool(morsel["httponly"]),
                )
                graph.fact(
                    page if response else cookie,
                    cookie if response else page,
                    "SETS_COOKIE" if response else "SENDS_COOKIE",
                    "http.cookie",
                    classification="observed",
                )
        except CookieError:
            graph.gaps.append("Malformed cookie header")
    if response_headers.get("access-control-allow-origin"):
        reference(response_headers["access-control-allow-origin"], "ALLOWS_ORIGIN", "http.cors-policy")
    for directive in response_headers.get("content-security-policy", "").split(";"):
        parts = directive.split()
        if parts and parts[0] in {"connect-src", "form-action", "frame-src", "script-src"}:
            for value in parts[1:]:
                if value.startswith(("https://", "http://", "wss://", "ws://")):
                    reference(value, "ALLOWS_CONNECTION", f"http.csp.{parts[0]}")
    if 300 <= int(data.get("response_code") or 0) < 400 and response_headers.get("location"):
        reference(response_headers["location"], "REDIRECTS_TO", "http.location", classification="observed")
    refresh = response_headers.get("refresh", "")
    match = re.search(r"url\s*=\s*['\"]?([^'\"]+)", refresh, re.I)
    if match:
        reference(match[1], "NAVIGATES_TO", "http.refresh")
    for match in re.finditer(r"<([^>]+)>\s*;\s*rel=[\"\']?([^,;\"\']+)", response_headers.get("link", "")):
        reference(match[1], "RESOURCE_LINK", f"http.link.{match[2].strip()}")
    for name, _ in parse_qsl(urlsplit(graph.url).query, keep_blank_values=True):
        field = graph.node("field", f"{data['method']} {graph.url}:query:{name}", name=name, role="source")
        graph.fact(field, page, "SENDS_FIELD", "http.query", classification="observed")
    request_body = data.get("request_body") or ""
    request_mime = request_headers.get("content-type", "")
    if "json" in request_mime:
        try:
            parsed = json.loads(request_body)
            fields = list(parsed) if isinstance(parsed, dict) else []
        except (ValueError, TypeError):
            fields = []
            graph.gaps.append("Malformed JSON request body")
    else:
        fields = (
            [name for name, _ in parse_qsl(request_body, keep_blank_values=True)]
            if "urlencoded" in request_mime
            else []
        )
    for name in fields:
        field = graph.node("field", f"{data['method']} {graph.url}:body:{name}", name=name, role="sink")
        graph.fact(page, field, "SENDS_FIELD", "http.body", classification="observed")
    for index, form in enumerate(data.get("forms") or []):
        if not isinstance(form, dict):
            continue
        target = reference(
            form.get("action") or graph.url,
            "SUBMITS_TO",
            "ingest.form",
            method=form.get("method") or "GET",
            location=f"forms:{index}",
        )
        for name in form.get("inputs") or []:
            name = name.get("name") if isinstance(name, dict) else name
            if target and isinstance(name, str):
                field = graph.node("field", identity(event["id"], "form", index, name), name=name, role="source")
                graph.fact(field, target, "SUBMITS_TO", "ingest.form-field", location=f"forms:{index}")
    scripts = []
    oversized = len(body.encode()) > MAX_BYTES
    markup_locators = []
    if "html" in mime or body.lstrip().lower().startswith(("<!doctype html", "<html")) or is_svg(mime):
        try:
            from contextlib import nullcontext

            with artifacts.manifest.batch() if artifacts else nullcontext():
                emitter = markup_emitter(artifacts, event, graph.url) if artifacts and record_discovery else None
                body, deferred = (scan_svg if is_svg(mime) else scan_markup)(
                    body, emitter or (lambda record: None), maximum=markup_limit,
                    offset=markup_offset, locators=markup_locators,
                )
                if emitter:
                    emitter.finish()
        except etree.XMLSyntaxError:
            body, deferred = "", 0
            graph.gaps.append("Malformed SVG response")
        if artifacts and record_discovery:
            artifacts.manifest.unit(event["id"], graph.url, discovery="complete",
                                    flow="partial" if deferred else "complete")
        if deferred:
            graph.gaps.append("Markup detail deferred; complete declarations remain in discovery manifest")
    if (oversized and record_discovery) or len(body.encode()) > MAX_BYTES:
        graph.gaps.append("Response exceeds 40 MiB analysis limit")
        body = ""
    if "html" in mime or body.lstrip().lower().startswith(("<!doctype html", "<html")):
        soup = BeautifulSoup(body, "html.parser")
        base_element = soup.find("base", href=True)
        base = web_url(base_element["href"], graph.url) if base_element else graph.url
        tags = soup.find_all(True)
        locations = {id(tag): markup_locators[index] for index, tag in enumerate(tags) if index < len(markup_locators)}
        for index, tag in enumerate(tags):
            if index >= 10000:
                graph.gaps.append("HTML element budget reached")
                break
            if tag.name == "svg" and tag.find_parent("svg") is None:
                extract_svg(tag, graph, page, reference, scripts, base, inline=True, prefix=f"html:{index}:svg",
                            locators=locations)
            if tag.name == "svg" or tag.find_parent("svg") is not None:
                continue
            locator = locations.get(id(tag), f"html:{index}:{tag.name}")
            owner = (
                (soup.find("form", id=tag["form"]) if tag.get("form") else None)
                if tag.has_attr("form")
                else tag.find_parent("form")
            )
            form_selectors = []
            if owner:
                if owner.get("id"):
                    form_selectors.append(f"#{owner['id']}")
                if owner.get("name"):
                    form_selectors.append(f'form[name="{owner["name"]}"]')
            editable = tag.get("contenteditable", "false").lower() in {"", "true", "plaintext-only"}
            inline_events = [name for name in tag.attrs if name in {
                "oninput", "onchange", "onsubmit", "onclick", "onkeydown", "onkeyup"
            }]
            ui_origin = tag.name in {"input", "select", "textarea", "button", "form", "a"} or editable
            ui_origin = ui_origin or bool(inline_events) or tag.has_attr("tabindex")
            element = graph.node(
                "element",
                identity(event["id"], locator),
                name=tag.get("id") or tag.name,
                html_id=tag.get("id"),
                field_name=tag.get("name"),
                html_tag=tag.name,
                ui_origin=ui_origin,
                inline_selector=f"@inline:{locator}" if inline_events else None,
                location=locator,
                form_selectors=form_selectors,
                disabled=tag.has_attr("disabled"),
                form_successful=_successful_control(tag),
                role="source" if ui_origin else "",
                capture_id=event["id"],
            )
            graph.fact(page, element, "CONTAINS", "html.element", location=locator)
            if tag.name in {"a", "area"} and tag.get("href"):
                reference(tag["href"], "NAVIGATES_TO", "html.link", base=base, location=locator)
            if tag.get("src"):
                reference(tag["src"], "LOADS", "html.src", base=base, location=locator)
            if tag.name == "link" and tag.get("href"):
                reference(tag["href"], "LOADS", "html.link-resource", base=base, location=locator)
            if tag.name == "meta" and str(tag.get("http-equiv", "")).lower() == "refresh":
                match = re.search(r"url\s*=\s*['\"]?([^'\"]+)", tag.get("content", ""), re.I)
                if match:
                    reference(match[1], "NAVIGATES_TO", "html.refresh", base=base, location=locator)
            if tag.name == "form":
                action = tag.get("action") or graph.url
                method = tag.get("method", "GET").upper()
                method = method if method in {"GET", "POST", "DIALOG"} else "GET"
                target = (
                    reference(action, "SUBMITS_TO", "html.form", base=base, method=method, location=locator)
                    if method != "DIALOG"
                    else None
                )
                if element in graph.nodes and target in graph.nodes:
                    graph.nodes[element]["form_target_url"] = graph.nodes[target]["url"]
                    graph.nodes[element]["form_target_method"] = method
                controls = list(tag.find_all(["input", "textarea", "select", "button"]))
                if tag.get("id"):
                    controls += soup.find_all(attrs={"form": tag["id"]})
                for control in controls:
                    if control.get("formaction"):
                        override_method = control.get("formmethod", method).upper()
                        override_method = override_method if override_method in {"GET", "POST", "DIALOG"} else "GET"
                        if override_method == "DIALOG":
                            continue
                        reference(
                            control["formaction"],
                            "SUBMITS_TO",
                            "html.form-override",
                            base=base,
                            method=override_method,
                            location=locator,
                        )
                    if control.has_attr("form") and control["form"] != tag.get("id"):
                        continue
                    if _successful_control(control) and target:
                        field = graph.node(
                            "field",
                            identity(event["id"], locator, control["name"]),
                            name=control["name"],
                            role="source",
                        )
                        graph.fact(field, target, "SUBMITS_TO", "html.form-field", location=locator)
            if tag.name == "script" and not tag.get("src") and tag.string:
                if tag.get("type", "").lower() in {"", "module", "text/javascript", "application/javascript"}:
                    scripts.append((locator, tag.string))
                elif tag.get("type") == "importmap":
                    try:
                        for specifier, value in json.loads(tag.string).get("imports", {}).items():
                            reference(value, "IMPORTS", f"html.importmap.{specifier}", base=base, location=locator)
                    except (ValueError, AttributeError):
                        graph.gaps.append("Malformed import map")
            for name, value in tag.attrs.items():
                if name.startswith("on") and isinstance(value, str):
                    scripts.append((f"{locator}:{name}", value))
    elif is_svg(mime):
        base = graph.url
        try:
            root = svg_root(body)
            tags = list(root.iter())
            locations = {id(tag): markup_locators[index] for index, tag in enumerate(tags)
                         if index < len(markup_locators)}
            extract_svg(root, graph, page, reference, scripts, base, locators=locations)
        except etree.XMLSyntaxError:
            graph.gaps.append("Malformed SVG response")
    elif "javascript" in mime or urlsplit(graph.url).path.lower().endswith((".js", ".mjs", ".jsx", ".ts", ".tsx")):
        source_map = (
            artifacts.source_map(
                graph.url,
                body,
                data.get("request_headers") or {},
                open_world and not event["backfill"],
                response_headers=data.get("response_headers"),
                observed_at=event["observed_at"],
            )
            if artifacts
            else None
        )
        map_url = source_map_url(graph.url)
        if map_url:
            refs.append(map_url)
        hint = response_headers.get("sourcemap") or response_headers.get("x-sourcemap")
        match = re.search(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)", body)
        hint = hint or (match[1].rstrip("*/") if match else None)
        if hint and web_url(hint, graph.url):
            refs.append(web_url(hint, graph.url))
        embedded_map = bool(hint and hint.startswith("data:"))
        sources = recovered_sources(source_map) if source_map and embedded_map else []
        if source_map and not embedded_map:
            graph.candidate_sources.append({
                "source_digest": identity(body), "map_digest": identity(source_map),
                "association": "unverified_external",
                "artifact": artifacts.write(identity("candidate-map", source_map), {"source_map": source_map}),
            })
            graph.gaps.append("External source map is unverified; delivered JavaScript remains authoritative")
        if not sources and artifacts:
            from shyhurricane.javascript_deobfuscation import deobfuscate_javascript

            body = artifacts.deobfuscate(body, deobfuscate_javascript)
        scripts = sources or [(graph.url, body)]
        if source_map and embedded_map and not sources:
            graph.gaps.append("Source map has no embedded sources; using delivered JavaScript")
    elif javascript_url_from_map(graph.url):
        try:
            recovered_sources(body)  # Validate the supplied map without treating it as delivered code.
            graph.candidate_sources.append({
                "map_digest": identity(body), "map_capture_id": event["id"],
                "association": "unverified_standalone",
                "artifact": artifacts.write(identity("candidate-map", body), {"source_map": body})
                if artifacts else "",
            })
            graph.gaps.append("Standalone source map is unverified candidate evidence")
            refs.append(javascript_url_from_map(graph.url))
        except (ValueError, AttributeError):
            graph.gaps.append("Malformed source map")
    elif "css" in mime:
        for match in re.finditer(r"(?:url\(|@import\s+)[\"']?([^\"')\s;]+)", body):
            reference(match[1], "LOADS", "css.resource")
    elif "json" in mime:
        try:
            structured = json.loads(body)
            if isinstance(structured, dict):
                # Vite build manifests expose explicit chunk dependencies without source-code access.
                for key, chunk in structured.items():
                    if isinstance(chunk, dict) and isinstance(chunk.get("file"), str):
                        entry = reference(chunk["file"], "DESCRIBES_ASSET", "vite.manifest")
                        for field in ("imports", "dynamicImports", "css", "assets"):
                            for dependency in chunk.get(field, []):
                                resolved = structured.get(dependency, {})
                                value = resolved.get("file", dependency) if isinstance(resolved, dict) else dependency
                                reference(
                                    value,
                                    "IMPORTS" if "mport" in field else "LOADS",
                                    "vite.manifest",
                                    source=entry or page,
                                )
                for path, operations in structured.get("paths", {}).items():
                    if isinstance(operations, dict):
                        for method in operations:
                            if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}:
                                reference(path, "DECLARES_ENDPOINT", "openapi.operation", method=method)
                for item in structured.get("links", []):
                    if isinstance(item, dict) and isinstance(item.get("href"), str):
                        reference(item["href"], "RESOURCE_LINK", "manifest.link")
                if structured.get("start_url"):
                    reference(structured["start_url"], "NAVIGATES_TO", "manifest.start_url")
        except (ValueError, AttributeError, TypeError):
            graph.gaps.append("Malformed structured response")
    for filename, source in scripts:
        started = time.monotonic()
        logger.debug("Graph capture %s JavaScript analysis starting", event["id"])
        try:
            result = (
                artifacts.cached(
                    identity("js-ir", ANALYZER_VERSION, mode, filename, source), lambda: runner(source, filename)
                )
                if artifacts
                else runner(source, filename)
            )
            source_digest = hashlib.sha256(source.encode()).hexdigest()
            result = {**result, "source_sha256": source_digest}
            if "archive" in result:
                result["archive"] = {**result["archive"], "source_sha256": source_digest}
            contexts = []
            if "html" in mime or is_svg(mime):
                contexts.append({"url": graph.url, "base": base, "id": event["id"]})
            elif document_contexts is not None:
                contexts.extend(document_contexts)
            elif artifacts:
                documents, truncated = artifacts.consuming_documents(javascript_url_from_map(graph.url) or graph.url)
                if truncated:
                    graph.gaps.append("Consuming-document dependency budget reached")
                for dependent in documents:
                    captured = dependent["data"]
                    headers = {key.lower(): value for key, value in captured.get("response_headers", {}).items()}
                    if is_svg(headers.get("content-type", "")):
                        contexts.append({"url": captured["url"], "id": dependent["id"], "base": captured["url"]})
                    elif "html" in headers.get("content-type", ""):
                        soup = BeautifulSoup(captured.get("response_body") or "", "html.parser")
                        base_tag = soup.find("base", href=True)
                        contexts.append(
                            {
                                "url": captured["url"],
                                "id": dependent["id"],
                                "base": web_url(base_tag["href"], captured["url"]) if base_tag else captured["url"],
                            }
                        )
            if artifacts and record_discovery:
                archive_ir(artifacts, event, graph.url, filename, result, contexts=contexts)
            apply_javascript(graph, page, filename, result, reference, contexts)
            graph.gaps.extend(result.get("gaps", []))
            logger.info(
                "Graph capture %s JavaScript analysis finished nodes=%s edges=%s seconds=%.3f",
                event["id"],
                len(graph.nodes),
                len(graph.edges),
                time.monotonic() - started,
            )
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            graph.gaps.append(f"JavaScript analysis unavailable: {type(error).__name__}")
            logger.warning(
                "Graph capture %s JavaScript analysis failed error=%s seconds=%.3f",
                event["id"],
                type(error).__name__,
                time.monotonic() - started,
                exc_info=True,
            )
    if event["backfill"]:
        graph.gaps.append("Backfilled stored representation; original capture fields may be unavailable")
    if artifacts and record_discovery:
        artifacts.references(event["id"], refs)
        artifacts.manifest.archive(graph, artifacts.write)
    return graph


def apply_javascript(graph, page, filename, result, reference, contexts):
    limits = graph.node_limit, graph.edge_limit
    before = len(graph.nodes), len(graph.edges)
    gaps_before = len(graph.gaps)
    summary = result.get("analysis", {}).get("mode") == "summary"
    if summary:
        graph.node_limit = min(graph.node_limit, before[0] + 1000)
        graph.edge_limit = min(graph.edge_limit, before[1] + 2000)
    try:
        _apply_javascript(graph, page, filename, result, reference, contexts)
    finally:
        graph.node_limit, graph.edge_limit = limits
    graph.analysis[-1].update(
        published_nodes=len(graph.nodes) - before[0], published_edges=len(graph.edges) - before[1]
    )
    if summary:
        publication_limited = any("budget reached" in gap for gap in graph.gaps[gaps_before:]) or (
            len(graph.nodes) >= min(limits[0], before[0] + 1000) and "Capture entity budget reached" in graph.gaps
            or len(graph.edges) >= min(limits[1], before[1] + 2000)
            and "Capture relationship budget reached" in graph.gaps
        )
        graph.analysis[-1]["publication_limited"] = publication_limited
        graph.analysis[-1]["budget_limited"] = graph.analysis[-1].get("budget_limited", False) or publication_limited
    graph.nodes[page]["analysis_details"] = json.dumps(graph.analysis, sort_keys=True)


def _apply_javascript(graph, page, filename, result, reference, contexts):
    analysis = {**result.get("analysis", {"mode": "full"}), "source_path": filename}
    graph.analysis.append(analysis)
    symbols = {}
    bundle_url = javascript_url_from_map(graph.url) or graph.url
    recovered = filename != graph.url
    module_key = f"{bundle_url}#source={posixpath.normpath(filename)}" if recovered else graph.url
    graph.contexts.extend(context for context in contexts if context not in graph.contexts)
    graph.nodes[page]["context_urls"] = [context["url"] for context in contexts]
    graph.nodes[page]["analysis_details"] = json.dumps(graph.analysis, sort_keys=True)
    origins = {f"{urlsplit(context['base']).scheme}://{urlsplit(context['base']).netloc}" for context in contexts}
    containments = []
    for item in result.get("nodes", []):
        import_url = item.get("import_url")
        if import_url:
            if recovered and import_url.startswith("."):
                import_key = (
                    f"{bundle_url}#source={posixpath.normpath(posixpath.join(posixpath.dirname(filename), import_url))}"
                )
            else:
                import_key = web_url(import_url, graph.url) if import_url.startswith((".", "/", "http")) else None
        else:
            import_key = None
        node_key = (
            identity(
                sorted(origins),
                item["name"],
                (
                    "persistent"
                    if len(origins) == 1 and item.get("name", "").startswith("localStorage:")
                    else graph.event["id"]
                ),
            )
            if item.get("kind") == "storage"
            else identity(graph.event["id"], filename, item["id"])
        )
        symbols[item["id"]] = graph.node(
            item.get("kind", "symbol"),
            node_key,
            name=item.get("name", ""),
            role=item.get("role", ""),
            persistent_storage=(item.get("kind") == "storage" and len(origins) == 1
                                and item.get("name", "").startswith("localStorage:")),
            source_path=filename,
            source_sha256=result.get("source_sha256"),
            location=item.get("location", ""),
            module_key=module_key,
            import_key=import_key,
            imported_name=item.get("imported_name"),
            export_name=item.get("export_name"),
            export_names=item.get("export_names") or ([item["reexport_name"]] if item.get("reexport_name") else None),
            parameter_index=item.get("parameter_index"),
            return_value=item.get("return_value"),
            callback_boundary=item.get("callback_boundary"),
            selector=item.get("selector"),
            ui_event=item.get("ui_event"),
            form_data=item.get("form_data"),
            form_field=item.get("form_field"),
            form_request=item.get("form_request"),
            reexport_name=item.get("reexport_name"),
            context_urls=[context["url"] for context in contexts],
            capture_id=None if item.get("kind") == "storage" else graph.event["id"],
        )
        containments.append(item)
        if analysis["mode"] != "summary":
            graph.fact(
                page,
                symbols[item["id"]],
                "CONTAINS",
                "js.symbol",
                location=f"{filename}:{item.get('location', '')}",
                snippet=item.get("snippet", ""),
            )
    for edge in result.get("edges", []):
        if edge["source"] in symbols and edge["target"] in symbols:
            graph.fact(
                symbols[edge["source"]],
                symbols[edge["target"]],
                edge["kind"],
                edge.get("rule", "js.def-use"),
                classification="statically_inferred",
                location=f"{filename}:{edge.get('location', '')}",
                snippet=edge.get("snippet", ""),
                **{
                    key: edge[key]
                    for key in ("original_hops", "endpoint_locations", "witness", "summary_notice")
                    if key in edge
                },
            )
    if analysis["mode"] == "summary":
        for item in containments:
            graph.fact(
                page,
                symbols[item["id"]],
                "CONTAINS",
                "js.symbol",
                location=f"{filename}:{item.get('location', '')}",
                snippet=item.get("snippet", ""),
            )
    for item in result.get("references", []):
        source = symbols.get(item.get("source"), page)
        location = f"{filename}:{item.get('location', '')}"
        if item["kind"] == "IMPORTS":
            if recovered and item["url"].startswith("."):
                virtual_path = posixpath.normpath(posixpath.join(posixpath.dirname(filename), item["url"]))
                module = graph.node(
                    "module_reference",
                    f"{bundle_url}#source={virtual_path}",
                    name=item["url"],
                )
                graph.fact(source, module, "IMPORTS", "js.recovered-import", location=location)
            else:
                reference(item["url"], "IMPORTS", "js.import", base=graph.url, source=source, location=location)
            continue
        absolute = web_url(item["url"])
        targets = contexts or ([{"url": None, "base": graph.url, "id": None}] if absolute else [])
        if not targets:
            if item["url"] not in graph.browser_references:
                graph.browser_references.append(item["url"])
            unresolved = graph.node(
                "reference", identity(graph.event["id"], filename, location, item["url"]), name=item["url"]
            )
            graph.fact(source, unresolved, "UNRESOLVED_REFERENCE", "js.document-context", location=location)
            graph.gaps.append("Browser-relative reference requires an ingested consuming document")
        for context in targets:
            target = reference(
                item["url"],
                item["kind"],
                item.get("rule", "js.reference"),
                base=context["base"],
                source=source,
                method=item.get("method", "GET"),
                classification="statically_inferred",
                location=location,
                context_capture_id=context["id"],
            )
            if target and item["kind"] in {"NAVIGATES_TO", "SUBMITS_TO"} and context["url"]:
                document = graph.resource(web_url(context["url"]))
                graph.fact(
                    document,
                    target,
                    item["kind"],
                    "js.page-navigation",
                    classification="statically_inferred",
                    location=location,
                    context_capture_id=context["id"],
                )
