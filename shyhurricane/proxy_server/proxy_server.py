#
# Async HTTP replay proxy with HTTPS MITM.
# - CONNECT (HTTP/1.1) → TLS with ALPN (h2 preferred, http/1.1 fallback)
# - HTTP/2: handles GET/HEAD/POST/PUT (reads/ignores body)
# - HTTP/1.1 (inside TLS): handles GET/HEAD/POST/PUT (reads/ignores body)
# - Per-host leaf certs minted from an in-memory CA (cryptography)
#
import asyncio, base64, json, os, ssl
import contextlib
import logging
import sys
import traceback
from asyncio import Server
from http import HTTPStatus
from os import PathLike
from pathlib import Path
from typing import Dict, Optional, Tuple, Set, Iterable

from cachetools import TTLCache
from chromadb.api.models.AsyncCollection import AsyncCollection
from cryptography.hazmat._oid import ExtendedKeyUsageOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived, StreamEnded, ConnectionTerminated, WindowUpdated

import chromadb

from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.target_info import parse_target_info
from shyhurricane.utils import urlparse_ext

CRLF = b"\r\n"
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
       "content-length", "content-encoding"}

logger = logging.getLogger(__name__)


#
# Chroma Store to serve up the indexed content.
#
class ContentStore:
    def __init__(self, collection: AsyncCollection, default_status=200):
        self.collection = collection
        self.default_status = default_status
        self.recommend_urls_cache = TTLCache(maxsize=100, ttl=60)

    async def lookup(self, url: str, method: str = "GET") -> Optional[Tuple[int, Dict[str, str], bytes]]:
        where = {"$and": [{"version": WEB_RESOURCE_VERSION}, {"url": url}, {"http_method": method}]}
        res = await self.collection.get(where=where, include=["metadatas", "documents"], limit=1)
        docs = res.get("documents") or []
        metas = res.get("metadatas") or []
        if not docs or not docs[0]:
            return None
        body_text = docs[0]
        meta = metas[0] if metas and metas[0] else {}

        try:
            headers = json.loads(meta.get("response_headers") or "{}")
        except Exception:
            headers = {}

        status = meta.get("status_code", self.default_status)

        if headers.get("Content-Transfer-Encoding", "").lower() == "base64":
            try:
                body = base64.b64decode(body_text)
            except Exception:
                body = b""
            headers.pop("Content-Transfer-Encoding", None)
        else:
            # FIXME: check encoding in Content-Type
            body = (body_text or "").encode("utf-8", errors="replace")

        return status, {str(k): str(v) for k, v in headers.items()}, body

    async def recommend_urls(self, requested_url: str) -> Set[str]:
        netloc = set()
        urls_in_domain = set()
        urls_with_path = set()

        try:
            requested_target_info = parse_target_info(requested_url)
            requested_url_parsed = urlparse_ext(requested_url)
            cache_key = requested_target_info.netloc
            domains_only = False
            metadatas = self.recommend_urls_cache.get(cache_key, None)
            if metadatas is None:
                where = {"$and": [
                    {"version": WEB_RESOURCE_VERSION},
                    {"netloc": cache_key},
                    {"http_method": "GET"}
                ]}
                limit = 1000
                res = await self.collection.get(where=where, include=["metadatas"], limit=limit)
                metadatas = res.get("metadatas") or []
                self.recommend_urls_cache[cache_key] = metadatas
        except ValueError:
            requested_url_parsed = None
            domains_only = True
            metadatas = []

        if len(metadatas) == 0:
            domains_only = True
            metadatas = self.recommend_urls_cache.get('domains', None)
            if metadatas is None:
                requested_url_parsed = None
                where = {"$and": [
                    {"version": WEB_RESOURCE_VERSION},
                    {"http_method": "GET"}
                ]}
                limit = 10_000
                res = await self.collection.get(where=where, include=["metadatas"], limit=limit)
                metadatas = res.get("metadatas") or []
                self.recommend_urls_cache['domains'] = metadatas

        for md in metadatas:
            netloc.add(md["netloc"])
            if domains_only:
                continue
            url = md["url"]
            urls_in_domain.add(url)
            if requested_url_parsed:
                try:
                    parsed_url = urlparse_ext(url)
                    if parsed_url.path.startswith(requested_url_parsed.path):
                        urls_with_path.add(url)
                except ValueError:
                    pass

        return urls_with_path or urls_in_domain or set(map(lambda e: parse_target_info(e).to_url(), netloc))


def have_cryptography() -> bool:
    try:
        import cryptography  # noqa
        return True
    except Exception:
        return False


class CertAuthority:
    """
    TLS CA + per-host certs
    """

    def __init__(self, cert_dir: PathLike, ca_cn="Replay MITM CA", ca_days=3650):
        if not have_cryptography():
            raise RuntimeError("cryptography is required for per-host certs")
        self.cert_dir = cert_dir
        self.ca_cert = Path(cert_dir, "ca.pem")
        self.ca_key = Path(cert_dir, "ca.key")
        self._contexts: Dict[str, ssl.SSLContext] = {}
        self._create_ca(ca_cn, ca_days)
        self.base_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tune_ctx_for_h2(self.base_ctx)
        self.base_ctx.load_cert_chain(self.ca_cert, self.ca_key)
        self.base_ctx.set_servername_callback(self._sni_cb)

    def _tune_ctx_for_h2(self, ctx: ssl.SSLContext) -> ssl.SSLContext:
        # Force TLS 1.2+ (HTTP/2 forbids TLS < 1.2)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Some older LibreSSL builds + h2 negotiate more reliably without TLS 1.3:
        # comment out the next line if your client supports TLS 1.3 cleanly.
        # ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        # HTTP/2 cipher suite constraints (no RC4, no 3DES, no CBC, etc.)
        # Prefer AEAD suites that most stacks share.
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:@STRENGTH")

        # ALPN: offer h2 first, then http/1.1
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            print("h2 not supported", file=sys.stderr)
            pass  # ALPN not available; HTTP/2 won't be negotiated

        # Misc hardening / compatibility
        ctx.options |= ssl.OP_NO_COMPRESSION
        return ctx

    def _create_ca(self, cn: str, days: int):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(self.ca_key, "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=serialization.NoEncryption()))
        with open(self.ca_cert, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def mint_ctx_for_host(self, host: str) -> ssl.SSLContext:
        if host in self._contexts:
            return self._contexts[host]
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        import datetime
        cert_path = Path(self.cert_dir, f"{host}.pem")
        key_path = Path(self.cert_dir, f"{host}.key")
        with open(self.ca_key, "rb") as f: ca_key = load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert, "rb") as f: ca_cert = x509.load_pem_x509_certificate(f.read())

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        san = x509.SubjectAlternativeName([x509.DNSName(host)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(self.ca_cert, "rb") as caf:
                f.write(caf.read())

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tune_ctx_for_h2(ctx)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self._contexts[host] = ctx
        return ctx

    def _sni_cb(self, sslobj: ssl.SSLObject, server_name: str, ctx: ssl.SSLContext):
        host = server_name or "localhost"
        try:
            sslobj.context = self.mint_ctx_for_host(host)
        except Exception:
            pass


class QuietReaderProtocol(asyncio.StreamReaderProtocol):
    def eof_received(self) -> bool:  # type: ignore[override]
        # Under SSL, returning True has no effect and triggers a warning.
        # Return False to keep asyncio quiet.
        return False


class ReplayProxy:
    def __init__(self, store: ContentStore, ca: CertAuthority):
        self.store = store
        self.ca = ca

    @staticmethod
    async def read_line(reader: asyncio.StreamReader, timeout=30.0) -> bytes:
        return await asyncio.wait_for(reader.readline(), timeout)

    @staticmethod
    async def _safe_close(writer: asyncio.StreamWriter):
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def drain_with_timeout(writer: asyncio.StreamWriter, timeout: float = 0.5) -> None:
        try:
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            # peer isn't reading / transport already closing; just move on
            pass
        except Exception:
            # defensive: don't let rare SSL errors wedge the loop
            pass

    @staticmethod
    async def read_headers(reader: asyncio.StreamReader, timeout=30.0) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        while True:
            line = await ReplayProxy.read_line(reader, timeout)
            if not line or line == CRLF:
                break
            try:
                k, v = line.decode("iso-8859-1").rstrip("\r\n").split(":", 1)
                headers[k.strip()] = v.strip()
            except ValueError:
                pass
        return headers

    @staticmethod
    async def read_body_http11(reader: asyncio.StreamReader, headers: Dict[str, str]) -> bytes:
        # Drain body for POST/PUT. Nuclei typically uses Content-Length; handle chunked minimally.
        body = b""
        te = headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            while True:
                line = await ReplayProxy.read_line(reader)
                if not line:
                    break
                size_str = line.strip().split(b";", 1)[0]
                try:
                    size = int(size_str, 16)
                except Exception:
                    break
                if size == 0:
                    # consume trailing CRLF and optional trailer headers
                    _ = await ReplayProxy.read_line(reader)
                    break
                chunk = await reader.readexactly(size)
                body += chunk
                _ = await ReplayProxy.read_line(reader)  # CRLF after chunk
        else:
            try:
                clen = int(headers.get("Content-Length", "0"))
            except Exception:
                clen = 0
            if clen > 0:
                body = await reader.readexactly(clen)
        return body

    @staticmethod
    def not_found_html(url: str, recommended_urls: Iterable[str]) -> str:
        html = f"<html><head><title>Not Found</title></head>\n<body><h1>Not Found</h1><p>{url} not found. Try one of these:</p><ul>\n"
        for ru in recommended_urls:
            html += f'<li><a href="{ru}">{ru}</a></li>\n'
        html += "</ul></body></html>\n"
        return html

    @staticmethod
    async def send_simple(writer: asyncio.StreamWriter, status: int, body: bytes):
        reason = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "OK"
        content_type = "text/plain"
        if body.startswith(b"<html>"):
            content_type = "text/html"
        head = f"HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        writer.write(head.encode("ascii") + body)
        await ReplayProxy.drain_with_timeout(writer)

    @staticmethod
    async def upgrade_to_tls(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ssl_context: ssl.SSLContext
                             ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        loop = asyncio.get_running_loop()

        # 1) make sure buffered bytes are flushed to the transport
        try:
            await ReplayProxy.drain_with_timeout(writer)
        except Exception:
            pass

        # 2) pause reading on the current transport to avoid races
        old_transport = writer.transport
        try:
            old_transport.pause_reading()
        except Exception:
            pass

        # 3) build a *new* reader/protocol for the TLS transport
        new_reader = asyncio.StreamReader(limit=2 ** 20)
        protocol = QuietReaderProtocol(new_reader)

        # 4) do the TLS upgrade (server-side)
        new_transport = await loop.start_tls(old_transport, protocol, ssl_context, server_side=True)

        # 5) wrap a writer around the new transport
        new_writer = asyncio.StreamWriter(new_transport, protocol, new_reader, loop)

        # 6) ALPN result (for h2/http1.1 switch)
        sslobj = new_transport.get_extra_info("ssl_object")
        alpn = (sslobj.selected_alpn_protocol() if sslobj else None) or "http/1.1"

        return new_reader, new_writer, alpn

    @staticmethod
    async def _h2_send_response(conn, reader, transport, stream_id: int,
                                status: int, resp_headers: dict[str, str], body: bytes) -> None:
        """
        HTTP/2 handling
        """
        # Build single response header block
        hdr_out: list[tuple[str, str]] = [(":status", str(status))]
        sent_ct = False
        for k, v in resp_headers.items():
            lk = k.lower()
            if lk in HOP:
                continue
            if lk == "content-type":
                sent_ct = True
            hdr_out.append((lk, str(v)))
        if not sent_ct:
            hdr_out.append(("content-type", "application/octet-stream"))

        if not body:
            conn.send_headers(stream_id, hdr_out, end_stream=True)
            transport.write(conn.data_to_send())
            return

        # Send headers, then DATA with proper chunking & flow control
        conn.send_headers(stream_id, hdr_out, end_stream=False)
        transport.write(conn.data_to_send())

        view = memoryview(body)
        offset = 0
        while offset < len(view):
            # Ensure we don't exceed frame size or flow-control window
            max_frame = conn.max_outbound_frame_size
            win = conn.local_flow_control_window(stream_id)
            if win == 0:
                # wait for WINDOW_UPDATE
                data = await asyncio.wait_for(reader.read(65535), 60.0)
                if not data:
                    break
                for ev in conn.receive_data(data):
                    # just process flow-control/window updates
                    if isinstance(ev, WindowUpdated):
                        pass
                    elif isinstance(ev, ConnectionTerminated):
                        return
                transport.write(conn.data_to_send())
                continue

            n = min(max_frame, win, len(view) - offset)
            conn.send_data(stream_id, view[offset:offset + n], end_stream=False)
            offset += n
            transport.write(conn.data_to_send())

        # Finish stream
        conn.end_stream(stream_id)
        transport.write(conn.data_to_send())

    @staticmethod
    async def handle_h2_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str,
                                   store: ContentStore):
        conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="iso-8859-1"))
        conn.initiate_connection()
        transport = writer.transport
        transport.write(conn.data_to_send())
        await ReplayProxy.drain_with_timeout(writer)

        try:
            # We handle a single request (typical nuclei flow). If you need multiplexing, extend this loop.
            request: Dict[str, str] = {}
            body_buf = b""

            while True:
                data = await reader.read(65535)
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, RequestReceived):
                        request = {k.lower(): v for k, v in event.headers}
                    elif isinstance(event, DataReceived):
                        # Collect POST/PUT data (not used for lookup by default)
                        body_buf += event.data
                        conn.acknowledge_received_data(len(event.data), event.stream_id)
                    elif isinstance(event, StreamEnded):
                        try:
                            # Build URL
                            method = (request.get(":method", "GET") or "GET").upper()
                            path = request.get(":path", "/")
                            authority = request.get(":authority", host)
                            url = f"https://{authority}{path}"

                            res = await store.lookup(url, method=method)
                            if not res:
                                print(f"HTTP/2 404 {url}")
                                not_found_body = ReplayProxy.not_found_html(url, await store.recommend_urls(url))
                                not_found_body_bytes = not_found_body.encode("iso-8859-1")
                                await ReplayProxy._h2_send_response(conn, reader, transport, event.stream_id, 404,
                                                                    {"content-type": "text/html"}, not_found_body_bytes)
                            else:
                                status, h, b = res
                                print(f"HTTP/2 {status} {url}")
                                await ReplayProxy._h2_send_response(conn, reader, transport, event.stream_id, status, h,
                                                                    b)
                        except Exception as e:
                            error_body = f"proxy error: {e}\n".encode()
                            print(f"HTTP/2 500 {error_body.decode()}")
                            await ReplayProxy._h2_send_response(conn, reader, transport, event.stream_id, 500,
                                                                {"content-type": "text/plain"}, error_body)
                            return
                        finally:
                            # Politely end the connection and flush; then **stop reading**
                            conn.close_connection()  # send GOAWAY
                            transport.write(conn.data_to_send())
                            # hard close to avoid TLS unwrap races
                            with contextlib.suppress(Exception):
                                transport.abort()
                            return
                    elif isinstance(event, ConnectionTerminated):
                        return
                transport.write(conn.data_to_send())
        except Exception as e:
            transport.write(conn.data_to_send())
            print(e, file=sys.stderr)

    @staticmethod
    async def handle_inner_http11(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str,
                                  store: ContentStore):
        """
        HTTP/1.1-inside-TLS fallback
        """
        line = await ReplayProxy.read_line(reader)
        if not line:
            writer.close()
            await writer.wait_closed()
            return
        parts = line.decode("iso-8859-1").rstrip("\r\n").split()
        if len(parts) < 3:
            writer.close()
            await writer.wait_closed()
            return
        method, path, _ = parts[0].upper(), parts[1], parts[2]
        headers = await ReplayProxy.read_headers(reader)
        # Read and discard body for POST/PUT
        if method in ("POST", "PUT", "PATCH"):
            _ = await ReplayProxy.read_body_http11(reader, headers)

        url = f"https://{host}{path}"
        await ReplayProxy.write_http11_response(url, method, writer, store)

    @staticmethod
    async def write_http11_response(url: str, method: str, writer: asyncio.StreamWriter, store: ContentStore):
        res = await store.lookup(url, method=method)
        if not res:
            print(f"HTTP/1.1 404 {url}")
            await ReplayProxy.send_simple(writer, 404,
                                          ReplayProxy.not_found_html(url, await store.recommend_urls(url)).encode(
                                              "iso-8859-1"))
            writer.close()
            await writer.wait_closed()
            return
        status, hdrs, body = res
        reason = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "OK"
        writer.write(f"HTTP/1.1 {status} {reason}\r\n".encode("ascii"))
        sent = set()
        for k, v in hdrs.items():
            lk = k.lower()
            if lk in HOP or lk in "content-encoding": continue
            if lk == "content-type": sent.add(lk)
            writer.write(f"{k}: {v}\r\n".encode("iso-8859-1"))
        if "content-type" not in sent:
            writer.write(b"Content-Type: application/octet-stream\r\n")
        writer.write(f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii"))
        if body: writer.write(body)
        await ReplayProxy.drain_with_timeout(writer)
        writer.close()
        await writer.wait_closed()
        print(f"HTTP/1.1 {status} {url}")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        url = "?"
        is_tls = False
        try:
            line = await ReplayProxy.read_line(reader)
            if not line:
                writer.close()
                await writer.wait_closed()
                return
            first = line.decode("iso-8859-1").rstrip("\r\n")
            parts = first.split()
            if len(parts) < 3:
                writer.close()
                await writer.wait_closed()
                return
            method, target, _ = parts[0].upper(), parts[1], parts[2]

            if method == "CONNECT":
                is_tls = True
                _ = await ReplayProxy.read_headers(reader)  # drain CONNECT headers
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await ReplayProxy.drain_with_timeout(writer)
                host, _sep, _port_s = target.partition(":") if ":" in target else target
                leaf_ctx = self.ca.mint_ctx_for_host(host)
                tls_reader, tls_writer, alpn = await ReplayProxy.upgrade_to_tls(reader, writer, leaf_ctx)
                if alpn == "h2":
                    await ReplayProxy.handle_h2_connection(tls_reader, tls_writer, host, self.store)
                else:
                    await ReplayProxy.handle_inner_http11(tls_reader, tls_writer, host, self.store)
                return

            # Plain HTTP proxying (HTTP/1.1 absolute-form or origin-form with Host)
            if target.startswith("http://") or target.startswith("https://"):
                url = target
                headers = await ReplayProxy.read_headers(reader)
            else:
                headers = await ReplayProxy.read_headers(reader)
                host = headers.get("Host", "")
                url = f"http://{host}{target}"

            # Drain body for POST/PUT/PATCH over plain HTTP
            if method in ("POST", "PUT", "PATCH"):
                _ = await ReplayProxy.read_body_http11(reader, headers)

            await ReplayProxy.write_http11_response(url, method, writer, self.store)

        except ConnectionResetError:
            pass

        except Exception as e:
            print(traceback.format_exc())
            try:
                print(f"HTTP/1.1 500 {url}")
                await ReplayProxy.send_simple(writer, 500, f"proxy error: {e}\n".encode())
            except Exception:
                pass

        finally:
            if not is_tls:
                await ReplayProxy._safe_close(writer)


async def run_proxy_server(db: str, host: str, port: int, cert_dir: PathLike) -> Server:
    db_host, db_port_s = db.split(":", 1)
    client = await chromadb.AsyncHttpClient(host=db_host, port=int(db_port_s))
    collection = await client.get_or_create_collection(name="content")
    store = ContentStore(collection)

    ca = CertAuthority(cert_dir=cert_dir)
    proxy = ReplayProxy(store, ca)
    server = await asyncio.start_server(proxy.handle, host, port, start_serving=True)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"replay proxy listening on {addrs}, CA cert is at {ca.ca_cert} (CONNECT→TLS ALPN: h2/http1.1)")
    return server
