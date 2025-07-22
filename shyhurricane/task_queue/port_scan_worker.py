import copy
import logging
import subprocess
import tempfile
import time
from datetime import datetime
from multiprocessing import Queue
from typing import Optional
from xml.etree import ElementTree as ET

from haystack import Document
from haystack.components.embedders import SentenceTransformersDocumentEmbedder
from haystack.document_stores.types import DuplicatePolicy
from haystack_integrations.document_stores.chroma import ChromaDocumentStore

from doc_type_model_map import doc_type_to_model
from pipeline import create_chrome_document_store
from ports import parse_ports_spec, bitfield_to_ports, is_subset
from shyhurricane.task_queue.types import PortScanQueueItem
from utils import PortScanResult, PortScanResults

NMAP_DOCUMENT_VERSION = 2

logger = logging.getLogger(__name__)


class PortScanContext:
    def __init__(self, db: str):
        self.nmap_store = create_chrome_document_store(db=db, collection_name="nmap")
        self.nmap_embedder = SentenceTransformersDocumentEmbedder(
            model=doc_type_to_model.get("nmap"),
            progress_bar=False)
        self.portscan_store = create_chrome_document_store(db=db, collection_name="portscan")
        self.portscan_embedder = SentenceTransformersDocumentEmbedder(
            model=doc_type_to_model.get("portscan"),
            progress_bar=False)

    def warm_up(self):
        self.nmap_embedder.warm_up()
        self.portscan_embedder.warm_up()


def port_scan_worker(ctx: PortScanContext, item: PortScanQueueItem, result_queue: Queue):
    nmap_store = ctx.nmap_store
    nmap_embedder = ctx.nmap_embedder
    portscan_store = ctx.portscan_store
    portscan_embedder = ctx.portscan_embedder

    wanted_ports = parse_ports_spec(item.ports)
    if wanted_ports.count() > 1000:
        # we want the top 100 ports, but we should not scan ports other than what the user asked for
        top_ports_100 = parse_ports_spec(
            "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157".split(
                ','))
        top_ports_100 &= wanted_ports
        if top_ports_100.count() > 20:
            item_100 = copy.copy(item)
            item_100.ports = list(map(str, bitfield_to_ports(top_ports_100)))
            logger.info("Performing an initial port scan with %d ports", top_ports_100.count())
            _do_port_scan(result_queue, item_100, nmap_store, nmap_embedder, portscan_store, portscan_embedder,
                          True)

    _do_port_scan(result_queue, item, nmap_store, nmap_embedder, portscan_store, portscan_embedder, False)


def _do_port_scan(
        result_queue: Queue,
        item: PortScanQueueItem,
        nmap_store: ChromaDocumentStore,
        nmap_embedder: SentenceTransformersDocumentEmbedder,
        portscan_store: ChromaDocumentStore,
        portscan_embedder: SentenceTransformersDocumentEmbedder,
        has_more: bool = False
) -> None:
    if stored_results := get_stored_port_scan_results(item, nmap_store, portscan_store):
        stored_results.has_more = has_more
        result_queue.put_nowait(stored_results)
        return None

    if item.ports:
        ports_option = f"-p{','.join(item.ports)}"
    else:
        ports_option = "-p-"
    nmap_command = ["nmap", "-sT", "--open", "-sC", "-sV", "-oX", "-", ports_option]
    nmap_command.extend(item.targets)

    docker_command = [
        "docker", "run", "--rm",
        "--user=0",
        "--cap-add", "NET_BIND_SERVICE",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "NET_RAW",
    ]
    for host, ip in (item.additional_hosts or {}).items():
        docker_command.extend(["--add-host", f"{host}:{ip}"])
    docker_command.extend(["shyhurricane_unix_command:latest"])
    docker_command.extend(nmap_command)

    runtime_ts = time.time()
    timestamp = datetime.fromtimestamp(runtime_ts).isoformat()

    logger.info(f"port scan with command {' '.join(docker_command)}")
    with tempfile.TemporaryFile(mode="w+") as output_file:
        proc = subprocess.Popen(docker_command, universal_newlines=True, stdout=output_file.fileno(),
                                stderr=subprocess.DEVNULL)
        return_code = proc.wait()
        if return_code != 0:
            logger.error("Port scan for %s returned exit code %d: %s", item.targets, return_code,
                         ' '.join(docker_command))
            return None

        logger.info("Port scan for %s completed", item.targets)
        output_file.seek(0, 0)
        try:
            tree = ET.parse(output_file)
        except ET.ParseError:
            logger.error("nmap findings corrupt")
            return None

    # remove elements we don't care about to keep the content size reasonable
    for parent in tree.findall(".//*"):
        for child in list(parent):
            if child.tag == "extrareasons":
                parent.remove(child)

    nmap_content = ET.tostring(tree.getroot(), encoding="unicode")
    nmap_doc = Document(
        content=nmap_content,
        meta={
            "version": NMAP_DOCUMENT_VERSION,
            "targets": ','.join(item.targets),
            "ports": ','.join(item.ports),
            "timestamp": timestamp,
            "runtime_ts": runtime_ts,
            "content_type": "text/xml",
            "status_code": 200,
            # "technologies": technologies_str,
        }
    )
    nmap_store.write_documents(nmap_embedder.run(documents=[nmap_doc])["documents"], policy=DuplicatePolicy.OVERWRITE)

    results = []
    for host_el in tree.findall('.//host'):
        addrs = []
        hostnames = []
        for el in host_el:
            if el.tag == 'address':
                addrs.append(el.attrib['addr'])
            elif el.tag == 'hostnames':
                for hostname_el in el:
                    if hostname_el.tag == 'hostname':
                        hostnames.append(hostname_el.attrib['name'])

        for addr in addrs:
            host_nmap_doc = Document(
                content=ET.tostring(host_el, encoding="unicode"),
                meta={
                    "version": NMAP_DOCUMENT_VERSION,
                    "targets": addr,
                    "ports": ','.join(item.ports),
                    "timestamp": timestamp,
                    "runtime_ts": runtime_ts,
                    "content_type": "text/xml",
                    "status_code": 200,
                    # "technologies": technologies_str,
                }
            )
            nmap_store.write_documents(nmap_embedder.run(documents=[host_nmap_doc])["documents"],
                                       policy=DuplicatePolicy.OVERWRITE)

        for el in host_el:
            if el.tag == 'ports':
                for port_el in el:
                    if port_el.tag != 'port':
                        continue
                    service_name = None
                    service_notes = []
                    state = 'unknown'
                    port = int(port_el.attrib.get('portid', 0))
                    for port_detail_el in port_el:
                        if port_detail_el.tag == 'service':
                            service_name = port_detail_el.attrib.get('name', None)
                        elif port_detail_el.tag == 'script':
                            service_notes.append(port_detail_el.attrib.get('output', None))
                        elif port_detail_el.tag == 'state':
                            state = port_detail_el.attrib.get('state', 'unknown')

                    for addr in addrs:
                        portscan_result = PortScanResult(
                            hostname=hostnames[0] if hostnames else '',
                            ip_address=addr,
                            port=port,
                            state=state,
                            service_name=service_name,
                            service_notes='\n'.join(filter(lambda e: e is not None, service_notes))
                        )
                        results.append(portscan_result)
                        portscan_content = portscan_result.model_dump_json()
                        portscan_doc = Document(
                            content=portscan_content,
                            meta={
                                "version": NMAP_DOCUMENT_VERSION,
                                "netloc": f"{addr}:{port}",
                                "host": addr,
                                "port": port,
                                "timestamp": timestamp,
                                "content_type": "text/json",
                                "status_code": 200,
                                # "technologies": technologies_str,
                            }
                        )
                        portscan_store.write_documents(portscan_embedder.run(documents=[portscan_doc])["documents"],
                                                       policy=DuplicatePolicy.OVERWRITE)

    result_queue.put(PortScanResults(
        runtime_ts=runtime_ts,
        results=results,
        targets=item.targets,
        ports=item.ports,
        nmap_xml=nmap_content,
        has_more=has_more,
    ))

    return None


def get_stored_port_scan_results(
        item: PortScanQueueItem,
        nmap_store: ChromaDocumentStore,
        portscan_store: ChromaDocumentStore
) -> Optional[PortScanResults]:
    filters = {
        "operator": "AND",
        "conditions": [
            {"field": "meta.version", "operator": "==", "value": NMAP_DOCUMENT_VERSION},
            {"field": "meta.targets", "operator": "==", "value": ','.join(item.targets)},
        ]
    }
    nmap_existing = nmap_store.filter_documents(filters=filters)
    runtime_expired_ts = time.time() - 60 * 60 * 24 * 7
    existing_results = []
    wanted_ports = parse_ports_spec(item.ports)

    # 0 is a special case of "don't care"
    if wanted_ports.count() == 1 and wanted_ports[0]:
        wanted_ports.setall(False)

    for doc in nmap_existing:
        if doc.meta.get("runtime_ts", 0) < runtime_expired_ts:
            continue
        covered_ports = parse_ports_spec([doc.meta.get("ports", "")])
        if not is_subset(wanted_ports, covered_ports):
            continue
        if "ERROR: Script execution failed" in doc.content:
            continue
        return PortScanResults(
            runtime_ts=doc.meta.get("runtime_ts", 0),
            results=existing_results,  # TODO:
            targets=item.targets,
            ports=item.ports,
            nmap_xml=doc.content,
            has_more=False,
        )
    return None
