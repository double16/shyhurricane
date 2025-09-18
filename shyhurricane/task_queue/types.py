import multiprocessing
from multiprocessing import Process
from typing import List, Dict, Optional


class TaskPool:
    def __init__(self, processes: List[Process]):
        self.processes = processes

    def close(self):
        for process in self.processes:
            try:
                process.terminate()
                process.join()
                process.close()
            except Exception:
                pass


class TaskWorkerIPC:
    def __init__(self,
                 task_queue: multiprocessing.Queue,
                 spider_result_queue: multiprocessing.Queue,
                 port_scan_result_queue: multiprocessing.Queue,
                 dir_busting_result_queue: multiprocessing.Queue,
                 task_pool: TaskPool,
                 ):
        self.task_queue = task_queue
        self.spider_result_queue = spider_result_queue
        self.port_scan_result_queue = port_scan_result_queue
        self.dir_busting_result_queue = dir_busting_result_queue
        self.task_pool = task_pool


class PortScanQueueItem:
    def __init__(self, targets: List[str], ports: List[str], additional_hosts: Dict[str, str], retry: bool) -> None:
        self.targets = targets
        self.ports = ports or []
        self.additional_hosts = additional_hosts
        self.retry = retry

    def __eq__(self, other):
        return isinstance(other, PortScanQueueItem) and self.targets == other.targets and self.ports == other.ports

    def __copy__(self):
        return PortScanQueueItem(self.targets, self.ports, self.additional_hosts, self.retry)


class SpiderQueueItem:
    def __init__(self,
                 uri: str,
                 depth: int = 3,
                 user_agent: Optional[str] = None,
                 request_headers: Optional[Dict[str, str]] = None,
                 additional_hosts: Dict[str, str] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 rate_limit_requests_per_second: Optional[int] = None,
                 ):
        self.uri = uri
        self.depth = depth
        self.user_agent = user_agent
        self.request_headers = request_headers
        self.additional_hosts = additional_hosts
        self.cookies = cookies
        self.rate_limit_requests_per_second = rate_limit_requests_per_second


class DirBustingQueueItem:
    def __init__(self,
                 uri: str,
                 depth: int = 3,
                 method: str = "GET",
                 wordlist: Optional[str] = None,
                 extensions: Optional[List[str]] = None,
                 ignored_response_codes: Optional[List[int]] = None,
                 user_agent: Optional[str] = None,
                 request_headers: Optional[Dict[str, str]] = None,
                 additional_hosts: Dict[str, str] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 params: Optional[Dict[str, str]] = None,
                 rate_limit_requests_per_second: Optional[int] = None,
                 seclists_volume: Optional[str] = None,
                 mcp_session_volume: Optional[str] = None,
                 work_path: Optional[str] = None,
                 ):
        self.uri = uri
        self.depth = depth
        self.method = method
        self.wordlist = wordlist
        self.extensions = extensions
        self.user_agent = user_agent
        self.request_headers = request_headers
        self.ignored_response_codes = ignored_response_codes
        self.additional_hosts = additional_hosts
        self.cookies = cookies
        self.params = params
        self.rate_limit_requests_per_second = rate_limit_requests_per_second
        self.seclists_volume = seclists_volume
        self.mcp_session_volume = mcp_session_volume
        self.work_path = work_path


class SaveFindingQueueItem:
    def __init__(self,
                 target: str,
                 markdown: str,
                 title: Optional[str]):
        self.target = target
        self.markdown = markdown
        self.title = title
