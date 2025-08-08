import datetime
import json
import logging
from json import JSONDecodeError
from typing import List, Dict, Optional, Any

from haystack import component
from pydantic import BaseModel, Field

from shyhurricane.utils import urlparse_ext, parse_http_request, parse_http_response, \
    parse_to_iso8601

logger = logging.getLogger(__name__)


class IngestableRequestResponse(BaseModel):
    url: str = Field(description="URL")
    timestamp: str = Field(description="Timestamp")
    method: str = Field(description="HTTP method")
    request_headers: Dict[str, str] = Field(description="Request headers")
    request_body: Optional[str] = Field(description="Request body")
    response_code: int = Field(description="HTTP response code")
    response_headers: Dict[str, str] = Field(description="Response headers")
    response_body: Optional[str] = Field(description="HTTP response body")
    response_rtt: Optional[float] = Field(description="Response RTT in milliseconds")
    technologies: Optional[List[str]] = Field(description="Technologies")
    forms: Optional[List[Dict[str, Any]]] = Field(description="Forms")  # see katana response.forms "schema"

    def to_katana(self) -> str:
        data: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "request": {
                "endpoint": self.url,
                "method": self.method,
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status_code": self.response_code,
                "headers": self.response_headers,
                "body": self.response_body,
            }
        }
        if self.response_rtt is not None:
            data["response"]["rtt"] = self.response_rtt
        if self.technologies is not None:
            data["response"]["technologies"] = self.technologies
        if self.forms is not None:
            data["response"]["forms"] = self.forms
        return json.dumps(data)


@component
class HarDocument:
    """
    Convert HAR into IngestableRequestResponse.
    """

    def __init__(self):
        self._empty_response = {"request_responses": []}

    @staticmethod
    def parse_headers(har_headers: List[Dict[str, str]]) -> Dict[str, str]:
        headers = {}
        if not har_headers:
            return headers
        for req_header in har_headers:
            key = req_header.get("name", "").strip().title()
            if not key:
                continue
            value = req_header.get("value", "")
            if key in headers:
                headers[key] += ";" + value
            else:
                headers[key] = value
        return headers

    @component.output_types(request_responses=List[IngestableRequestResponse])
    def run(self, text: str | dict):
        if isinstance(text, dict):
            har = text
        else:
            try:
                har = json.loads(str(text))
            except JSONDecodeError:
                return self._empty_response
        if "log" not in har:
            logger.info("Missing log")
            return self._empty_response

        results = []
        for entry in har.get("log", {}).get("entries", []):
            if "request" not in entry:
                continue
            request = entry.get("request")

            if "response" not in entry:
                continue
            response = entry.get("response")

            url = request.get("url", None)
            if not url:
                continue
            try:
                urlparse_ext(url)
            except Exception:
                logger.warning(f"Malformed URL: {url}")
                continue

            timestamp = entry.get("startedDateTime",
                                  datetime.datetime.now().isoformat())  # 2025-08-06T12:03:55.711-05:00

            request_headers = self.parse_headers(request.get("headers", []))
            request_body = request.get("content", {}).get("text", None)
            http_method = request.get("method", "").upper()

            response_headers = self.parse_headers(response.get("headers", []))
            response_body = response.get("content", {}).get("text", None)
            status_code = response.get("status", 200)

            if "time" in entry:
                response_rtt = float(entry.get("time")) / 1000.0
            else:
                response_rtt = None

            results.append(IngestableRequestResponse(
                url=url,
                timestamp=timestamp,
                method=http_method,
                request_headers=request_headers,
                request_body=request_body,
                response_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                response_rtt=response_rtt,
                technologies=None,
                forms=None,
            ))

        return {"request_responses": results}


@component
class HttpRawDocument:
    """
    Convert raw HTTP request/response into IngestableRequestResponse.
    """

    def __init__(self):
        self._empty_response = {"request_responses": []}

    @component.output_types(request_responses=List[IngestableRequestResponse])
    def run(self, text: str):
        http_method, path, http_version, request_headers, request_body, response = parse_http_request(text)
        if not (http_method and path and response):
            return self._empty_response

        status_code, response_headers, response_body = parse_http_response(response)
        if not status_code:
            return self._empty_response

        if "://" in path:
            url = path
        else:
            host = request_headers.get("Host", request_headers.get("host", None))
            if host is None:
                return self._empty_response
            url = f"http://{host}{path}"

        timestamp = datetime.datetime.now().isoformat()
        if "Date" in response_headers:
            try:
                timestamp, _ = parse_to_iso8601(response_headers["Date"])
            except Exception:
                pass

        request_response = IngestableRequestResponse(
            url=url,
            timestamp=timestamp,
            method=http_method,
            request_headers=request_headers,
            request_body=request_body,
            response_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            response_rtt=None,
            technologies=None,
            forms=None,
        )
        return {"request_responses": [request_response]}


@component
class KatanaDocument:
    """
    Convert katana jsonl into IngestableRequestResponse.
    """

    def __init__(self):
        self._empty_response = {"request_responses": []}

    @component.output_types(request_responses=List[IngestableRequestResponse])
    def run(self, text: str | dict):
        if isinstance(text, dict):
            entry = text
        else:
            try:
                entry = json.loads(str(text))
            except JSONDecodeError:
                logger.warning("Invalid katana json")
                return self._empty_response
        if "request" not in entry:
            logger.warning("Missing request")
            return self._empty_response
        if "response" not in entry:
            logger.warning("Missing response")
            return self._empty_response
        if "status_code" not in entry["response"]:
            logger.info("No status_code, usually indicates out of scope")
            return self._empty_response
        if "endpoint" not in entry["request"]:
            logger.info("No endpoint")
            return self._empty_response

        url = entry["request"]["endpoint"]
        try:
            urlparse_ext(url)
        except Exception:
            logger.warning(f"Malformed URL: {url}")
            return self._empty_response

        timestamp = entry["timestamp"]  # 2025-06-28T22:52:07.882000
        request_body: Optional[str] = entry.get("request", {}).get("body", None)
        response_body: Optional[str] = entry.get("response", {}).get("body", None)
        status_code = entry["response"].get("status_code", 200)
        http_method = entry["request"].get("method", "").upper()
        request_headers = self._title_case_header(entry["request"].get("headers", {}))
        request_headers.pop("raw", None)
        response_headers = self._title_case_header(entry["response"].get("headers", {}))
        response_headers.pop("raw", None)
        response_rtt: Optional[float] = entry.get("response", {}).get("rtt", None)
        technologies = entry["response"].get("technologies", [])
        if not isinstance(technologies, list):
            technologies = [str(technologies)]
        forms = entry.get("response", {}).get("forms", None)

        request_response = IngestableRequestResponse(
            url=url,
            timestamp=timestamp,
            method=http_method,
            request_headers=request_headers,
            request_body=request_body,
            response_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            response_rtt=response_rtt,
            technologies=technologies,
            forms=forms,
        )
        return {"request_responses": [request_response]}

    def _title_case_header(self, katana_headers: Dict[str, str]) -> Dict[str, str]:
        result = dict()
        for k, v in katana_headers.items():
            result[k.replace('_', '-').title()] = v
            pass
        return result
