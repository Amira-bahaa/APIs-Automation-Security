import requests
import time
import logging

logger = logging.getLogger(__name__)


class APIClient:
    def __init__(self, base_url, default_headers=None, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if default_headers:
            self.session.headers.update(default_headers)

    def post(self, endpoint, data=None, headers=None, raw_body=None):
        url = f"{self.base_url}{endpoint}"
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)

        start = time.time()
        try:
            if raw_body is not None:
                resp = requests.post(
                    url, data=raw_body, headers=merged_headers, timeout=self.timeout
                )
            else:
                resp = requests.post(
                    url, json=data, headers=merged_headers, timeout=self.timeout
                )
            elapsed = round((time.time() - start) * 1000)
            logger.info(f"POST {endpoint} -> {resp.status_code} ({elapsed}ms)")
            return resp
        except requests.exceptions.RequestException as exc:
            logger.error(f"POST {endpoint} failed: {exc}")
            raise

    def get(self, endpoint, headers=None):
        url = f"{self.base_url}{endpoint}"
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)

        start = time.time()
        try:
            resp = requests.get(
                url, headers=merged_headers, timeout=self.timeout
            )
            elapsed = round((time.time() - start) * 1000)
            logger.info(f"GET {endpoint} -> {resp.status_code} ({elapsed}ms)")
            return resp
        except requests.exceptions.RequestException as exc:
            logger.error(f"GET {endpoint} failed: {exc}")
            raise
