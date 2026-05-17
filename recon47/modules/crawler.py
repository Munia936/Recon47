"""
Recon47 — Web Crawler (Recursive, Multi-threaded)
Author: Munia936
Discovers: URLs, endpoints, JS files, parameters, forms
"""
import re
import queue
import threading
import urllib.request
import urllib.error
import ssl
from urllib.parse import urljoin, urlparse, urlencode
from ..utils.console import found, info, warn, ok, err, progress
from ..utils.helpers import Deduplicator, RateLimiter, clean_url

JS_PATTERN   = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
LINK_PATTERN = re.compile(r'href=["\']([^"\'#?]+)["\']', re.I)
ACTION_PATTERN = re.compile(r'action=["\']([^"\']+)["\']', re.I)
PARAM_PATTERN  = re.compile(r'name=["\']([^"\']+)["\']', re.I)
SRC_PATTERN    = re.compile(r'(https?://[^\s"\'<>]+)', re.I)

INTERESTING = re.compile(
    r'(admin|login|signup|register|upload|config|backup|debug|test|api|v\d|'
    r'secret|token|key|password|user|account|panel|dashboard|shell|cmd|exec|'
    r'eval|\.env|\.git|\.svn|wp-admin|phpmyadmin|manager|console)', re.I
)

class Crawler:
    def __init__(self, base_url, domain, max_depth=2, max_pages=80,
                 threads=10, rate=8):
        self.base_url  = base_url
        self.domain    = domain
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.rate      = RateLimiter(rate)
        self.dedup     = Deduplicator()
        self.q         = queue.Queue()
        self.lock      = threading.Lock()
        self.results   = {
            "urls": [], "endpoints": [], "js_files": [],
            "parameters": set(), "forms": [], "interesting": []
        }
        self._count    = 0
        self._ctx      = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def crawl(self):
        info(f"Crawling {self.base_url} (depth={self.max_depth}, max={self.max_pages})")
        self.q.put((self.base_url, 0))

        workers = []
        for _ in range(self.rate._rate):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        self.q.join()
        for _ in workers:
            self.q.put(None)
        for t in workers:
            t.join(timeout=2)

        # Finalize
        self.results["parameters"] = list(self.results["parameters"])
        ok(f"Crawl complete: {len(self.results['urls'])} URLs, "
           f"{len(self.results['js_files'])} JS files, "
           f"{len(self.results['parameters'])} params")
        return self.results

    def _worker(self):
        while True:
            item = self.q.get()
            if item is None:
                self.q.task_done()
                return
            url, depth = item
            try:
                self._fetch(url, depth)
            except Exception:
                pass
            finally:
                self.q.task_done()

    def _fetch(self, url, depth):
        with self.lock:
            if self._count >= self.max_pages:
                return
            self._count += 1
            count = self._count

        if not self.dedup.is_new(url):
            return

        self.rate.acquire()
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Recon47/2.0)"
            })
            with urllib.request.urlopen(req, timeout=6, context=self._ctx) as resp:
                ctype = resp.headers.get("Content-Type", "")
                body  = resp.read(1024 * 256).decode(errors="ignore")  # 256KB max
        except Exception:
            return

        progress("Crawling", count, self.max_pages)

        clean = clean_url(url)
        with self.lock:
            self.results["urls"].append(clean)

        # Flag interesting
        if INTERESTING.search(url):
            with self.lock:
                if clean not in self.results["interesting"]:
                    found(f"Interesting: {clean}")
                    self.results["interesting"].append(clean)

        if "html" not in ctype:
            return

        # Extract JS files
        for m in JS_PATTERN.findall(body):
            js_url = urljoin(url, m)
            with self.lock:
                if js_url not in self.results["js_files"]:
                    self.results["js_files"].append(js_url)

        # Extract forms + params
        for action in ACTION_PATTERN.findall(body):
            form_url = urljoin(url, action)
            params   = PARAM_PATTERN.findall(body)
            entry    = {"url": form_url, "params": params}
            with self.lock:
                self.results["forms"].append(entry)
                for p in params:
                    self.results["parameters"].add(p)

        if depth >= self.max_depth:
            return

        # Extract links and queue
        for href in LINK_PATTERN.findall(body):
            abs_url = urljoin(url, href)
            p = urlparse(abs_url)
            if p.netloc and self.domain not in p.netloc:
                continue
            abs_url = clean_url(abs_url)
            if self.dedup.is_new(abs_url + "__queued"):
                self.q.put((abs_url, depth + 1))

            # Collect endpoints
            if p.path and p.path not in ("/", ""):
                ep = p.path
                with self.lock:
                    if ep not in self.results["endpoints"]:
                        self.results["endpoints"].append(ep)


def crawl(target_info, max_depth=2, max_pages=80):
    base = target_info["base"]
    domain = target_info["domain"]
    c = Crawler(base, domain, max_depth=max_depth, max_pages=max_pages)
    return c.crawl()
