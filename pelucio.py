#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PELUCIO v4.1 — JS / MAP Recon Tool (full patterns + refined anti-false-positive)
--------------------------------------------------------------------------------

• Restaura todos os padrões: private_key, AWS keys, slack webhook, JWT, bearer/query tokens,
  generic_api_key, long_base64, email, url, password-like.
• Adiciona filtro inteligente contra falsos-positivos visuais (spoticon, illustration, theme,
  color, mask, gradient, shadow, palette, etc) e filtros extra para JWTs falsos.
• Mantém CSV + JSON + discovered_urls + ffuf_paths outputs.
"""

from __future__ import annotations
import argparse, concurrent.futures, csv, json, math, os, random, re, sys, requests, time
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse
from tqdm import tqdm

VERSION = "4.1"
MAX_MAP_BYTES = 30 * 1024 * 1024
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 10

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
]

CDN_HOST_RE = re.compile(r"(fonts\.gstatic|googleapis|cloudflare|jsdelivr|unpkg|recaptcha|bootstrapcdn|cdn\.js)", re.I)
ASSET_EXT_RE = re.compile(r"\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|eot|mp4|webm|css|map)\b", re.I)

# --- Patterns ---
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|PRIVATE) KEY-----"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key[^A-Za-z0-9]{0,10}([A-Za-z0-9/+=]{40})"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack_webhook": re.compile(r"https?://hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"),
    "jwt": re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "bearer_token": re.compile(r"(?i)bearer\s+([A-Za-z0-9\-\._]{20,})"),
    "query_token": re.compile(r"(?:[?&](?:token|access_token|api_key|auth|secret)=)([^&\s]{6,})", re.I),
    "generic_api_key": re.compile(r"\b[A-Za-z0-9-_]{32,}\b"),
    "long_base64": re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    "email": re.compile(r"[A-Za-z0-9.\-_+]+@[A-Za-z0-9\-_]+\.[A-Za-z0-9.\-_]+"),
    "url": re.compile(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s'\"<>()]*)?", re.I),
    "password_like": re.compile(r'(?i)(?:password|passwd|pwd|senha)\s*[:=]\s*["\']([^"\']{4,})["\']'),
}

SCORES = {
    "private_key": 100, "aws_secret_key": 80, "aws_access_key": 60,
    "slack_webhook": 60, "password_like": 90, "jwt": 50,
    "bearer_token": 45, "query_token": 40, "generic_api_key": 15,
    "long_base64": 10, "email": 5, "url": 3,
}
HIGH_CONF_TYPES = {"private_key","aws_secret_key","aws_access_key","slack_webhook","password_like","jwt","bearer_token","query_token"}

def entropy(s):
    if not s: return 0.0
    c, l = Counter(s), len(s)
    return -sum((v/l)*math.log2(v/l) for v in c.values())

def has_mixed_charsets(s, min_classes=2):
    c = 0
    if re.search(r"[a-z]", s): c += 1
    if re.search(r"[A-Z]", s): c += 1
    if re.search(r"[0-9]", s): c += 1
    if re.search(r"[^A-Za-z0-9]", s): c += 1
    return c >= min_classes

def print_banner():
    CYAN, YELLOW, RESET = "\033[96m", "\033[93m", "\033[0m"
    print(f"{CYAN}PELUCIO — JS / MAP Recon Tool{RESET}")
    print(f"{YELLOW}version {VERSION}{RESET}\nAuthorized security testing only\n")

class PelucioScanner:
    def __init__(self, args):
        self.args = args
        self.outdir = Path(args.output)
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        if args.proxy:
            self.session.proxies.update({"http": args.proxy, "https": args.proxy})
        self.verify = not args.insecure
        self.timeout = args.timeout
        self.findings, self.discovered_urls, self.ffuf_paths, self.processed = [], set(), set(), set()

    def _headers(self):
        return {"User-Agent": self.args.user_agent or random.choice(UA_POOL)}

    def scan(self, sources):
        start = time.time()
        with tqdm(total=len(sources), desc="Analyzing", unit="src") as bar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as ex:
                futures = [ex.submit(self._process_source, s) for s in sources]
                for _ in concurrent.futures.as_completed(futures):
                    bar.update(1)
        print(f"\n[+] Scan finished in {time.time() - start:.1f}s")

    def _process_source(self, src):
        key = f"{src['type']}::{src['value']}"
        if key in self.processed: return
        self.processed.add(key)
        if src["type"] == "url": self._process_url(src["value"])
        else: self._process_file(src["value"])

    def _process_url(self, url):
        r = {"source": url, "type": "url", "score": 0, "matches": [], "high_conf": 0, "static_filtered": 0}
        try:
            resp = self.session.get(url, headers=self._headers(), timeout=self.timeout, verify=self.verify)
            score, matches, filt, high = self._detect(resp.text)
            r.update({"score": score, "matches": matches, "static_filtered": filt, "high_conf": high})
            if matches: self._extract_links(resp.text, url); self._extract_paths(resp.text, url)
        except Exception as e: r["error"] = str(e)
        if r["matches"]: self.findings.append(r)

    def _process_file(self, p):
        p = Path(p)
        r = {"source": str(p), "type": "file", "score": 0, "matches": [], "high_conf": 0, "static_filtered": 0}
        try:
            txt = p.read_text("utf-8", "ignore")
            score, matches, filt, high = self._detect(txt)
            r.update({"score": score, "matches": matches, "static_filtered": filt, "high_conf": high})
            if matches: self._extract_links(txt, str(p)); self._extract_paths(txt, None)
        except Exception as e: r["error"] = str(e)
        if r["matches"]: self.findings.append(r)

    # === Detection Core ===
    def _detect(self, text):
        total, matches, filt, high, seen = 0, [], 0, 0, {}
        for name, regex in PATTERNS.items():
            for m in regex.finditer(text):
                raw = m.group(0)
                start, end = m.start(), m.end()
                context = text[max(0, start-200):min(len(text), end+200)]

                if re.search(r"fonts\.gstatic|roboto", context, re.I): filt += 1; continue
                if CDN_HOST_RE.search(raw) or ASSET_EXT_RE.search(raw): filt += 1; continue

                if re.match(r"^[A-Za-z][A-Za-z0-9_]*$", raw):
                    if len(re.findall(r"[A-Z]", raw)) >= 3 or re.search(r"(Element|Node|Client|Width|Height|create|Scroll|Doc|Ref|Error|Count|Request|Session|Token|Validation|overlay|parentNode|removeChild)", raw, re.I):
                        filt += 1; continue

                # ==== REPLACED JWT BLOCK (stricter validation to avoid method names being tagged) ====
                if name == "jwt":
                    parts = raw.split(".")
                    if len(parts) != 3:
                        filt += 1
                        continue

                    h, p, s = parts

                    # Charset base64url and minimum lengths:
                    if any(len(x) < 16 for x in (h, p)) or not all(re.match(r"^[A-Za-z0-9_-]+$", x) for x in parts):
                        filt += 1
                        continue

                    # Header of a real JWT usually starts with 'eyJ' (base64url of '{"')
                    # Accept rarely 'e30' ({}), but avoid method-like dot strings
                    if not h.startswith(("eyJ", "e30")):
                        filt += 1
                        continue

                    # Payload must have minimal entropy and not be just letters (avoid method names)
                    if entropy(p) < 3.5 or re.match(r"^[A-Za-z]+$", p):
                        filt += 1
                        continue

                # ==== long_base64 handling ====
                if name == "long_base64":
                    if re.match(r"^[A-Z][a-zA-Z0-9_]+$", raw):
                        filt += 1
                        continue
                    if entropy(raw) < 3.8 or not re.match(r"^[A-Za-z0-9+/=]+$", raw):
                        filt += 1
                        continue
                    if "/s/roboto" in context or "fonts.gstatic.com" in context:
                        filt += 1
                        continue

                # ==== REPLACED generic_api_key BLOCK (with extra UI filters) ====
                if name == "generic_api_key":
                    if entropy(raw) < 4.0 or not has_mixed_charsets(raw, 3):
                        filt += 1
                        continue
                    if re.match(r"^[A-Z]?[a-z]+(?:[A-Z][a-z]+)+$", raw):
                        filt += 1
                        continue
                    if raw.count("_") >= 4:
                        filt += 1
                        continue
                    if re.search(r"(color|text|font|style|heading|body|regular|medium|bold|button|hero_)", raw, re.I):
                        filt += 1
                        continue
                    if re.search(r"(^--|spoticon|illustration|biometricId|icon|svg|theme|palette|mask|gradient|shadow|fill|stroke|border|radius)", raw, re.I):
                        filt += 1
                        continue

                    # NEW: require at least one digit (UI tokens rarely have digits)
                    if not re.search(r"\d", raw):
                        filt += 1
                        continue

                    # NEW: common UI keywords to ignore
                    if re.search(r"(onLight|onDark|feedback|celebration|overlay|element|parent|child)", raw, re.I):
                        filt += 1
                        continue

                if raw in seen: continue
                seen[raw] = True

                matches.append({"type": name, "match": raw})
                total += SCORES.get(name, 5)
                if name in HIGH_CONF_TYPES: high += 1

                if name == "url" and not any(u in raw for u in ("googleapis","gstatic","fonts.gstatic")):
                    self.discovered_urls.add(raw)
                    try:
                        path = urlparse(raw).path
                        if path and path.count("/")>0 and len(path)>1: self.ffuf_paths.add(path)
                    except: pass
        return total, matches, filt, high

    def _extract_links(self, text, base):
        for m in re.finditer(r'href=["\']([^"\']+)["\']', text, re.I):
            href = m.group(1).strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"): continue
            try:
                full = urljoin(base, href) if base else href
                if not ASSET_EXT_RE.search(full): self.discovered_urls.add(full)
            except: continue

    def _extract_paths(self, text, base=None):
        for m in re.finditer(r'(?:src|href)=["\']([^"\']+)["\']', text, re.I):
            val = m.group(1).strip()
            try:
                full = urljoin(base, val) if base else val
                if ASSET_EXT_RE.search(full): continue
                p = urlparse(full).path if full.startswith("http") else full
                if p: self.ffuf_paths.add(p)
            except: continue

    def write_outputs(self):
        if not self.findings:
            print("[-] No findings."); return
        (self.outdir / "findings.json").write_text(json.dumps(self.findings, indent=2))
        with open(self.outdir / "findings.csv","w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(["Source","Type","Match"])
            for r in self.findings:
                for m in r["matches"]:
                    w.writerow([r["source"],m["type"],m["match"]])
        if self.discovered_urls:
            (self.outdir / "discovered_urls.txt").write_text("\n".join(sorted(self.discovered_urls)))
        if self.ffuf_paths:
            (self.outdir / "ffuf_paths.txt").write_text("\n".join(sorted(self.ffuf_paths)))
        print(f"[+] Results written to {self.outdir}/")

def gather_sources(a):
    src=[]
    if a.input:
        with open(a.input, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line=line.strip()
                if not line or line.startswith("#"): continue
                if line.startswith("http"): src.append({"type":"url","value":line})
                elif os.path.exists(line): src.append({"type":"file","value":line})
                else: src.append({"type":"url","value":line})
    if a.dir:
        for root,_,files in os.walk(a.dir):
            for f in files:
                if f.lower().endswith((".js",".map")):
                    src.append({"type":"file","value":os.path.join(root,f)})
    seen=set(); out=[]
    for s in src:
        k=(s["type"],s["value"])
        if k not in seen: seen.add(k); out.append(s)
    return out

def main():
    p=argparse.ArgumentParser(description="PELUCIO v4.1")
    p.add_argument("--input","-i",help="File with list of URLs or paths (one per line)")
    p.add_argument("--dir","-d",help="Directory to recursively scan for .js and .map files")
    p.add_argument("--output","-o",default="pelucio_out_v41")
    p.add_argument("--proxy",help="Proxy (http://host:port)")
    p.add_argument("--insecure",action="store_true",help="Disable SSL verification")
    p.add_argument("--threads",type=int,default=DEFAULT_THREADS)
    p.add_argument("--timeout",type=int,default=DEFAULT_TIMEOUT)
    p.add_argument("--user-agent",help="Custom user-agent (overrides rotation)")
    a=p.parse_args()
    print_banner()
    src=gather_sources(a)
    if not src: print("[-] No sources provided. Use --input or --dir."); sys.exit(1)
    s=PelucioScanner(a); s.scan(src); s.write_outputs()

if __name__=="__main__": main()
