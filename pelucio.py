#!/usr/bin/env python3
# pelucio.py v1.4.1
# Analisa URLs de .js e .map (inline e remotos), detecta possíveis vazamentos,
# segue referências para outros .js (cascata limitada), e gera:
#   - pelucio_findings.json
#   - pelucio_urls.txt
#   - pelucio_wordlist.txt
#   - pelucio_findings.csv (ordenado por criticidade)
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

VERSION = "1.4.1"
DEFAULT_TIMEOUT = 15
UA = f"pelucio/{VERSION}"

# =========================
# Banner
# =========================
def print_banner() -> None:
    print("\n" + "=" * 72)
    print(f"  🧠  Pelucio v{VERSION}")
    print("  Sourcemap & JavaScript Analyzer — detecção de leaks, URLs e paths")
    print("  Bichinho tranquera roubador de itens preciosos")
    print("=" * 72 + "\n")

# =========================
# Config
# =========================
FALSE_POS = [
    "fonts.gstatic.com",
    "fonts.googleapis.com",
    "roboto",
    "com/s/roboto",
    "/wp-includes/",
    "google-analytics.com/analytics.js",
]

# --- PATTERNS (sem generic_api_key) ---
PATTERNS = {

    # --- Detectores específicos de tokens internos (novos) ---
    "system_token_identifier": re.compile(
        r"\bSYSTEM_TOKEN(?:_BFF)?(?:_[A-Z0-9_]{3,})?\b"
    ),

    "datadog_synthetics_identifier": re.compile(
        r"datadog-[a-z0-9\-]+(?:token|public-id|result-id|execution-id)",
        re.I,
    ),

    "shopify_checkout_api_token": re.compile(
        r"shopify-[a-z0-9\-]*token",
        re.I,
    ),

    "google_site_verification": re.compile(
        r"google-site-verification",
        re.I,
    ),

    "private_key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|PRIVATE) KEY-----"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key.*[:=]\s*[A-Za-z0-9/+=]{40,}"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
    "bearer_token": re.compile(r"(?i)bearer\s+([A-Za-z0-9\-\._~\+/=]{20,})"),
    "query_token": re.compile(r"(?i)(?:token|api_key|access_token|auth|secret)=([^ \s&\"';]+)"),
    "long_base64": re.compile(r"(?P<quote>['\"])?(?P<b64>(?:[A-Za-z0-9+/]{40,}={0,2}))(?:(?P=quote))"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "password_like": re.compile(r"(?i)(?:\bsenha\b|\bpassw?d\b|\bpasswd\b|\bpwd\b)\s*[:=]\s*[\"']([^\"']{4,})[\"']"),
    "script_src": re.compile(r"<script[^>]+src=[\"'](?P<src>[^\"']+\.js[^\"']*)[\"']", re.I),
}

HIGH_TYPES = {
    "private_key", "aws_secret_key", "aws_access_key", "slack_webhook",
    "jwt", "bearer_token", "query_token", "password_like",
    "system_token_identifier", "shopify_checkout_api_token",
}
LOW_TYPES = {
    "long_base64", "email", "url",
    "datadog_synthetics_identifier", "google_site_verification",
}

SOURCE_MAP_REGEX = re.compile(r"//#\s*sourceMappingURL\s*=\s*(.+)|//@\s*sourceMappingURL\s*=\s*(.+)")
INLINE_SOURCEMAP_REGEX = re.compile(r"(?:sourceMappingURL\s*=\s*data:application/json;base64,)([A-Za-z0-9+/=]+)")

# =========================
# Helpers
# =========================
def is_false_positive(s: str) -> bool:
    sl = s.lower()
    return any(fp in sl for fp in FALSE_POS)

def classify(kind: str, value: str, decoded_preview: Optional[str] = None) -> str:
    if kind in HIGH_TYPES:
        return "high"
    if kind in LOW_TYPES:
        if decoded_preview and any(k in decoded_preview.lower() for k in ("api_key","secret","token","password","private","aws")):
            return "high"
        return "low"
    return "low"

def try_gunzip(b: bytes) -> bytes:
    try:
        import gzip
        return gzip.decompress(b)
    except Exception:
        return b

def safe_fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> Tuple[Optional[bytes], Optional[int], Optional[str]]:
    try:
        r = requests.get(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"}, timeout=timeout, allow_redirects=True)
        return r.content, r.status_code, None
    except requests.RequestException as e:
        return None, None, str(e)

def base64_try_decode(s: str) -> Optional[bytes]:
    s = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s): return None
    s += "=" * ((4 - len(s) % 4) % 4)
    try: return base64.b64decode(s, validate=False)
    except Exception: return None

def jwt_decode_part(part: str) -> Optional[str]:
    p = part.replace("-", "+").replace("_", "/")
    p += "=" * ((4 - len(p) % 4) % 4)
    try: return base64.b64decode(p).decode("utf-8", errors="ignore")
    except Exception: return None

def candidate_sourcemap_urls(js_url: str) -> List[str]:
    parsed = urlparse(js_url)
    base_path = parsed.path or ""
    candidates: List[str] = []
    if base_path.endswith(".js"):
        basename = os.path.basename(base_path)
        name_noext = os.path.splitext(basename)[0]
        candidates.append(urljoin(js_url, basename + ".map"))
        candidates.append(urljoin(js_url, base_path[:-3] + ".map"))
        candidates.append(urljoin(js_url, os.path.dirname(base_path) + "/" + name_noext + ".map"))
    else:
        candidates.append(urljoin(js_url, base_path + ".map"))
    seen, out = set(), []
    for u in candidates:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out

def extract_paths_from_url(url: str) -> Set[str]:
    try:
        p = urlparse(url).path
        if not p or p == "/": return set()
        parts = p.strip("/").split("/")
        acc, cur = set(), ""
        for seg in parts:
            cur += "/" + seg
            acc.add(cur)
        acc.add(p)
        return acc
    except Exception:
        return set()

def resolve_ref(base_url: str, ref: str) -> Optional[str]:
    ref = ref.strip()
    if ref.startswith("data:"): return None
    if re.match(r"^https?://", ref, re.I): return ref
    try:
        joined = urljoin(base_url, ref)
        if re.match(r"^https?://", joined, re.I): return joined
    except Exception:
        pass
    return None

# =========================
# Análise de texto
# =========================
def analyze_text(blob_text: str) -> Tuple[List[Dict[str,Any]], List[str], List[str]]:
    findings: List[Dict[str,Any]] = []
    urls_found: List[str] = []
    js_refs: List[str] = []

    for key, regex in PATTERNS.items():
        for m in regex.finditer(blob_text):
            try:
                if key in ("bearer_token","query_token","password_like"):
                    val = m.group(1) if m.groups() else m.group(0)
                elif key == "long_base64":
                    val = m.group("b64") if "b64" in regex.groupindex else m.group(0)
                elif key == "script_src":
                    val = m.group("src")
                else:
                    val = m.group(0)
            except Exception:
                val = m.group(0)
            val = (val or "").strip()
            if not val:
                continue
            if key == "url" and is_false_positive(val):
                continue

            decoded_preview = None
            jwt_parts = None

            if key == "long_base64":
                dec = base64_try_decode(val)
                if dec:
                    try: decoded_preview = dec.decode("utf-8", errors="ignore")
                    except Exception: pass

            if key == "jwt":
                parts = val.split(".")
                if len(parts) >= 2:
                    header = jwt_decode_part(parts[0])
                    payload = jwt_decode_part(parts[1])
                    jwt_parts = {"header": header, "payload": payload}
                    decoded_preview = payload or header or decoded_preview

            if key == "url":
                urls_found.append(val)
            if key == "script_src":
                js_refs.append(val)

            findings.append({
                "type": key,
                "value": val,
                "decoded_preview": decoded_preview,
                "jwt_parts": jwt_parts,
                "sensitivity": classify(key, val, decoded_preview),
            })

    for m in re.finditer(r"https?://[^\s'\"<>]+\.js[^\s'\"<>]*", blob_text):
        u = m.group(0)
        if u not in urls_found:
            urls_found.append(u)

    return findings, sorted(set(urls_found)), sorted(set(js_refs))

def parse_sourcemap_bytes(blob_bytes: bytes) -> Tuple[Optional[Dict[str,Any]], str]:
    try: txt = try_gunzip(blob_bytes).decode("utf-8", errors="ignore")
    except Exception: txt = str(blob_bytes[:2000])
    try:
        obj = json.loads(txt)
        if isinstance(obj, dict):
            sc = obj.get("sourcesContent")
            if isinstance(sc, list) and sc:
                hay = "\n\n".join([s for s in sc if isinstance(s, str)])
                return obj, hay
            return obj, txt
        return None, txt
    except Exception:
        return None, txt

# =========================
# Processamento de um JS
# =========================
def process_js_entry(js_url: str, timeout: float) -> Dict[str,Any]:
    result = {
        "js_url": js_url,
        "js_status": None,
        "sourcemap_found": None,
        "sourcemap_status": None,
        "has_sourcesContent": False,
        "findings": [],
        "discovered_urls": [],
        "referenced_js": [],
    }
    js_bytes, js_status, _ = safe_fetch(js_url, timeout=timeout)
    result["js_status"] = js_status
    if not js_bytes:
        return result

    try:
        js_text = try_gunzip(js_bytes).decode("utf-8", errors="replace")
    except Exception:
        js_text = js_bytes.decode("latin1", errors="replace")

    inline = INLINE_SOURCEMAP_REGEX.search(js_text)
    if inline:
        try:
            dec = base64.b64decode(inline.group(1))
            obj, hay = parse_sourcemap_bytes(dec)
            result["sourcemap_found"] = {"type": "inline"}
            if obj and obj.get("sourcesContent"): result["has_sourcesContent"] = True
            f, u, refs = analyze_text(hay)
            result["findings"].extend(f)
            result["discovered_urls"].extend(u)
            result["referenced_js"].extend(refs)
        except Exception:
            pass

    sm_comments = SOURCE_MAP_REGEX.findall(js_text)
    sm_targets = [m[0] or m[1] for m in sm_comments if (m[0] or m[1])]
    candidates: List[str] = []
    for tgt in sm_targets:
        tgt = tgt.strip()
        if not tgt.startswith("data:"):
            candidates.append(urljoin(js_url, tgt))
    candidates.extend(candidate_sourcemap_urls(js_url))

    seen, uniq = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    for c in uniq:
        mb, st, _ = safe_fetch(c, timeout=timeout)
        if not mb:
            continue
        obj, hay = parse_sourcemap_bytes(mb)
        result["sourcemap_found"] = {"type": "remote", "url": c}
        result["sourcemap_status"] = st
        if obj and obj.get("sourcesContent"): result["has_sourcesContent"] = True
        f, u, refs = analyze_text(hay)
        result["findings"].extend(f)
        result["discovered_urls"].extend(u)
        result["referenced_js"].extend(refs)
        break

    f_js, u_js, refs_js = analyze_text(js_text)
    result["findings"].extend(f_js)
    result["discovered_urls"].extend(u_js)
    result["referenced_js"].extend(refs_js)

    resolved_refs: List[str] = []
    for ref in sorted(set(result["referenced_js"])):
        r = resolve_ref(js_url, ref)
        if r: resolved_refs.append(r)
    for u in result["discovered_urls"]:
        if u.lower().endswith(".js"):
            resolved_refs.append(u)
    result["referenced_js"] = sorted(set(resolved_refs))

    uniqf: Dict[Tuple[str,str], Dict[str,Any]] = {}
    for f in result["findings"]:
        k = (f.get("type"), f.get("value"))
        if k not in uniqf:
            uniqf[k] = f
    result["findings"] = list(uniqf.values())
    result["discovered_urls"] = sorted(set(result["discovered_urls"]))
    return result

# =========================
# Runner
# =========================
def run_all(js_list: List[str], threads: int, timeout: float, outdir: str, max_depth: int = 3) -> Dict[str,Any]:
    outp = Path(outdir); outp.mkdir(parents=True, exist_ok=True)
    findings_path = outp / "pelucio_findings.json"
    urls_path = outp / "pelucio_urls.txt"
    wordlist_path = outp / "pelucio_wordlist.txt"
    csv_path = outp / "pelucio_findings.csv"

    results: List[Dict[str,Any]] = []
    discovered_urls_global: Set[str] = set()
    wordlist_paths: Set[str] = set()

    seen_urls: Set[str] = set()
    lock = threading.Lock()
    scheduled = 0
    processed = 0

    def submit_url(ex, u: str, depth: int, fmap: Dict):
        nonlocal scheduled
        with lock:
            if u in seen_urls: return
            seen_urls.add(u)
            scheduled += 1
        fut = ex.submit(process_js_entry, u, timeout)
        fmap[fut] = (u, depth)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures_map: Dict[concurrent.futures.Future, Tuple[str,int]] = {}
        for u in js_list:
            su = u.strip()
            if su:
                submit_url(ex, su, 0, futures_map)

        while futures_map:
            done, _ = concurrent.futures.wait(list(futures_map.keys()), return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in done:
                url, depth = futures_map.pop(fut)
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"js_url": url, "findings": [], "discovered_urls": [], "referenced_js": [], "error": str(e)}
                results.append(res)

                for u in res.get("discovered_urls", []):
                    discovered_urls_global.add(u)
                    for p in extract_paths_from_url(u):
                        wordlist_paths.add(p)
                for f in res.get("findings", []):
                    v = f.get("value")
                    if isinstance(v, str) and v.startswith("http"):
                        for p in extract_paths_from_url(v):
                            wordlist_paths.add(p)

                if depth < max_depth:
                    for ref in res.get("referenced_js", []):
                        if re.match(r"^https?://", ref, re.I):
                            submit_url(ex, ref, depth + 1, futures_map)

                with lock:
                    processed += 1
                    pct = (processed / scheduled) * 100 if scheduled else 100.0
                sys.stdout.write(f"\r[+] Andamento: {processed}/{scheduled} ({pct:.1f}%)   ")
                sys.stdout.flush()

    print("\n[+] Análise concluída.\n")

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_count": len(js_list),
        "version": VERSION,
        "cascading_max_depth": max_depth,
        "total_processed": len(results),
    }
    with findings_path.open("w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "results": results}, fh, ensure_ascii=False, indent=2)

    with urls_path.open("w", encoding="utf-8") as fh:
        for u in sorted(discovered_urls_global):
            fh.write(u + "\n")

    cleaned = {p for p in wordlist_paths if p and p != "/"}
    with wordlist_path.open("w", encoding="utf-8") as fh:
        for p in sorted(cleaned):
            fh.write(p + "\n")

    def risk_counts(r: Dict[str,Any]) -> Tuple[int,int,int]:
        hi = sum(1 for f in r.get("findings", []) if f.get("sensitivity") == "high")
        md = sum(1 for f in r.get("findings", []) if f.get("sensitivity") == "medium")
        lo = sum(1 for f in r.get("findings", []) if f.get("sensitivity") == "low")
        return hi, md, lo

    rows = []
    for r in results:
        hi, md, lo = risk_counts(r)
        if hi > 0: risk = "HIGH"
        elif md > 0: risk = "MEDIUM"
        elif lo > 0: risk = "LOW"
        else: risk = "NONE"
        sample = " | ".join(f"{f.get('type')}:{(f.get('value') or '')[:80]}" for f in (r.get("findings") or [])[:6])
        rows.append({
            "identifier": r.get("js_url"),
            "risk": risk, "hi": hi, "md": md, "lo": lo,
            "has_sourcesContent": r.get("has_sourcesContent", False),
            "sample_hits": sample
        })

    def sort_key(row):
        bucket = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(row["risk"], 3)
        return (bucket, -row["hi"], -row["md"], -row["lo"], row["identifier"])

    rows_sorted = sorted(rows, key=sort_key)
    with csv_path.open("w", encoding="utf-8", newline="") as cf:
        w = csv.writer(cf)
        w.writerow(["identifier","risk","high_findings","medium_findings","low_findings","has_sourcesContent","sample_hits"])
        for row in rows_sorted:
            w.writerow([row["identifier"], row["risk"], row["hi"], row["md"], row["lo"], row["has_sourcesContent"], row["sample_hits"]])

    return {
        "findings_json": str(findings_path),
        "urls_txt": str(urls_path),
        "wordlist": str(wordlist_path),
        "csv": str(csv_path),
    }

# =========================
# CLI
# =========================
def read_input_lines(src: str) -> List[str]:
    if src == "-":
        return [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    p = Path(src)
    if not p.exists():
        raise FileNotFoundError(src)
    return [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")]

def main() -> None:
    print_banner()
    ap = argparse.ArgumentParser(
        prog="pelucio",
        description="Analisa JS e sourcemaps; segue refs de JS; gera CSV/JSON/URLs/wordlist."
    )
    ap.add_argument("-i","--input", required=True, help="arquivo com URLs .js (um por linha) ou '-' (stdin)")
    ap.add_argument("-o","--outdir", default="pelucio_out", help="diretório de saída")
    ap.add_argument("-t","--threads", type=int, default=10, help="workers em paralelo")
    ap.add_argument("--timeout", type=float, default=float(DEFAULT_TIMEOUT), help="timeout HTTP (s)")
    ap.add_argument("--max-depth", type=int, default=3, help="profundidade máxima de cascata (0=apenas os iniciais)")
    args = ap.parse_args()

    try:
        inputs = read_input_lines(args.input)
    except Exception as e:
        print("[!] failed to read input:", e, file=sys.stderr); sys.exit(2)
    if not inputs:
        print("[!] no inputs", file=sys.stderr); sys.exit(2)

    print(f"[+] pelucio: processando {len(inputs)} JS URLs com {args.threads} threads (max-depth={args.max_depth})...\n")
    summary = run_all(inputs, threads=args.threads, timeout=args.timeout, outdir=args.outdir, max_depth=args.max_depth)
    print("[+] arquivos gerados:")
    for k, v in summary.items():
        print(f"    - {k}: {v}")

if __name__ == "__main__":
    main()
