#!/usr/bin/env python3
# pelucio.py v1.4.2
# Analisa URLs de .js e .map (inline e remotos), detecta possíveis vazamentos,
# segue referências para outros .js (cascata limitada), e gera:
#   - pelucio_findings.json
#   - pelucio_urls.txt
#   - pelucio_endpoints.txt  (NOVO: endpoints/APIs descobertos com contexto e confiança)
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests

VERSION = "1.4.2"
DEFAULT_TIMEOUT = 15
UA = f"pelucio/{VERSION}"

# =========================
# Banner
# =========================
def print_banner() -> None:
    print("\n" + "=" * 72)
    print(f"  pelucio v{VERSION}")
    print("  Sourcemap & JavaScript Analyzer — endpoints, leaks e paths")
    print("  Bichinho tranquera roubador de itens preciosos")
    print("=" * 72 + "\n")


# =========================
# False-positive / noise
# =========================

# Domínios/fragmentos que indicam recurso externo conhecido — nunca são endpoints internos
NOISE_DOMAINS: Set[str] = {
    "fonts.gstatic.com", "fonts.googleapis.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "analytics.google.com", "doubleclick.net", "googlesyndication.com",
    "google.com/recaptcha", "recaptcha.net",
    "facebook.com", "facebook.net", "fbcdn.net", "instagram.com",
    "twitter.com", "t.co", "twimg.com",
    "linkedin.com", "licdn.com",
    "github.com", "githubusercontent.com",
    "jquery.com", "cloudflare.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net", "bootstrapcdn.com",
    "sentry.io", "sentry-cdn.com", "bugsnag.com",
    "hotjar.com", "fullstory.com", "logrocket.com",
    "intercom.io", "intercomcdn.com", "crisp.chat",
    "segment.com", "mixpanel.com", "amplitude.com",
    "newrelic.com", "nr-data.net", "datadog-browser-agent.com",
    "cloudfront.net", "akamaihd.net", "fastly.net",
    "amazonaws.com/cdn", "s3.amazonaws.com",
    "stripe.com", "js.stripe.com",
    "paypal.com", "paypalobjects.com",
    "maps.googleapis.com", "maps.gstatic.com",
    "wp-includes", "wp-content",
    "gravatar.com",
    "mozilla.org", "w3.org", "schema.org",
    "apple.com/favicon",
}

# Extensões de assets estáticos — não são endpoints HTTP úteis
NOISE_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".scss", ".less",
    ".pdf", ".zip", ".tar", ".gz",
    ".mp4", ".mp3", ".ogg", ".wav", ".webm",
    ".map",  # source maps já são tratados separadamente
}

# Prefixos de URL que são sempre ruído para endpoint hunting
NOISE_URL_PREFIXES = (
    "data:", "javascript:", "mailto:", "tel:", "blob:",
    "#", "about:",
)

# Fragmentos que — se encontrados no URL — indicam que é um recurso externo de analytics/cdn
FALSE_POS_FRAGMENTS = [
    "fonts.gstatic.com", "fonts.googleapis.com",
    "roboto", "com/s/roboto",
    "/wp-includes/",
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.net/en_US/fbevents",
    "connect.facebook.net",
    "cdn.segment.com",
    "hotjar.com",
    "bugsnag.com",
]


def is_noise_url(url: str) -> bool:
    """True se a URL claramente não é um endpoint interno da aplicação."""
    if not url:
        return True
    u = url.strip().lower()
    for prefix in NOISE_URL_PREFIXES:
        if u.startswith(prefix):
            return True
    for frag in FALSE_POS_FRAGMENTS:
        if frag in u:
            return True
    try:
        parsed = urlparse(u)
        host = parsed.hostname or ""
        for nd in NOISE_DOMAINS:
            if host == nd or host.endswith("." + nd):
                return True
        path = parsed.path.lower()
        ext = os.path.splitext(path)[1]
        if ext in NOISE_EXTENSIONS:
            return True
    except Exception:
        pass
    return False


def is_internal_hint(url_or_path: str) -> bool:
    """Heurística: o path parece ser um endpoint interno da aplicação."""
    p = url_or_path.lower().strip()
    internal_segments = (
        "/api/", "/api", "/v1/", "/v2/", "/v3/", "/v4/",
        "/graphql", "/rest/", "/rpc/",
        "/admin", "/internal/", "/private/",
        "/auth/", "/oauth/", "/login", "/logout", "/register", "/signup",
        "/user", "/account", "/profile",
        "/dashboard", "/panel",
        "/webhook", "/callback", "/redirect",
        "/service/", "/services/",
        "/backend/", "/server/",
        "/upload", "/download",
        "/search", "/suggest",
        "/config", "/settings",
        "/health", "/status", "/ping", "/ready", "/live",
        "/metrics", "/telemetry",
        "/ws", "/socket",
        "/_/", "/__/",
    )
    for seg in internal_segments:
        if seg in p:
            return True
    # Relative paths starting with /
    if p.startswith("/") and len(p) > 2 and not p.startswith("//"):
        return True
    return False


# =========================
# Endpoint Hunter
# =========================

# Captura o valor de string em qualquer tipo de aspas (single, double, backtick)
# Limitado a 300 chars para evitar match de blobs gigantes
_STR = r'(?:`([^`\n]{1,300})`|"([^"\n]{1,300})"|\'([^\'\n]{1,300})\')'


def _extract_str_value(m: re.Match, offset: int = 1) -> Optional[str]:
    """Retorna o primeiro grupo não-None do match (backtick, double, single)."""
    for i in range(offset, offset + 3):
        try:
            v = m.group(i)
            if v is not None:
                return v.strip()
        except IndexError:
            pass
    return None


# (label, regex, fixed_group_or_None, confidence)
# fixed_group_or_None: se int, usa esse grupo diretamente; se None, chama _extract_str_value
ENDPOINT_PATTERNS: List[Tuple[str, re.Pattern, Optional[int], str]] = [
    # ---------- chamadas HTTP de alta confiança ----------
    ("fetch", re.compile(
        r'\bfetch\s*\(\s*' + _STR, re.I
    ), None, "high"),

    ("fetch_then", re.compile(
        r'\bfetch\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*)?' + _STR, re.I
    ), None, "high"),

    ("axios", re.compile(
        r'\baxios\s*(?:\.\s*(?:get|post|put|patch|delete|head|options|request)\s*)?\(\s*' + _STR, re.I
    ), None, "high"),

    ("xhr_open", re.compile(
        r'\.open\s*\(\s*["\'][A-Z]{3,7}["\']\s*,\s*' + _STR, re.I
    ), None, "high"),

    ("jquery_http", re.compile(
        r'\$\s*\.\s*(?:ajax|get|post|getJSON|getScript|load)\s*\(\s*' + _STR, re.I
    ), None, "high"),

    ("superagent", re.compile(
        r'\b(?:request|superagent|got|ky|needle|wretch)\s*\.\s*(?:get|post|put|patch|del|delete)\s*\(\s*' + _STR, re.I
    ), None, "high"),

    ("http_client_generic", re.compile(
        r'\bhttp(?:Client|Service|)\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*' + _STR, re.I
    ), None, "high"),

    ("websocket_new", re.compile(
        r'\bnew\s+WebSocket\s*\(\s*' + _STR, re.I
    ), None, "high"),

    # ---------- configuração de URL ----------
    ("url_object_key", re.compile(
        r'''(?:^|[,{;(\s])url\s*:\s*''' + _STR, re.I | re.M
    ), None, "medium"),

    ("base_url_config", re.compile(
        r'\b(?:baseURL|baseUrl|base_url|apiUrl|api_url|'
        r'apiEndpoint|api_endpoint|endpoint|serviceUrl|'
        r'SERVICE_URL|API_URL|API_BASE(?:_URL)?|ROOT_URL|'
        r'REACT_APP_API|NEXT_PUBLIC_API|VUE_APP_API|'
        r'serverUrl|server_url|backendUrl|backend_url|'
        r'host(?:name)?|origin)\s*[=:]\s*' + _STR,
        re.I
    ), None, "medium"),

    ("action_key", re.compile(
        r'\baction\s*:\s*["\']([^"\']{2,200})["\']', re.I
    ), 1, "medium"),

    ("path_router", re.compile(
        r'\bpath\s*:\s*["\'](/[^"\'*\s]{1,200})["\']'
    ), 1, "medium"),

    ("route_definition", re.compile(
        r'\b(?:router|app)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*["\']([^"\']{2,200})["\']'
    ), 1, "medium"),

    # ---------- navegação / redirect ----------
    ("history_push", re.compile(
        r'\bhistory\s*\.\s*(?:push(?:State)?|replace(?:State)?)\s*\([^,)]*,\s*[^,)]*,\s*' + _STR, re.I
    ), None, "low"),

    ("navigate_call", re.compile(
        r'\b(?:navigate|redirectTo|router\.push|router\.replace|this\.\$router\.push)\s*\(\s*' + _STR, re.I
    ), None, "low"),

    ("location_assign", re.compile(
        r'\b(?:window\.location(?:\.href|\.assign|\.replace)?\s*=|location\.href\s*=)\s*' + _STR, re.I
    ), None, "low"),

    # ---------- string simples que parece path de API ----------
    ("api_path_literal", re.compile(
        r'["\'](\/?(?:api|v\d+|graphql|rest|rpc|admin|auth|internal|backend)'
        r'(?:/[A-Za-z0-9_\-\./:{}$]{0,150})?)["\']'
    ), 1, "medium"),
]


@dataclass
class EndpointHit:
    source_js: str
    label: str          # qual padrão capturou
    value: str          # URL ou path encontrado
    confidence: str     # high / medium / low
    context: str        # trecho de código ao redor (snippet)
    is_internal: bool = field(default=False)
    is_full_url: bool = field(default=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_js": self.source_js,
            "label": self.label,
            "value": self.value,
            "confidence": self.confidence,
            "context": self.context,
            "is_internal": self.is_internal,
            "is_full_url": self.is_full_url,
        }


def _normalize_endpoint(value: str) -> str:
    """Remove query-string e fragmento para fins de deduplicação."""
    v = value.strip()
    try:
        parsed = urlparse(v)
        if parsed.scheme in ("http", "https", "ws", "wss"):
            return urlunparse(parsed._replace(query="", fragment=""))
        # path relativo: strip query/fragment
        q = v.find("?")
        f = v.find("#")
        cut = min(c for c in (q, f, len(v)) if c >= 0)
        return v[:cut]
    except Exception:
        return v


def _snippet(text: str, match_start: int, match_end: int, radius: int = 80) -> str:
    start = max(0, match_start - radius)
    end = min(len(text), match_end + radius)
    raw = text[start:end].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s{2,}", " ", raw).strip()


def extract_endpoints(text: str, source_js: str) -> List[EndpointHit]:
    """
    Extrai endpoints/URLs chamados pelo JS com contexto e nível de confiança.
    Aplica filtragem agressiva de falsos positivos.
    """
    hits: List[EndpointHit] = []
    seen_normalized: Set[Tuple[str, str]] = set()

    for label, regex, fixed_group, confidence in ENDPOINT_PATTERNS:
        for m in regex.finditer(text):
            if fixed_group is not None:
                try:
                    val = m.group(fixed_group)
                except (IndexError, error):
                    val = None
            else:
                val = _extract_str_value(m, offset=1)

            if not val:
                continue
            val = val.strip()

            # Filtros básicos
            if len(val) < 2:
                continue
            if is_noise_url(val):
                continue
            # Ignora se parece ser só um identificador JS, cor CSS, etc.
            if re.fullmatch(r"[a-zA-Z_$][a-zA-Z0-9_$]*", val):
                continue
            if re.fullmatch(r"#[0-9a-fA-F]{3,8}", val):
                continue
            # Ignora strings que são claramente nomes de eventos ou CSS classes
            if re.fullmatch(r"[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*", val) and "/" not in val and "." not in val:
                if confidence != "high":
                    continue

            normalized = _normalize_endpoint(val)
            dedup_key = (label.split("_")[0], normalized)  # agrupa label similar
            if dedup_key in seen_normalized:
                continue
            seen_normalized.add(dedup_key)

            is_full = bool(re.match(r"^(?:https?|wss?|ws)://", val, re.I))
            is_int = is_internal_hint(val) or (
                is_full and not is_noise_url(val)
            )

            # Para labels de baixa confiança, só mantém se parece interno
            if confidence == "low" and not is_int:
                continue

            ctx = _snippet(text, m.start(), m.end())
            hits.append(EndpointHit(
                source_js=source_js,
                label=label,
                value=val,
                confidence=confidence,
                context=ctx,
                is_internal=is_int,
                is_full_url=is_full,
            ))

    return hits


# =========================
# Secrets / Findings patterns (melhorados, menos FP)
# =========================

PATTERNS = {
    "system_token_identifier": re.compile(
        r"\bSYSTEM_TOKEN(?:_BFF)?(?:_[A-Z0-9_]{3,})?\b"
    ),
    "datadog_synthetics_identifier": re.compile(
        r"datadog-[a-z0-9\-]+(?:token|public-id|result-id|execution-id)", re.I
    ),
    "shopify_checkout_api_token": re.compile(
        r"shopify-[a-z0-9\-]*token", re.I
    ),
    "google_site_verification": re.compile(
        r"google-site-verification", re.I
    ),
    "private_key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|PRIVATE) KEY-----"),
    "aws_secret_key": re.compile(
        r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40,}"
    ),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"
    ),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"
    ),
    "bearer_token": re.compile(
        r"(?i)bearer\s+([A-Za-z0-9\-\._~\+/=]{20,})"
    ),
    "query_token": re.compile(
        r"(?i)(?:token|api_key|access_token|auth|secret)=([^ \s&\"';]{8,})"
    ),
    # base64 longo mas com comprimento mínimo aumentado e sem match de hashes comuns
    "long_base64": re.compile(
        r"(?P<quote>['\"])?(?P<b64>[A-Za-z0-9+/]{60,}={0,2})(?:(?P=quote))"
    ),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "url": re.compile(r"https?://[^\s\"'<>]{10,}"),
    "password_like": re.compile(
        r"(?i)(?:\bsenha\b|\bpassw?d\b|\bpassword\b|\bpasswd\b|\bpwd\b)\s*[:=]\s*[\"']([^\"']{6,})[\"']"
    ),
    "script_src": re.compile(
        r"<script[^>]+src=[\"'](?P<src>[^\"']+\.js[^\"']*)[\"']", re.I
    ),
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

SOURCE_MAP_REGEX = re.compile(
    r"//#\s*sourceMappingURL\s*=\s*(.+)|//@\s*sourceMappingURL\s*=\s*(.+)"
)
INLINE_SOURCEMAP_REGEX = re.compile(
    r"(?:sourceMappingURL\s*=\s*data:application/json;base64,)([A-Za-z0-9+/=]+)"
)


# =========================
# Helpers
# =========================

def classify(kind: str, value: str, decoded_preview: Optional[str] = None) -> str:
    if kind in HIGH_TYPES:
        return "high"
    if kind in LOW_TYPES:
        if decoded_preview and any(
            k in decoded_preview.lower()
            for k in ("api_key", "secret", "token", "password", "private", "aws")
        ):
            return "high"
        return "low"
    return "low"


def try_gunzip(b: bytes) -> bytes:
    try:
        import gzip
        return gzip.decompress(b)
    except Exception:
        return b


def safe_fetch(
    url: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[bytes], Optional[int], Optional[str]]:
    try:
        r = requests.get(
            url,
            headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"},
            timeout=timeout,
            allow_redirects=True,
        )
        return r.content, r.status_code, None
    except requests.RequestException as e:
        return None, None, str(e)


def base64_try_decode(s: str) -> Optional[bytes]:
    s = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return None
    s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return None


def jwt_decode_part(part: str) -> Optional[str]:
    p = part.replace("-", "+").replace("_", "/")
    p += "=" * ((4 - len(p) % 4) % 4)
    try:
        return base64.b64decode(p).decode("utf-8", errors="ignore")
    except Exception:
        return None


def candidate_sourcemap_urls(js_url: str) -> List[str]:
    parsed = urlparse(js_url)
    base_path = parsed.path or ""
    candidates: List[str] = []
    if base_path.endswith(".js"):
        basename = os.path.basename(base_path)
        name_noext = os.path.splitext(basename)[0]
        candidates.append(urljoin(js_url, basename + ".map"))
        candidates.append(urljoin(js_url, base_path[:-3] + ".map"))
        candidates.append(
            urljoin(js_url, os.path.dirname(base_path) + "/" + name_noext + ".map")
        )
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
        if not p or p == "/":
            return set()
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
    if ref.startswith("data:"):
        return None
    if re.match(r"^https?://", ref, re.I):
        return ref
    try:
        joined = urljoin(base_url, ref)
        if re.match(r"^https?://", joined, re.I):
            return joined
    except Exception:
        pass
    return None


# =========================
# Análise de texto (secrets)
# =========================

def analyze_text(
    blob_text: str,
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    findings: List[Dict[str, Any]] = []
    urls_found: List[str] = []
    js_refs: List[str] = []

    for key, regex in PATTERNS.items():
        for m in regex.finditer(blob_text):
            try:
                if key in ("bearer_token", "query_token", "password_like"):
                    val = m.group(1) if m.groups() else m.group(0)
                elif key == "long_base64":
                    val = (
                        m.group("b64") if "b64" in regex.groupindex else m.group(0)
                    )
                elif key == "script_src":
                    val = m.group("src")
                else:
                    val = m.group(0)
            except Exception:
                val = m.group(0)
            val = (val or "").strip()
            if not val:
                continue
            if key == "url" and is_noise_url(val):
                continue

            decoded_preview = None
            jwt_parts = None

            if key == "long_base64":
                dec = base64_try_decode(val)
                if dec:
                    try:
                        decoded_preview = dec.decode("utf-8", errors="ignore")
                    except Exception:
                        pass

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

            findings.append(
                {
                    "type": key,
                    "value": val,
                    "decoded_preview": decoded_preview,
                    "jwt_parts": jwt_parts,
                    "sensitivity": classify(key, val, decoded_preview),
                }
            )

    for m in re.finditer(r"https?://[^\s'\"<>]+\.js[^\s'\"<>]*", blob_text):
        u = m.group(0)
        if u not in urls_found:
            urls_found.append(u)

    return findings, sorted(set(urls_found)), sorted(set(js_refs))


def parse_sourcemap_bytes(
    blob_bytes: bytes,
) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        txt = try_gunzip(blob_bytes).decode("utf-8", errors="ignore")
    except Exception:
        txt = str(blob_bytes[:2000])
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

def process_js_entry(js_url: str, timeout: float) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "js_url": js_url,
        "js_status": None,
        "sourcemap_found": None,
        "sourcemap_status": None,
        "has_sourcesContent": False,
        "findings": [],
        "discovered_urls": [],
        "referenced_js": [],
        "endpoints": [],          # NOVO
    }
    js_bytes, js_status, _ = safe_fetch(js_url, timeout=timeout)
    result["js_status"] = js_status
    if not js_bytes:
        return result

    try:
        js_text = try_gunzip(js_bytes).decode("utf-8", errors="replace")
    except Exception:
        js_text = js_bytes.decode("latin1", errors="replace")

    # --- inline sourcemap ---
    inline = INLINE_SOURCEMAP_REGEX.search(js_text)
    if inline:
        try:
            dec = base64.b64decode(inline.group(1))
            obj, hay = parse_sourcemap_bytes(dec)
            result["sourcemap_found"] = {"type": "inline"}
            if obj and obj.get("sourcesContent"):
                result["has_sourcesContent"] = True
            f, u, refs = analyze_text(hay)
            result["findings"].extend(f)
            result["discovered_urls"].extend(u)
            result["referenced_js"].extend(refs)
            for ep in extract_endpoints(hay, js_url):
                result["endpoints"].append(ep.to_dict())
        except Exception:
            pass

    # --- sourcemap remoto ---
    sm_comments = SOURCE_MAP_REGEX.findall(js_text)
    sm_targets = [m[0] or m[1] for m in sm_comments if (m[0] or m[1])]
    candidates: List[str] = []
    for tgt in sm_targets:
        tgt = tgt.strip()
        if not tgt.startswith("data:"):
            candidates.append(urljoin(js_url, tgt))
    candidates.extend(candidate_sourcemap_urls(js_url))

    seen_c: Set[str] = set()
    uniq_c: List[str] = []
    for c in candidates:
        if c not in seen_c:
            seen_c.add(c)
            uniq_c.append(c)

    for c in uniq_c:
        mb, st, _ = safe_fetch(c, timeout=timeout)
        if not mb:
            continue
        obj, hay = parse_sourcemap_bytes(mb)
        result["sourcemap_found"] = {"type": "remote", "url": c}
        result["sourcemap_status"] = st
        if obj and obj.get("sourcesContent"):
            result["has_sourcesContent"] = True
        f, u, refs = analyze_text(hay)
        result["findings"].extend(f)
        result["discovered_urls"].extend(u)
        result["referenced_js"].extend(refs)
        for ep in extract_endpoints(hay, js_url):
            result["endpoints"].append(ep.to_dict())
        break

    # --- JS direto ---
    f_js, u_js, refs_js = analyze_text(js_text)
    result["findings"].extend(f_js)
    result["discovered_urls"].extend(u_js)
    result["referenced_js"].extend(refs_js)
    for ep in extract_endpoints(js_text, js_url):
        result["endpoints"].append(ep.to_dict())

    # --- resolver refs de JS ---
    resolved_refs: List[str] = []
    for ref in sorted(set(result["referenced_js"])):
        r = resolve_ref(js_url, ref)
        if r:
            resolved_refs.append(r)
    for u in result["discovered_urls"]:
        if u.lower().endswith(".js"):
            resolved_refs.append(u)
    result["referenced_js"] = sorted(set(resolved_refs))

    # --- dedup findings ---
    uniqf: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in result["findings"]:
        k = (f.get("type"), f.get("value"))
        if k not in uniqf:
            uniqf[k] = f
    result["findings"] = list(uniqf.values())

    # --- dedup endpoints ---
    seen_ep: Set[Tuple[str, str]] = set()
    deduped_ep: List[Dict[str, Any]] = []
    for ep in result["endpoints"]:
        k = (ep.get("label", "").split("_")[0], _normalize_endpoint(ep.get("value", "")))
        if k not in seen_ep:
            seen_ep.add(k)
            deduped_ep.append(ep)
    result["endpoints"] = deduped_ep

    result["discovered_urls"] = sorted(set(result["discovered_urls"]))
    return result


# =========================
# Runner
# =========================

def _confidence_order(c: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(c, 3)


def run_all(
    js_list: List[str],
    threads: int,
    timeout: float,
    outdir: str,
    max_depth: int = 3,
    base_domain: Optional[str] = None,
) -> Dict[str, Any]:
    outp = Path(outdir)
    outp.mkdir(parents=True, exist_ok=True)
    findings_path = outp / "pelucio_findings.json"
    urls_path = outp / "pelucio_urls.txt"
    endpoints_path = outp / "pelucio_endpoints.txt"
    wordlist_path = outp / "pelucio_wordlist.txt"
    csv_path = outp / "pelucio_findings.csv"

    results: List[Dict[str, Any]] = []
    discovered_urls_global: Set[str] = set()
    wordlist_paths: Set[str] = set()
    all_endpoints: List[Dict[str, Any]] = []

    seen_urls: Set[str] = set()
    lock = threading.Lock()
    scheduled = 0
    processed = 0

    def submit_url(ex, u: str, depth: int, fmap: Dict) -> None:
        nonlocal scheduled
        with lock:
            if u in seen_urls:
                return
            seen_urls.add(u)
            scheduled += 1
        fut = ex.submit(process_js_entry, u, timeout)
        fmap[fut] = (u, depth)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures_map: Dict[concurrent.futures.Future, Tuple[str, int]] = {}
        for u in js_list:
            su = u.strip()
            if su:
                submit_url(ex, su, 0, futures_map)

        while futures_map:
            done, _ = concurrent.futures.wait(
                list(futures_map.keys()),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done:
                url, depth = futures_map.pop(fut)
                try:
                    res = fut.result()
                except Exception as e:
                    res = {
                        "js_url": url,
                        "findings": [],
                        "discovered_urls": [],
                        "referenced_js": [],
                        "endpoints": [],
                        "error": str(e),
                    }
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

                for ep in res.get("endpoints", []):
                    # filtro por base_domain se especificado
                    val = ep.get("value", "")
                    if base_domain:
                        if re.match(r"^https?://", val, re.I):
                            try:
                                h = urlparse(val).hostname or ""
                                if base_domain not in h:
                                    continue
                            except Exception:
                                pass
                    all_endpoints.append(ep)

                if depth < max_depth:
                    for ref in res.get("referenced_js", []):
                        if re.match(r"^https?://", ref, re.I):
                            submit_url(ex, ref, depth + 1, futures_map)

                with lock:
                    processed += 1
                    pct = (processed / scheduled) * 100 if scheduled else 100.0
                sys.stdout.write(
                    f"\r[+] Andamento: {processed}/{scheduled} ({pct:.1f}%)   "
                )
                sys.stdout.flush()

    print("\n[+] Análise concluída.\n")

    # --- dedup global de endpoints ---
    seen_global: Set[Tuple[str, str]] = set()
    deduped_global: List[Dict[str, Any]] = []
    for ep in all_endpoints:
        k = (
            ep.get("label", "").split("_")[0],
            _normalize_endpoint(ep.get("value", "")),
        )
        if k not in seen_global:
            seen_global.add(k)
            deduped_global.append(ep)

    deduped_global.sort(
        key=lambda e: (
            _confidence_order(e.get("confidence", "low")),
            0 if e.get("is_internal") else 1,
            e.get("value", ""),
        )
    )

    # --- JSON principal ---
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_count": len(js_list),
        "version": VERSION,
        "cascading_max_depth": max_depth,
        "total_processed": len(results),
        "total_endpoints": len(deduped_global),
        "base_domain_filter": base_domain,
    }
    with findings_path.open("w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "results": results}, fh, ensure_ascii=False, indent=2)

    # --- URLs ---
    with urls_path.open("w", encoding="utf-8") as fh:
        for u in sorted(discovered_urls_global):
            fh.write(u + "\n")

    # --- Endpoints (destaque da v1.4.2) ---
    _conf_label = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}
    with endpoints_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# pelucio v{VERSION} — endpoints discovered\n")
        fh.write(f"# generated: {meta['generated_at']}\n")
        fh.write(f"# total: {len(deduped_global)}\n\n")

        current_conf = None
        for ep in deduped_global:
            conf = ep.get("confidence", "low")
            if conf != current_conf:
                current_conf = conf
                fh.write(f"\n{'─'*60}\n")
                fh.write(f"# {_conf_label.get(conf, conf).strip()} confidence\n")
                fh.write(f"{'─'*60}\n\n")

            label = ep.get("label", "?")
            value = ep.get("value", "")
            src = ep.get("source_js", "")
            ctx = ep.get("context", "")
            internal_flag = " [internal]" if ep.get("is_internal") else ""

            fh.write(f"{value}{internal_flag}\n")
            fh.write(f"  via: {label}  |  src: {src}\n")
            if ctx:
                fh.write(f"  ctx: {ctx[:160]}\n")
            fh.write("\n")

    # --- Wordlist ---
    cleaned = {p for p in wordlist_paths if p and p != "/"}
    # enriquece wordlist com paths dos endpoints
    for ep in deduped_global:
        v = ep.get("value", "")
        for p in extract_paths_from_url(v if v.startswith("http") else "http://x" + v):
            cleaned.add(p)
    with wordlist_path.open("w", encoding="utf-8") as fh:
        for p in sorted(cleaned):
            fh.write(p + "\n")

    # --- CSV ---
    def risk_counts(r: Dict[str, Any]) -> Tuple[int, int, int]:
        hi = sum(1 for f in r.get("findings", []) if f.get("sensitivity") == "high")
        md = sum(1 for f in r.get("findings", []) if f.get("sensitivity") == "medium")
        lo = sum(1 for f in r.get("findings", []) if f.get("sensitivity") == "low")
        return hi, md, lo

    rows = []
    for r in results:
        hi, md, lo = risk_counts(r)
        ep_count = len(r.get("endpoints", []))
        ep_high = sum(
            1 for e in r.get("endpoints", []) if e.get("confidence") == "high"
        )
        if hi > 0:
            risk = "HIGH"
        elif ep_high > 0 or md > 0:
            risk = "MEDIUM"
        elif lo > 0 or ep_count > 0:
            risk = "LOW"
        else:
            risk = "NONE"
        sample = " | ".join(
            f"{f.get('type')}:{(f.get('value') or '')[:80]}"
            for f in (r.get("findings") or [])[:6]
        )
        rows.append(
            {
                "identifier": r.get("js_url"),
                "risk": risk,
                "hi": hi,
                "md": md,
                "lo": lo,
                "endpoints_found": ep_count,
                "endpoints_high_conf": ep_high,
                "has_sourcesContent": r.get("has_sourcesContent", False),
                "sample_hits": sample,
            }
        )

    def sort_key(row: Dict) -> Tuple:
        bucket = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(row["risk"], 3)
        return (bucket, -row["hi"], -row["md"], -row["lo"], row["identifier"])

    rows_sorted = sorted(rows, key=sort_key)
    with csv_path.open("w", encoding="utf-8", newline="") as cf:
        w = csv.writer(cf)
        w.writerow([
            "identifier", "risk", "high_findings", "medium_findings",
            "low_findings", "endpoints_found", "endpoints_high_conf",
            "has_sourcesContent", "sample_hits",
        ])
        for row in rows_sorted:
            w.writerow([
                row["identifier"], row["risk"], row["hi"], row["md"],
                row["lo"], row["endpoints_found"], row["endpoints_high_conf"],
                row["has_sourcesContent"], row["sample_hits"],
            ])

    return {
        "findings_json": str(findings_path),
        "urls_txt": str(urls_path),
        "endpoints_txt": str(endpoints_path),
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
    return [
        l.strip()
        for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]


def main() -> None:
    print_banner()
    ap = argparse.ArgumentParser(
        prog="pelucio",
        description=(
            "Analisa JS e sourcemaps; caça endpoints/APIs internos; "
            "segue refs de JS; gera CSV/JSON/endpoints/URLs/wordlist."
        ),
    )
    ap.add_argument(
        "-i", "--input", required=True,
        help="arquivo com URLs .js (um por linha) ou '-' (stdin)",
    )
    ap.add_argument("-o", "--outdir", default="pelucio_out", help="diretório de saída")
    ap.add_argument("-t", "--threads", type=int, default=10, help="workers em paralelo")
    ap.add_argument(
        "--timeout", type=float, default=float(DEFAULT_TIMEOUT), help="timeout HTTP (s)"
    )
    ap.add_argument(
        "--max-depth", type=int, default=3,
        help="profundidade máxima de cascata (0=apenas os iniciais)",
    )
    ap.add_argument(
        "--base-domain", default=None,
        help=(
            "domínio base da aplicação (ex: example.com). "
            "Filtra endpoints externos de URLs absolutas do output de endpoints."
        ),
    )
    args = ap.parse_args()

    try:
        inputs = read_input_lines(args.input)
    except Exception as e:
        print("[!] falha ao ler input:", e, file=sys.stderr)
        sys.exit(2)
    if not inputs:
        print("[!] nenhum input", file=sys.stderr)
        sys.exit(2)

    print(
        f"[+] pelucio: processando {len(inputs)} JS URLs "
        f"com {args.threads} threads (max-depth={args.max_depth})"
        + (f", base-domain={args.base_domain}" if args.base_domain else "")
        + "...\n"
    )
    summary = run_all(
        inputs,
        threads=args.threads,
        timeout=args.timeout,
        outdir=args.outdir,
        max_depth=args.max_depth,
        base_domain=args.base_domain,
    )
    print("[+] arquivos gerados:")
    for k, v in summary.items():
        print(f"    - {k}: {v}")


if __name__ == "__main__":
    main()
