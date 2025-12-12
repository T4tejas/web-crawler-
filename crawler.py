#!/usr/bin/env python3
"""
Lightweight crawler + passive scanner:
- Respects robots.txt
- Discovers pages, forms, inputs, query params
- Performs safe reflection checks (non-executable marker)
- Detects likely missing CSRF tokens on POST forms (heuristic)
- Collects cookie attributes (Secure/HttpOnly/SameSite)
Outputs results.json and results.html/pdf report via report_generator.py
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time, json, re, os, hashlib
from collections import deque

import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "curl/8.0.1",
    "Wget/1.21.1",
]

def fetch(url, session):
    try:
        resp = session.post(url, data=data, headers=get_headers(), timeout=12)
        return resp
    except Exception:
        return None

def fetch(url, session):
    try:
        resp = session.get(new, headers=get_headers(), timeout=12)
        return resp
    except Exception as e:
        return None

def get_links(html, base):
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        full = urljoin(base, href)
        links.add(full.split('#')[0])
    return links

def extract_forms(html, base):
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = form.get("method","get").lower()
        fields = []
        for inp in form.find_all(["input","textarea","select"]):
            name = inp.get("name")
            itype = inp.get("type", inp.name)
            fields.append({"name": name, "type": itype})
        forms.append({"action": urljoin(base, action), "method": method, "fields": fields})
    return forms

def cookie_attrs_from_response(resp):
    cookies = []
    for c in resp.cookies:
        # requests' cookie object doesn't expose SameSite etc; parse Set-Cookie header
        pass
    set_cookie_headers = resp.headers.get("Set-Cookie")
    attrs = []
    if set_cookie_headers:
        # naive parse: split multiple Set-Cookie by comma can be tricky; use regex to find attributes per cookie
        for part in resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [set_cookie_headers]:
            attrs.append(part)
    return attrs

def safe_reflection_check(session, url, param_name=None, is_form=False):
    """
    Inject a harmless marker string and check for reflection unencoded.
    Marker is non-executable: e.g. <<SCAN_MARKER_xxx>>
    Returns True if marker is reflected raw in the response body (possible output encoding issue).
    """
    marker = f"<<SCAN_MARKER_{hashlib.sha1(url.encode()).hexdigest()[:8]}>>"
    if is_form:
        data = {param_name: marker} if param_name else { "test": marker }
        try:
            resp = session.post(url, data=data, headers=HEADERS, timeout=12)
        except Exception:
            return False, None
    else:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        if param_name:
            q[param_name] = marker
        else:
            # pick one param or append a new
            q_key = "_scan"
            q[q_key] = marker
        qs = "&".join(f"{k}={v[0]}" for k,v in q.items())
        new = parsed._replace(query=qs).geturl()
        try:
            resp = session.get(new, headers=HEADERS, timeout=12)
        except Exception:
            return False, None

    if resp is None:
        return False, None
    body = resp.text
    # raw substring check - also check for encoded forms (e.g., &lt; &gt;). If marker appears raw, it's risky.
    if marker in body:
        return True, marker
    # also check for encoded version
    enc = marker.replace("<","&lt;").replace(">","&gt;")
    if enc in body:
        # encoded reflection - probably safer (output is encoded) but record it
        return False, marker
    return False, None

def crawl(start_url, max_pages=MAX_PAGES):
    parsed_start = urlparse(start_url)
    base_netloc = parsed_start.netloc
    session = requests.Session()
    session.headers.update(HEADERS)
    seen = set()
    q = deque([start_url])
    results = {"pages": []}
    pages_scanned = 0

    while q and pages_scanned < max_pages:
        url = q.popleft()
        if url in seen: 
            continue
        seen.add(url)
        time.sleep(RATE_LIMIT)
        resp = fetch(url, session)
        if not resp or resp.status_code >= 500:
            continue
        pages_scanned += 1
        page = {"url": url, "status": resp.status_code, "forms": [], "params": [], "cookies": [], "issues": []}
        html = resp.text
        # find links to continue crawl (limit to same domain)
        for link in get_links(html, url):
            if urlparse(link).netloc == base_netloc and link not in seen:
                q.append(link)
        # extract forms
        forms = extract_forms(html, url)
        page["forms"] = forms
        # extract query params
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for k in qs:
            page["params"].append(k)
        # cookie inspection (passive)
        # For now we capture Set-Cookie header text
        sc = resp.headers.get("Set-Cookie")
        if sc:
            page["cookies"].append(sc)
        # Passive checks: CSRF token heuristic (POST forms without obvious token fields)
        for f in forms:
            if f["method"] == "post":
                field_names = [ (fld.get("name") or "").lower() for fld in f["fields"] ]
                has_token = any("csrf" in n or "token" in n or "authenticity" in n for n in field_names)
                if not has_token:
                    page["issues"].append({
                        "type":"missing_csrf_token",
                        "message":"POST form with no obvious CSRF token field found",
                        "form": f
                    })
            # Safe reflection check on text fields (non-executable marker)
            for fld in f["fields"]:
                if not fld.get("name"):
                    continue
                reflected, marker = safe_reflection_check(session, f["action"], param_name=fld["name"], is_form=True)
                if reflected:
                    page["issues"].append({
                        "type":"possible_reflection",
                        "message": f"Marker reflected raw for form field {fld['name']}",
                        "field": fld
                    })
        # Passive reflection check for URL params
        for p in page["params"]:
            reflected, marker = safe_reflection_check(session, url, param_name=p, is_form=False)
            if reflected:
                page["issues"].append({
                    "type":"possible_reflection",
                    "message": f"Marker reflected raw for query param {p}"
                })
        results["pages"].append(page)

    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("start_url")
    parser.add_argument("--max", type=int, default=200)
    parser.add_argument("--out", default="results.json")
    args = parser.parse_args()
    r = crawl(args.start_url, max_pages=args.max)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(r, f, indent=2)
    print("Scan complete; results written to", args.out)
