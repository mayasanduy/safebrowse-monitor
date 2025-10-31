#!/usr/bin/env python3
# check_safebrowsing.py - for GitHub Actions
import os, time, json, logging, requests
from typing import List

API_KEY = os.getenv("GSB_API_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
DOMAINS_FILE = os.getenv("DOMAINS_FILE", "domains.txt")
LOGFILE = os.getenv("LOGFILE", "safebrowse.log")
BATCH_SIZE = 500
REQUEST_TIMEOUT = 15

if not API_KEY:
    raise SystemExit("Set GSB_API_KEY environment variable and re-run.")

logging.basicConfig(filename=LOGFILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
console = logging.StreamHandler(); console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def read_urls(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f]
    urls = []
    for ln in lines:
        if not ln: continue
        urls.append(ln if ln.startswith(("http://","https://")) else "http://" + ln)
    return urls

def chunked(it, n):
    for i in range(0, len(it), n):
        yield it[i:i+n]

def find_threats(urls: List[str]):
    body = {
        "client": {"clientId": "github-actions-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }
    headers = {"Content-Type":"application/json"}
    backoff = 1
    for _ in range(6):
        try:
            r = requests.post(API_URL, headers=headers, json=body, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            logging.error("Request failed: %s", e); time.sleep(backoff); backoff*=2; continue
        if r.status_code == 200:
            try: return r.json()
            except ValueError: logging.error("Invalid JSON"); return {}
        if r.status_code in (429,500,502,503,504):
            logging.warning("Rate/server error %s. Backoff %ss", r.status_code, backoff)
            time.sleep(backoff); backoff*=2; continue
        logging.error("Unexpected %s: %s", r.status_code, r.text[:300]); return {}
    logging.error("Exceeded retries."); return {}

def send_telegram(text: str):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        logging.info("Telegram not configured."); return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": True, "parse_mode": "HTML"}
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code >= 400:
            logging.error("Telegram error %s: %s", r.status_code, r.text[:200])
        else:
            logging.info("Telegram notified.")
    except Exception as e:
        logging.error("Telegram exception: %s", e)

def build_tg_message(matches: list, batch_total: int) -> str:
    lines = ["<b>Safe Browsing ALERT</b>",
             f"Matches: <b>{len(matches)}</b> (checked {batch_total})"]
    by_url = {}
    for m in matches:
        u = m.get("threat",{}).get("url","unknown")
        t = m.get("threatType","UNKNOWN")
        by_url.setdefault(u,set()).add(t)
    for i,(u,types) in enumerate(by_url.items()):
        if i>=20: lines.append("… (more)"); break
        lines.append(f"• <code>{u}</code> → {', '.join(sorted(types))}")
    lines.append("Action: clean site and request review in Search Console.")
    return "\n".join(lines)

def main():
    urls = read_urls(DOMAINS_FILE)
    if not urls:
        logging.info("No URLs to check."); return
    total = 0
    for batch in chunked(urls, BATCH_SIZE):
        total += len(batch)
        result = find_threats(batch)
        matches = result.get("matches", [])
        if matches:
            msg = build_tg_message(matches, len(batch))
            send_telegram(msg)
            logging.info("Matches: %s", json.dumps(matches, ensure_ascii=False)[:2000])
        else:
            logging.info("No matches in batch of %d", len(batch))
    logging.info("Finished. Total processed: %d", total)

if __name__ == "__main__":
    main()
