import os
import re
import sys
import json
import time
import shutil
import base64
import sqlite3
import tempfile
import subprocess
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

# ==================== تنظیمات ====================
BASE_URL = "https://www.v2nodes.com"

# لیست کشورهای هدف برای استخراج
TARGET_COUNTRIES = [
    "us", "de", "fr", "nl", "gb", "ca", "sg", "jp", 
    "kr", "tr", "fi", "se", "ch", "it", "es", "pl", "ae"
]

OUTPUT_DIR = "subs"
DB_FILE = "tested_configs.db"
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 2.0           # حداکثر مهلت پاسخ‌دهی تست اتصال (ثانیه)
MAX_TEST_PER_COUNTRY = 60    # حداکثر تعداد کانفیگ جدید برای تست در هر کشور
EXPIRY_HOURS = 12            # مدت زمان ماندگاری کانفیگ در کش
MAX_FAILURES = 2             # دفعات مجاز عدم پاسخ قبل از حذف از دیتابیس

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# ==================== پایگاه داده ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS tested_configs
                 (config_hash TEXT PRIMARY KEY, country TEXT, real_delay REAL, last_test_time REAL, fail_count INTEGER DEFAULT 0)""")
    conn.commit()
    conn.close()

def save_config(config_hash, country, real_delay, fail_count=0):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO tested_configs 
                 (config_hash, country, real_delay, last_test_time, fail_count)
                 VALUES (?, ?, ?, ?, ?)""",
              (config_hash, country, real_delay, time.time(), fail_count))
    conn.commit()
    conn.close()

def delete_config(config_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM tested_configs WHERE config_hash=?", (config_hash,))
    conn.commit()
    conn.close()

def increment_fail(config_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE tested_configs SET fail_count = fail_count + 1, last_test_time = ? WHERE config_hash=?",
              (time.time(), config_hash))
    c.execute("SELECT fail_count FROM tested_configs WHERE config_hash=?", (config_hash,))
    row = c.fetchone()
    conn.commit()
    conn.close()
    return row[0] if row else 0

def get_cached_for_country(country):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT config_hash, real_delay FROM tested_configs WHERE country=? ORDER BY real_delay ASC", (country,))
    rows = c.fetchall()
    conn.close()
    return {r[0]: r for r in rows}

# ==================== استخراج بدون فیلتر از V2Nodes ====================
def is_valid_protocol_link(link):
    """صرفاً بررسی ساختار اولیه پروتکل بدون اعمال فیلتر کیفی"""
    if not link or not isinstance(link, str):
        return False
    return any(link.startswith(proto) for proto in ["vless://", "vmess://", "ss://", "trojan://"])

def fetch_country_configs(country_code):
    """استخراج تمامی کانفیگ‌های کشور بدون فیلترهای محدودکننده"""
    country_url = f"{BASE_URL}/country/{country_code}/"
    session = requests.Session()
    session.headers.update(HEADERS)

    found_configs = set()
    try:
        resp = session.get(country_url, timeout=15)
        if resp.status_code != 200:
            print(f"⚠️ خطای {resp.status_code} در دریافت صفحه {country_code}")
            return []

        # ۱. تلاش برای یافتن لینک اشتراک داینامیک
        sub_link_match = re.search(r'https?://[^\s"\'<>]+/subscriptions/country/[^"\'\s<>]+', resp.text)
        sub_url = None
        if sub_link_match:
            sub_url = sub_link_match.group(0)
        else:
            soup = BeautifulSoup(resp.text, "html.parser")
            for inp in soup.find_all("input"):
                val = inp.get("value", "")
                if "/subscriptions/country/" in val:
                    sub_url = val
                    break

        if sub_url:
            print(f"   ↳ لینک اشتراک: {sub_url[:65]}...")
            sub_resp = session.get(sub_url, timeout=15)
            if sub_resp.status_code == 200:
                raw_text = sub_resp.text.strip()
                try:
                    padded = raw_text + "=" * ((4 - len(raw_text) % 4) % 4)
                    decoded_text = base64.b64decode(padded).decode("utf-8", errors="ignore")
                    lines = decoded_text.splitlines()
                except Exception:
                    lines = raw_text.splitlines()

                for line in lines:
                    line = line.strip()
                    if is_valid_protocol_link(line):
                        found_configs.add(line)

        # ۲. استخراج تمام لینک‌های پروتکل از متن HTML صفحه به عنوان مکمل
        page_matches = re.findall(r'(?:vless|vmess|ss|trojan)://[^\s"\'<>]+', resp.text)
        for link in page_matches:
            if is_valid_protocol_link(link):
                found_configs.add(link)

    except Exception as e:
        print(f"⚠️ خطا در دریافت اطلاعات کشور {country_code}: {e}")

    return list(found_configs)

# ==================== هسته تست Xray ====================
def download_xray():
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    resp = requests.get(url, stream=True, timeout=30)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        for chunk in resp.iter_content(chunk_size=8192):
            tmp.write(chunk)
        zip_path = tmp.name
    xray_dir = tempfile.mkdtemp()
    shutil.unpack_archive(zip_path, xray_dir)
    xray_bin = os.path.join(xray_dir, "xray")
    os.chmod(xray_bin, 0o755)
    return xray_bin

def parse_link_to_outbound(link):
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            padded = b64 + "=" * (4 - len(b64) % 4) if len(b64) % 4 != 0 else b64
            decoded = json.loads(base64.b64decode(padded).decode("utf-8"))
            out = {
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": decoded["add"],
                    "port": int(decoded["port"]),
                    "users": [{"id": decoded["id"], "security": decoded.get("scy", "auto")}]
                }]},
                "streamSettings": {"network": decoded.get("net", "tcp")}
            }
            if decoded.get("net") == "ws":
                out["streamSettings"]["wsSettings"] = {
                    "path": decoded.get("path", "/"),
                    "headers": {"Host": decoded.get("host", decoded["add"])} if decoded.get("host") else {}
                }
            if decoded.get("tls") == "tls":
                out["streamSettings"]["security"] = "tls"
                out["streamSettings"]["tlsSettings"] = {"serverName": decoded.get("sni", decoded["add"])}
            return out

        elif link.startswith("ss://"):
            parsed = urlparse(link)
            userinfo = parsed.username
            if userinfo:
                try:
                    padded = userinfo + "=" * (4 - len(userinfo) % 4) if len(userinfo) % 4 != 0 else userinfo
                    decoded = base64.b64decode(padded).decode("utf-8")
                    method, password = decoded.split(":", 1) if ":" in decoded else ("aes-256-gcm", decoded)
                except Exception:
                    method, password = userinfo.split(":", 1) if ":" in userinfo else ("aes-256-gcm", userinfo)
            else:
                return None
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": parsed.hostname, "port": int(parsed.port), "method": method, "password": password}]},
                "streamSettings": {"network": "tcp", "security": "none"}
            }

        elif link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urlparse(link)
            is_vless = link.startswith("vless://")
            protocol = "vless" if is_vless else "trojan"
            
            port = parsed.port if parsed.port else 443
            settings = {"vnext": [{"address": parsed.hostname, "port": port, "users": [{"id": parsed.username, "encryption": "none", "flow": ""}]}]} if is_vless else {"servers": [{"address": parsed.hostname, "port": port, "password": parsed.username}]}

            params = parse_qs(parsed.query)
            def gp(k, d=""): return params.get(k, [d])[0]

            network = gp("type", "tcp")
            security = gp("security", "none")
            sni = gp("sni", parsed.hostname)
            host = gp("host", "")
            path = gp("path", "/")
            header_type = gp("headerType", "none")
            alpn = gp("alpn", "")
            fp = gp("fp", "")
            flow = gp("flow", "")

            if is_vless and flow:
                settings["vnext"][0]["users"][0]["flow"] = flow

            outbound = {
                "protocol": protocol,
                "settings": settings,
                "streamSettings": {"network": network, "security": security}
            }

            if network == "ws":
                outbound["streamSettings"]["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
            elif network == "tcp" and header_type == "http":
                outbound["streamSettings"]["tcpSettings"] = {"header": {"type": "http", "request": {"headers": {"Host": host} if host else {}, "path": [path]}}}
            elif network == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {"serviceName": path.lstrip("/"), "multiMode": False}
            elif network in ["xhttp", "httpupgrade"]:
                outbound["streamSettings"][f"{network}Settings"] = {"path": path, "host": host}

            if security == "tls":
                tls_settings = {"serverName": sni, "allowInsecure": gp("allowInsecure", "0") == "1"}
                if alpn: tls_settings["alpn"] = alpn.split(",")
                if fp: tls_settings["fingerprint"] = fp
                outbound["streamSettings"]["tlsSettings"] = tls_settings
            elif security == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": sni,
                    "fingerprint": fp if fp else "chrome",
                    "publicKey": gp("pbk", ""),
                    "shortId": gp("sid", ""),
                    "spiderX": gp("spx", "")
                }
            return outbound

    except Exception:
        return None

def test_single_config(xray_bin, link, timeout=TEST_TIMEOUT):
    outbound = parse_link_to_outbound(link)
    if not outbound:
        return False, 999999

    inbound = {"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": False, "auth": "noauth"}}
    config = {"inbounds": [inbound], "outbounds": [outbound]}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    xray_proc = None
    try:
        xray_proc = subprocess.Popen([xray_bin, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.8)

        res = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
             "--socks5-hostname", "127.0.0.1:10808", TEST_URL,
             "--connect-timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 4
        )

        if res.returncode == 0 and res.stdout.strip():
            latency = float(res.stdout.strip()) * 1000
            if latency < timeout * 1000:
                return True, latency
        return False, 999999
    except Exception:
        return False, 999999
    finally:
        if xray_proc:
            xray_proc.terminate()
            try: xray_proc.wait(timeout=2)
            except: xray_proc.kill()
        try: os.unlink(config_path)
        except: pass

# ==================== اجرای اصلی ====================
def main():
    init_db()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("📥 دانلود هسته Xray...")
    xray_bin = download_xray()
    print("✅ هسته Xray آماده شد.\n")

    all_valid_configs = []

    for country in TARGET_COUNTRIES:
        print(f"🌍 بررسی کشور [{country.upper()}]...")
        raw_configs = fetch_country_configs(country)
        print(f"   ↳ {len(raw_configs)} کانفیگ خام دریافت شد.")

        cached_country = get_cached_for_country(country)
        valid_country_configs = dict(cached_country)

        to_test = [c for c in raw_configs if c not in valid_country_configs][:MAX_TEST_PER_COUNTRY]

        for i, link in enumerate(to_test, 1):
            short = link[:65] + ("..." if len(link) > 65 else "")
            ok, delay = test_single_config(xray_bin, link)
            if ok:
                valid_country_configs[link] = delay
                save_config(link, country, delay, fail_count=0)
                print(f"   [{i}/{len(to_test)}] ✅ {short} → {delay:.0f}ms")
            else:
                print(f"   [{i}/{len(to_test)}] ❌ {short}")

        # مرتب‌سازی بر اساس کمترین پینگ
        sorted_links = [l for l, _ in sorted(valid_country_configs.items(), key=lambda x: x[1])]

        if sorted_links:
            country_file = os.path.join(OUTPUT_DIR, f"{country}.txt")
            encoded_content = base64.b64encode("\n".join(sorted_links).encode("utf-8")).decode("utf-8")
            with open(country_file, "w", encoding="utf-8") as f:
                f.write(encoded_content)
            all_valid_configs.extend(sorted_links)
            print(f"   💾 {len(sorted_links)} کانفیگ فعال در {country_file} ذخیره شد.\n")
        else:
            print(f"   ⚠️ کانفیگ فعالی برای {country.upper()} یافت نشد.\n")

    # ذخیره فایل تجمیعی همه کشورها
    unique_all = list(dict.fromkeys(all_valid_configs))
    if unique_all:
        all_file = os.path.join(OUTPUT_DIR, "all.txt")
        all_encoded = base64.b64encode("\n".join(unique_all).encode("utf-8")).decode("utf-8")
        with open(all_file, "w", encoding="utf-8") as f:
            f.write(all_encoded)
        print(f"📦 فایل تجمیعی با {len(unique_all)} کانفیگ در {all_file} ذخیره شد.")

    shutil.rmtree(os.path.dirname(xray_bin), ignore_errors=True)
    print("\n🏁 فرآیند با موفقیت پایان یافت.")

if __name__ == "__main__":
    main()
