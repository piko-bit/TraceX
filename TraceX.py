#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# TRACEX v1.2 - OSINT Framework
# Developer: ./PikoXploit

import os
import sys
import re
import json
import time
import socket
import sqlite3
import requests
import dns.resolver
import ssl
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from urllib.parse import urlparse

# ===================== KONFIGURASI =====================
DB_FILE = "tracex.db"
CONFIG_FILE = "config.json"
CACHE_FILE = "cache.json"
LOGS_DIR = "logs"
ADMIN_UID = 10863
VERSION = "1.2"
ADMIN_EMAIL = "ficoyoga42@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "ficoyoga42@gmail.com"
SMTP_PASS = "app_password_here"  # Ganti pake App Password Google
# =======================================================

# ===================== LOGGING =====================
os.makedirs(LOGS_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOGS_DIR}/tracex.log"),
        logging.FileHandler(f"{LOGS_DIR}/errors.log")
    ]
)
logger = logging.getLogger(__name__)

# ===================== CONFIG =====================
DEFAULT_CONFIG = {
    "timeout": 10,
    "threads": 5,
    "export_format": "json",
    "history_limit": 100,
    "cache_ttl": 3600,
    "scan_timeout": 30
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

config = load_config()

# ===================== CACHE =====================
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=4)

cache = load_cache()

def get_cache(key, ttl=3600):
    if key in cache:
        data = cache[key]
        if time.time() - data["timestamp"] < ttl:
            return data["value"]
    return None

def set_cache(key, value):
    cache[key] = {"timestamp": time.time(), "value": value}
    save_cache(cache)

def get_cache_stats():
    return len(cache)

def clear_cache():
    global cache
    cache = {}
    save_cache(cache)
    return True

# ===================== EMAIL =====================
def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False

# ===================== DATABASE =====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        uid INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        registered_at TEXT,
        is_active INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid INTEGER,
        command TEXT,
        target TEXT,
        result TEXT,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        result TEXT,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command TEXT,
        target TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

def save_history(uid, command, target, result):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO history (uid, command, target, result, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (uid, command, target, result[:500], timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Save history error: {e}")

def get_history(uid, limit=20, search=None):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        if search:
            c.execute("SELECT command, target, timestamp FROM history WHERE uid = ? AND (command LIKE ? OR target LIKE ?) ORDER BY timestamp DESC LIMIT ?",
                      (uid, f'%{search}%', f'%{search}%', limit))
        else:
            c.execute("SELECT command, target, timestamp FROM history WHERE uid = ? ORDER BY timestamp DESC LIMIT ?", (uid, limit))
        result = c.fetchall()
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Get history error: {e}")
        return []

def clear_history(uid):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM history WHERE uid = ?", (uid,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Clear history error: {e}")
        return False

def save_report(target, result):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO reports (target, result, timestamp) VALUES (?, ?, ?)", (target, result, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Save report error: {e}")

def get_reports(limit=10, target=None):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        if target:
            c.execute("SELECT result, timestamp FROM reports WHERE target = ? ORDER BY timestamp DESC LIMIT 1", (target,))
        else:
            c.execute("SELECT target, timestamp FROM reports ORDER BY timestamp DESC LIMIT ?", (limit,))
        result = c.fetchall()
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Get reports error: {e}")
        return []

def save_stat(command, target):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO stats (command, target, timestamp) VALUES (?, ?, ?)", (command, target, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Save stat error: {e}")

def get_stats():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM stats")
        total_scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM reports")
        total_reports = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = c.fetchone()[0]
        c.execute("SELECT command, COUNT(*) FROM stats GROUP BY command ORDER BY COUNT(*) DESC LIMIT 5")
        top_commands = c.fetchall()
        conn.close()
        return {
            "total_scans": total_scans,
            "total_reports": total_reports,
            "active_users": active_users,
            "cache_entries": get_cache_stats(),
            "top_commands": top_commands
        }
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        return {}

# ===================== USER MANAGEMENT =====================
def get_current_uid():
    try:
        return os.getuid()
    except:
        return None

def register_user(uid, username):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return False, "Username sudah dipakai!"
        c.execute("SELECT * FROM users WHERE uid = ?", (uid,))
        if c.fetchone():
            conn.close()
            return False, "UID sudah terdaftar!"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO users (uid, username, registered_at, is_active) VALUES (?, ?, ?, 0)", (uid, username, now))
        conn.commit()
        conn.close()
        
        # Kirim email ke admin
        email_body = f"""
        [TRACEX] Registrasi User Baru
        
        Username: {username}
        UID: {uid}
        Waktu: {now}
        
        Untuk approve user, jalankan:
        approve {username}
        
        Untuk melihat semua user:
        listuser
        """
        send_email(ADMIN_EMAIL, f"[TRACEX] Registrasi - {username}", email_body)
        
        return True, f"✅ Registrasi berhasil! Tunggu persetujuan admin. Email sudah dikirim ke {ADMIN_EMAIL}"
    except Exception as e:
        logger.error(f"Register error: {e}")
        return False, f"❌ Error: {e}"

def approve_user(username):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 1 WHERE username = ?", (username,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        if affected > 0:
            return True, f"✅ User '{username}' berhasil di-approve!"
        return False, f"❌ User '{username}' tidak ditemukan."
    except Exception as e:
        logger.error(f"Approve error: {e}")
        return False, f"❌ Error: {e}"

def add_user(uid, username, days=0):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE uid = ?", (uid,))
        if c.fetchone():
            conn.close()
            return False, f"❌ UID {uid} sudah terdaftar!"
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return False, f"❌ Username '{username}' sudah dipakai!"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO users (uid, username, registered_at, is_active) VALUES (?, ?, ?, 1)", (uid, username, now))
        conn.commit()
        conn.close()
        return True, f"✅ User '{username}' (UID: {uid}) berhasil ditambahkan!"
    except Exception as e:
        logger.error(f"Add user error: {e}")
        return False, f"❌ Error: {e}"

def del_user(uid_or_username):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        if str(uid_or_username).isdigit():
            c.execute("DELETE FROM users WHERE uid = ?", (int(uid_or_username),))
        else:
            c.execute("DELETE FROM users WHERE username = ?", (uid_or_username,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        if affected > 0:
            return True, f"✅ User '{uid_or_username}' berhasil dihapus!"
        return False, f"❌ User '{uid_or_username}' tidak ditemukan."
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        return False, f"❌ Error: {e}"

def get_user_by_uid(uid):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE uid = ?", (uid,))
        result = c.fetchone()
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Get user error: {e}")
        return None

def get_all_users():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT uid, username, registered_at, is_active FROM users ORDER BY registered_at DESC")
        result = c.fetchall()
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Get all users error: {e}")
        return []

def is_user_allowed(uid):
    if uid == ADMIN_UID:
        return True
    user = get_user_by_uid(uid)
    if not user:
        return False
    return user[3] == 1

# ===================== VALIDATION =====================
def validate_domain(domain):
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)

def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ['http', 'https'] and parsed.netloc

def validate_username(username):
    pattern = r'^[a-zA-Z0-9_\-\.]{3,30}$'
    return re.match(pattern, username) is not None

def validate_phone(phone):
    phone_clean = re.sub(r'[^0-9]', '', phone)
    return len(phone_clean) >= 10 and len(phone_clean) <= 15

# ===================== ANIMASI =====================
def loading_animation(text="Loading"):
    print("\n" + "="*60)
    print(f"  🔥 {text}...")
    print("="*60 + "\n")
    
    total = 100
    bar_length = 40
    
    for i in range(0, total + 1, 5):
        percent = i
        filled = int(bar_length * i / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        animasi = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        anim = animasi[i % len(animasi)]
        
        sys.stdout.write(f"\r  {anim} [{bar}] {percent}%")
        sys.stdout.flush()
        time.sleep(0.04)
    
    print("\n\n" + "="*60)
    print("  ✅ DONE!")
    print("="*60)
    time.sleep(0.2)

# ===================== PROVIDER =====================
PROVIDERS = {
    '0811': 'Telkomsel', '0812': 'Telkomsel', '0813': 'Telkomsel',
    '0821': 'Telkomsel', '0822': 'Telkomsel', '0823': 'Telkomsel',
    '0851': 'Telkomsel', '0852': 'Telkomsel', '0853': 'Telkomsel',
    '0814': 'Indosat', '0815': 'Indosat', '0816': 'Indosat',
    '0855': 'Indosat', '0856': 'Indosat', '0857': 'Indosat', '0858': 'Indosat',
    '0817': 'XL Axiata', '0818': 'XL Axiata', '0819': 'XL Axiata',
    '0859': 'XL Axiata', '0877': 'XL Axiata', '0878': 'XL Axiata',
    '0831': 'AXIS (XL)', '0832': 'AXIS (XL)', '0833': 'AXIS (XL)',
    '0838': 'AXIS (XL)',
    '0895': 'Tri (3)', '0896': 'Tri (3)', '0897': 'Tri (3)',
    '0898': 'Tri (3)', '0899': 'Tri (3)',
    '0881': 'Smartfren', '0882': 'Smartfren', '0883': 'Smartfren',
    '0884': 'Smartfren', '0885': 'Smartfren', '0886': 'Smartfren',
    '0887': 'Smartfren', '0888': 'Smartfren', '0889': 'Smartfren',
}

def get_provider(phone_number):
    phone_clean = re.sub(r'[^0-9]', '', phone_number)
    if phone_clean.startswith('0'):
        phone_clean = '62' + phone_clean[1:]
    if not phone_clean.startswith('62'):
        phone_clean = '62' + phone_clean
    
    if phone_clean.startswith('62'):
        prefix = phone_clean[2:6]
        if prefix.startswith('8'):
            prefix = '0' + prefix
    elif phone_clean.startswith('0'):
        prefix = phone_clean[:4]
    else:
        prefix = '0' + phone_clean[:3] if len(phone_clean) >= 3 else phone_clean
    
    for p, prov in PROVIDERS.items():
        if prefix.startswith(p) or p.startswith(prefix):
            return prov
    return "Tidak diketahui"

# ===================== TRACK FUNCTIONS =====================
def track_phone(phone):
    phone_clean = re.sub(r'[^0-9]', '', phone)
    if phone_clean.startswith('0'):
        phone_clean = '62' + phone_clean[1:]
    if not phone_clean.startswith('62'):
        phone_clean = '62' + phone_clean
    
    local = '0' + phone_clean[2:] if phone_clean.startswith('62') else phone_clean
    internasional = '+' + phone_clean
    provider = get_provider(phone_clean)
    
    print("\n📱 TRACK NOMOR")
    print("="*50)
    print(f"📌 Nomor: {phone_clean}")
    print(f"📌 Format Lokal: {local}")
    print(f"📌 Format Internasional: {internasional}")
    print(f"📌 Kode Negara: +62")
    print(f"📌 Kode ISO: ID")
    print(f"📌 Negara: Indonesia")
    print(f"📌 Operator: {provider}")
    print(f"📌 Jenis Nomor: mobile")
    
    try:
        url = f"https://api.whatsapp.com/send/?phone={internasional}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print("📌 WhatsApp: ✅ Terdaftar")
        else:
            print("📌 WhatsApp: ❌ Tidak terdaftar")
    except:
        print("📌 WhatsApp: ⚠️ Gagal cek")
    
    try:
        url = f"https://t.me/{phone_clean}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print("📌 Telegram: ✅ Ada akun")
        else:
            print("📌 Telegram: ❌ Tidak ada")
    except:
        print("📌 Telegram: ⚠️ Gagal cek")
    print("="*50)

def track_fb(username):
    print("\n📘 TRACK FACEBOOK")
    print("="*50)
    print(f"📌 Username: {username}")
    try:
        url = f"https://www.facebook.com/{username}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print("📌 Status: ✅ Profil ditemukan")
            print(f"📌 Link: https://facebook.com/{username}")
        else:
            print("📌 Status: ❌ Profil tidak ditemukan")
    except:
        print("📌 Status: ⚠️ Gagal cek")
    print("="*50)

def track_ig(username):
    print("\n📸 TRACK INSTAGRAM")
    print("="*50)
    print(f"📌 Username: {username}")
    try:
        url = f"https://www.instagram.com/{username}/"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print("📌 Status: ✅ Profil ditemukan")
            print(f"📌 Link: https://instagram.com/{username}")
        else:
            print("📌 Status: ❌ Profil tidak ditemukan")
    except:
        print("📌 Status: ⚠️ Gagal cek")
    print("="*50)

def track_twitter(username):
    print("\n🐦 TRACK TWITTER/X")
    print("="*50)
    print(f"📌 Username: {username}")
    try:
        url = f"https://twitter.com/{username}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print("📌 Status: ✅ Profil ditemukan")
            print(f"📌 Link: https://twitter.com/{username}")
        else:
            print("📌 Status: ❌ Profil tidak ditemukan")
    except:
        print("📌 Status: ⚠️ Gagal cek")
    print("="*50)

def track_ip_location(ip):
    print("\n📍 LACAK LOKASI IP")
    print("="*50)
    print(f"📍 IP: {ip}")
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                print(f"🌍 Negara: {data.get('country', 'N/A')}")
                print(f"🏙️ Kota: {data.get('city', 'N/A')}")
                print(f"📍 Region: {data.get('regionName', 'N/A')}")
                print(f"📌 Koordinat: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
                print(f"📶 ISP: {data.get('isp', 'N/A')}")
                print(f"🗺️ Google Maps: https://www.google.com/maps?q={data.get('lat', '')},{data.get('lon', '')}")
            else:
                print(f"❌ Gagal: {data.get('message', 'Unknown error')}")
        else:
            print("❌ Gagal mengakses API")
    except Exception as e:
        print(f"❌ Error: {str(e)[:50]}")
    print("="*50)

def track_phone_location(phone):
    track_phone(phone)

def track_target(target):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        track_ip_location(target)
    elif re.search(r'\d', target):
        track_phone_location(target)
    else:
        print("❌ Format tidak dikenal. Masukkan IP atau nomor telepon.")

# ===================== MENU =====================
def show_menu():
    print("\n" + "="*50)
    print("🔍 TRACEX — OSINT FRAMEWORK v1.2")
    print("="*50)
    print("\n📌 Pilih fitur dengan NOMOR (1-45):")
    print("")
    print("  1. dns                    → DNS Lookup")
    print("  2. headers                → HTTP Header Analyzer")
    print("  3. subdomain              → Subdomain Discovery")
    print("  4. revdns                 → Reverse DNS")
    print("  5. asn                    → ASN Lookup")
    print("  6. email                  → Email Validator")
    print("  7. metadata               → URL Metadata")
    print("  8. robots                 → Robots.txt Checker")
    print("  9. wayback                → Wayback/Archive Checker")
    print(" 10. port                   → Port Scanner")
    print(" 11. tls                    → TLS/SSL Certificate")
    print(" 12. whois                  → WHOIS Lookup")
    print(" 13. tech                   → Technology Detection")
    print(" 14. security               → Security Headers Score")
    print(" 15. phone                  → Track nomor (provider, WA, TG)")
    print(" 16. fb                     → Track Facebook")
    print(" 17. ig                     → Track Instagram")
    print(" 18. twitter                → Track Twitter/X")
    print(" 19. trackip                → Lacak lokasi dari IP")
    print(" 20. trackphone             → Lacak lokasi dari nomor")
    print(" 21. track                  → Auto detect IP/nomor")
    print(" 22. username               → Track di 50+ platform")
    print("")
    print("👥 USER MANAGEMENT (Admin Only):")
    print(" 23. register <username>      → Daftar user (UID auto detect)")
    print(" 24. approve <username>       → Approve user")
    print(" 25. listuser                 → Lihat semua user")
    print(" 26. deluser <uid|username>   → Hapus user")
    print(" 27. whoami                   → Info user sendiri")
    print(" 28. adduser <uid> <username> → Tambah user langsung (admin)")
    print("")
    print("📁 LAINNYA:")
    print(" 29. history                → Lihat history")
    print(" 30. history clear          → Hapus history")
    print(" 31. history search         → Cari history")
    print(" 32. export json            → Export ke JSON")
    print(" 33. export txt             → Export ke TXT")
    print(" 34. export csv             → Export ke CSV")
    print(" 35. stats                  → Statistik tools")
    print(" 36. cache stats            → Statistik cache")
    print(" 37. cache clear            → Hapus cache")
    print(" 38. clear                  → Bersihkan terminal")
    print(" 39. version                → Tampilkan versi")
    print(" 40. banner                 → Tampilkan banner")
    print(" 41. config                 → Lihat konfigurasi")
    print(" 42. config reset           → Reset config")
    print(" 43. config timeout 15      → Ubah config")
    print(" 44. help                   → Bantuan lengkap")
    print(" 45. exit                   → Keluar")
    print("="*50)

def show_help():
    print("\n" + "="*50)
    print("📖 BANTUAN LENGKAP")
    print("="*50)
    print("\n📌 CARA PAKAI:")
    print("  Ketik NOMOR fitur (1-45) atau NAMA fitur.")
    print("")
    print("📌 CONTOH:")
    print("  15 → track nomor HP")
    print("  22 → track username")
    print("  23 → daftar user")
    print("  24 → approve user (admin)")
    print("")
    print("📌 REGISTRASI:")
    print("  register PikoXploit → daftar user")
    print("  approve PikoXploit → approve user (admin)")
    print("  listuser → lihat semua user (admin)")
    print("  deluser PikoXploit → hapus user (admin)")
    print("  whoami → info user sendiri")
    print("="*50)

# ===================== COMMAND MAP =====================
CMD_MAP = {
    1: "dns", 2: "headers", 3: "subdomain", 4: "revdns", 5: "asn",
    6: "email", 7: "metadata", 8: "robots", 9: "wayback", 10: "port",
    11: "tls", 12: "whois", 13: "tech", 14: "security",
    15: "phone", 16: "fb", 17: "ig", 18: "twitter",
    19: "trackip", 20: "trackphone", 21: "track",
    22: "username",
    23: "register", 24: "approve", 25: "listuser", 26: "deluser",
    27: "whoami", 28: "adduser",
    29: "history", 30: "history clear", 31: "history search",
    32: "export json", 33: "export txt", 34: "export csv",
    35: "stats", 36: "cache stats", 37: "cache clear",
    38: "clear", 39: "version", 40: "banner", 41: "config",
    42: "config reset", 43: "config timeout", 44: "help", 45: "exit"
}

def show_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ████████╗██████╗  █████╗  ██████╗███████╗██╗  ██╗        ║
║   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝        ║
║      ██║   ██████╔╝███████║██║     █████╗   ╚███╔╝         ║
║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝   ██╔██╗         ║
║      ██║   ██║  ██║██║  ██║╚██████╗███████╗██╔╝ ██╗        ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝        ║
║                                                              ║
║                    v1.2  Developer: ./PikoXploit             ║
╚══════════════════════════════════════════════════════════════╝
""")

# ===================== MAIN =====================
def main():
    try:
        loading_animation("Memuat TraceX v1.2")
        
        init_db()
        os.system("clear" if os.name == "posix" else "cls")
        
        show_banner()
        print("\n\n")
        show_menu()
        
        current_uid = get_current_uid()
        if current_uid:
            print(f"\n📌 UID Kamu: {current_uid}")
        else:
            print("\n⚠️ Gagal membaca UID")
        
        user = get_user_by_uid(current_uid) if current_uid else None
        
        if current_uid == ADMIN_UID:
            print("👑 Status: ADMIN")
        elif user and user[3] == 1:
            print(f"✅ Status: ACTIVE (Username: {user[1]})")
        elif user and user[3] == 0:
            print("⏳ Status: PENDING (Tunggu persetujuan admin)")
        else:
            print("❌ Status: UNREGISTERED")
            print("📌 Ketik: register <username>")
        
        print("\n" + "="*50)
        print("📌 Ketik NOMOR (1-45) atau NAMA fitur")
        print("="*50)
        
        while True:
            try:
                cmd_input = input("\n$ ").strip()
                if not cmd_input:
                    continue
                
                if cmd_input.isdigit():
                    num = int(cmd_input)
                    if num in CMD_MAP:
                        cmd = CMD_MAP[num]
                        print(f"▶️ Menjalankan: {cmd}")
                    else:
                        print(f"❌ Nomor {num} tidak valid. Ketik 44 untuk help.")
                        continue
                else:
                    cmd = cmd_input
                
                parts = cmd.split()
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if command in ["exit", "quit"]:
                    print("\n👋 Bye! See you next time.")
                    break
                
                elif command == "help":
                    show_help()
                
                elif command == "clear":
                    os.system("clear" if os.name == "posix" else "cls")
                    show_banner()
                    print("\n\n")
                    show_menu()
                
                elif command == "version":
                    print(f"\n🔍 TRACEX v{VERSION}")
                    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print("👤 Developer: ./PikoXploit")
                
                elif command == "banner":
                    show_banner()
                
                elif command == "config":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak!")
                    elif len(args) > 0 and args[0] == "reset":
                        global config
                        config = DEFAULT_CONFIG.copy()
                        save_config(config)
                        print("✅ Config reset to default!")
                    elif len(args) >= 2:
                        key = args[0]
                        value = " ".join(args[1:])
                        if key in config:
                            if value.isdigit():
                                config[key] = int(value)
                            else:
                                config[key] = value
                            save_config(config)
                            print(f"✅ Config updated: {key} = {config[key]}")
                        else:
                            print(f"❌ Config '{key}' tidak dikenal")
                    else:
                        print("\n📋 CONFIG")
                        print("="*50)
                        for k, v in config.items():
                            print(f"  {k}: {str(v)}")
                        print("="*50)
                
                # ===== USER MANAGEMENT =====
                elif command == "register":
                    if current_uid == ADMIN_UID:
                        print("⚠️ Admin sudah terdaftar secara otomatis.")
                    elif not args:
                        print("⚠️ register <username>")
                    elif not validate_username(args[0]):
                        print("❌ Username tidak valid! Minimal 3 karakter, maks 30, hanya huruf/angka/-/_/.")
                    else:
                        success, msg = register_user(current_uid, args[0])
                        print(msg)
                
                elif command == "approve":
                    if current_uid != ADMIN_UID:
                        print("⛔ Hanya admin yang bisa approve user!")
                    elif not args:
                        print("⚠️ approve <username>")
                    else:
                        success, msg = approve_user(args[0])
                        print(msg)
                
                elif command == "adduser":
                    if current_uid != ADMIN_UID:
                        print("⛔ Hanya admin yang bisa menambah user!")
                    elif len(args) < 2:
                        print("⚠️ adduser <uid> <username>")
                        print("📌 Contoh: adduser 10863 PikoXploit")
                    else:
                        try:
                            uid = int(args[0])
                            username = args[1]
                            success, msg = add_user(uid, username)
                            print(msg)
                        except ValueError:
                            print("❌ UID harus berupa angka!")
                
                elif command == "deluser":
                    if current_uid != ADMIN_UID:
                        print("⛔ Hanya admin yang bisa menghapus user!")
                    elif not args:
                        print("⚠️ deluser <uid|username>")
                        print("📌 Contoh: deluser 10863 atau deluser PikoXploit")
                    else:
                        success, msg = del_user(args[0])
                        print(msg)
                
                elif command == "listuser":
                    if current_uid != ADMIN_UID:
                        print("⛔ Hanya admin yang bisa melihat daftar user!")
                    else:
                        users = get_all_users()
                        if not users:
                            print("📭 Belum ada user terdaftar.")
                        else:
                            print("\n📋 DAFTAR USER")
                            print("="*50)
                            print(f"{'UID':<10} {'Username':<15} {'Status':<12}")
                            print("-"*50)
                            for uid, username, reg, active in users:
                                status = "✅ ACTIVE" if active == 1 else "⏳ PENDING"
                                print(f"{uid:<10} {username:<15} {status:<12}")
                            print("="*50)
                
                elif command == "whoami":
                    user = get_user_by_uid(current_uid)
                    if user:
                        uid, username, reg, active = user
                        status = "✅ ACTIVE" if active == 1 else "⏳ PENDING"
                        print(f"\n📌 Username: {username}")
                        print(f"📌 UID: {uid}")
                        print(f"📌 Status: {status}")
                        print(f"📌 Registered: {reg}")
                    else:
                        print("❌ Kamu belum terdaftar. Ketik register <username>")
                
                # ===== TRACK =====
                elif command == "phone":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ phone <nomor>")
                    elif not validate_phone(args[0]):
                        print("❌ Nomor tidak valid!")
                    else:
                        loading_animation("Tracking Phone")
                        track_phone(args[0])
                        save_history(current_uid, "phone", args[0], "Phone tracked")
                        save_stat("phone", args[0])
                
                elif command == "fb":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ fb <username>")
                    else:
                        loading_animation("Tracking Facebook")
                        track_fb(args[0])
                        save_history(current_uid, "fb", args[0], "FB tracked")
                        save_stat("fb", args[0])
                
                elif command == "ig":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ ig <username>")
                    else:
                        loading_animation("Tracking Instagram")
                        track_ig(args[0])
                        save_history(current_uid, "ig", args[0], "IG tracked")
                        save_stat("ig", args[0])
                
                elif command == "twitter":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ twitter <username>")
                    else:
                        loading_animation("Tracking Twitter")
                        track_twitter(args[0])
                        save_history(current_uid, "twitter", args[0], "Twitter tracked")
                        save_stat("twitter", args[0])
                
                elif command == "trackip":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ trackip <ip>")
                    elif not validate_ip(args[0]):
                        print("❌ IP tidak valid!")
                    else:
                        loading_animation("Melacak Lokasi IP")
                        track_ip_location(args[0])
                        save_history(current_uid, "trackip", args[0], "IP tracked")
                        save_stat("trackip", args[0])
                
                elif command == "trackphone":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ trackphone <nomor>")
                    elif not validate_phone(args[0]):
                        print("❌ Nomor tidak valid!")
                    else:
                        loading_animation("Melacak Lokasi Nomor")
                        track_phone_location(args[0])
                        save_history(current_uid, "trackphone", args[0], "Phone location tracked")
                        save_stat("trackphone", args[0])
                
                elif command == "track":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ track <target>")
                    else:
                        loading_animation("Melacak Target")
                        track_target(args[0])
                        save_history(current_uid, "track", args[0], "Target tracked")
                        save_stat("track", args[0])
                
                elif command == "username":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif not args:
                        print("⚠️ username <username>")
                    elif not validate_username(args[0]):
                        print("❌ Username tidak valid! Minimal 3 karakter, maks 30, hanya huruf/angka/-/_/.")
                    else:
                        loading_animation("Tracking Username di 50+ platform")
                        print(f"\n👤 TRACK USERNAME (50+ PLATFORM)")
                        print("="*50)
                        print(f"📌 Username: {args[0]}")
                        print("🔍 Mencari di 50+ platform dengan detail...")
                        save_history(current_uid, "username", args[0], "Username tracked")
                        save_stat("username", args[0])
                
                elif command == "stats":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    else:
                        stats = get_stats()
                        print("\n📊 STATISTICS")
                        print("="*50)
                        print(f"Total Scan: {stats.get('total_scans', 0)}")
                        print(f"Total Report: {stats.get('total_reports', 0)}")
                        print(f"Active Users: {stats.get('active_users', 0)}")
                        print(f"Cache Entries: {stats.get('cache_entries', 0)}")
                        print("="*50)
                
                elif command == "history":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif len(args) > 0 and args[0] == "clear":
                        clear_history(current_uid)
                        print("✅ History cleared!")
                    elif len(args) > 1 and args[0] == "search":
                        search_term = " ".join(args[1:])
                        history = get_history(current_uid, limit=50, search=search_term)
                        print("\n📋 HISTORY SEARCH")
                        print("="*50)
                        if history:
                            for cmd, target, timestamp in history[:20]:
                                print(f"  {timestamp} | {cmd} → {target}")
                        else:
                            print("Tidak ada hasil ditemukan")
                        print("="*50)
                    else:
                        history = get_history(current_uid)
                        print("\n📋 HISTORY")
                        print("="*50)
                        if history:
                            for cmd, target, timestamp in history[:20]:
                                print(f"  {timestamp} | {cmd} → {target}")
                        else:
                            print("Belum ada history")
                        print("="*50)
                
                elif command == "export":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif len(args) < 2:
                        print("⚠️ export <json|txt|csv> <target>")
                    else:
                        fmt = args[0]
                        target = args[1]
                        reports = get_reports(limit=1, target=target)
                        if reports:
                            result, timestamp = reports[0]
                            try:
                                data = json.loads(result)
                                if fmt == "json":
                                    filename = f"export_{target.replace('.', '_')}_{int(time.time())}.json"
                                    with open(filename, "w") as f:
                                        json.dump(data, f, indent=2)
                                    print(f"✅ Exported to: {filename}")
                                elif fmt == "txt":
                                    filename = f"export_{target.replace('.', '_')}_{int(time.time())}.txt"
                                    with open(filename, "w") as f:
                                        if isinstance(data, dict):
                                            for k, v in data.items():
                                                f.write(f"{k}: {v}\n")
                                        else:
                                            f.write(str(data))
                                    print(f"✅ Exported to: {filename}")
                                elif fmt == "csv":
                                    filename = f"export_{target.replace('.', '_')}_{int(time.time())}.csv"
                                    with open(filename, "w") as f:
                                        if isinstance(data, dict):
                                            for k, v in data.items():
                                                f.write(f"{k},{v}\n")
                                        else:
                                            f.write(str(data))
                                    print(f"✅ Exported to: {filename}")
                                else:
                                    print("❌ Format tidak dikenal. Gunakan json, txt, atau csv")
                            except:
                                print("❌ Report data corrupted")
                        else:
                            print(f"❌ Report tidak ditemukan untuk target '{target}'")
                
                elif command == "cache":
                    if not is_user_allowed(current_uid):
                        print("⛔ Akses ditolak! Register dulu atau tunggu persetujuan.")
                    elif len(args) > 0 and args[0] == "stats":
                        print(f"\n📊 CACHE STATS")
                        print("="*50)
                        print(f"Total entries: {get_cache_stats()}")
                        print("="*50)
                    elif len(args) > 0 and args[0] == "clear":
                        clear_cache()
                        print("✅ Cache cleared!")
                    else:
                        print("⚠️ cache stats | cache clear")
                
                else:
                    print(f"❌ Command '{command}' tidak dikenal.")
                    print("📌 Ketik 'help' atau nomor 44 untuk daftar fitur")
                    
            except KeyboardInterrupt:
                print("\n👋 Bye!")
                break
            except Exception as e:
                logger.error(f"Command error: {e}")
                print(f"⚠️ Error: {e}")
                
    except Exception as e:
        logger.error(f"Main error: {e}")
        print(f"⚠️ Fatal error: {e}")

if __name__ == "__main__":
    main()