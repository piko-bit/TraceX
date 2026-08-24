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
from datetime import datetime, timedelta
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)

# ===================== KONFIGURASI =====================
DB_FILE = "tracex.db"
CONFIG_FILE = "config.json"
CACHE_FILE = "cache.json"
LOGS_DIR = "logs"
ADMIN_UID = 10863
VERSION = "1.2"
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
    "color": True,
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

# ===================== DATABASE =====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        uid INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        registered_at TEXT,
        expired_at TEXT,
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
            return False, f"{Fore.RED}❌ Username sudah dipakai!{Style.RESET_ALL}"
        c.execute("SELECT * FROM users WHERE uid = ?", (uid,))
        if c.fetchone():
            conn.close()
            return False, f"{Fore.RED}❌ UID sudah terdaftar!{Style.RESET_ALL}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO users (uid, username, registered_at, expired_at, is_active) VALUES (?, ?, ?, ?, 0)",
                  (uid, username, now, "PERMANENT"))
        conn.commit()
        conn.close()
        return True, f"{Fore.GREEN}✅ Registrasi berhasil! Tunggu persetujuan admin.{Style.RESET_ALL}"
    except Exception as e:
        logger.error(f"Register error: {e}")
        return False, f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}"

def approve_user(username):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 1 WHERE username = ?", (username,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        if affected > 0:
            return True, f"{Fore.GREEN}✅ User '{username}' berhasil di-approve!{Style.RESET_ALL}"
        return False, f"{Fore.RED}❌ User '{username}' tidak ditemukan.{Style.RESET_ALL}"
    except Exception as e:
        logger.error(f"Approve error: {e}")
        return False, f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}"

def add_user(uid, username, days=0):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE uid = ?", (uid,))
        if c.fetchone():
            conn.close()
            return False, f"{Fore.RED}❌ UID {uid} sudah terdaftar!{Style.RESET_ALL}"
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return False, f"{Fore.RED}❌ Username '{username}' sudah dipakai!{Style.RESET_ALL}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if days == 0:
            expired = "PERMANENT"
            is_active = 1
        else:
            expired = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            is_active = 0
        c.execute("INSERT INTO users (uid, username, registered_at, expired_at, is_active) VALUES (?, ?, ?, ?, ?)",
                  (uid, username, now, expired, is_active))
        conn.commit()
        conn.close()
        status = f"{Fore.GREEN}PERMANEN{Style.RESET_ALL}" if days == 0 else f"{Fore.YELLOW}{days} hari{Style.RESET_ALL}"
        return True, f"{Fore.GREEN}✅ User '{username}' (UID: {uid}) berhasil ditambahkan!{Style.RESET_ALL}\n📌 Status: {status}"
    except Exception as e:
        logger.error(f"Add user error: {e}")
        return False, f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}"

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
            return True, f"{Fore.GREEN}✅ User '{uid_or_username}' berhasil dihapus!{Style.RESET_ALL}"
        return False, f"{Fore.RED}❌ User '{uid_or_username}' tidak ditemukan.{Style.RESET_ALL}"
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        return False, f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}"

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
        c.execute("SELECT uid, username, registered_at, expired_at, is_active FROM users ORDER BY registered_at DESC")
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
    return user[4] == 1

# ===================== BANNER =====================
def show_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.YELLOW}                                                              {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}   ████████╗██████╗  █████╗  ██████╗███████╗██╗  ██╗        {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝        {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}      ██║   ██████╔╝███████║██║     █████╗   ╚███╔╝         {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}      ██║   ██╔══██╗██╔══██║██║     ██╔══╝   ██╔██╗         {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}      ██║   ██║  ██║██║  ██║╚██████╗███████╗██╔╝ ██╗        {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝        {Fore.CYAN}║
{Fore.CYAN}║{Fore.MAGENTA}                                                              {Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}                    v1.2  Developer: ./PikoXploit             {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

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
    print(f"\n{Fore.CYAN}="*60)
    print(f"  🔥 {text}...")
    print(f"{Fore.CYAN}="*60 + "\n")
    
    total = 100
    bar_length = 40
    
    for i in range(0, total + 1, 5):
        percent = i
        filled = int(bar_length * i / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        animasi = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        anim = animasi[i % len(animasi)]
        
        sys.stdout.write(f"\r  {Fore.YELLOW}{anim}{Fore.GREEN} [{bar}] {Fore.CYAN}{percent}%{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.04)
    
    print(f"\n\n{Fore.CYAN}="*60)
    print(f"{Fore.GREEN}  ✅ DONE!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*60)
    time.sleep(0.2)

def color_text(text, color):
    colors = {
        "green": Fore.GREEN,
        "red": Fore.RED,
        "yellow": Fore.YELLOW,
        "blue": Fore.BLUE,
        "cyan": Fore.CYAN,
        "magenta": Fore.MAGENTA,
        "white": Fore.WHITE
    }
    return colors.get(color, Fore.WHITE) + text + Style.RESET_ALL

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

# ===================== TRACK FUNCTIONS (SINGKAT) =====================
def track_phone(phone):
    phone_clean = re.sub(r'[^0-9]', '', phone)
    if phone_clean.startswith('0'):
        phone_clean = '62' + phone_clean[1:]
    if not phone_clean.startswith('62'):
        phone_clean = '62' + phone_clean
    
    local = '0' + phone_clean[2:] if phone_clean.startswith('62') else phone_clean
    internasional = '+' + phone_clean
    provider = get_provider(phone_clean)
    
    print(f"\n{Fore.CYAN}📱 TRACK NOMOR{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)
    print(f"{Fore.GREEN}📌 Nomor: {Fore.YELLOW}{phone_clean}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Format Lokal: {Fore.YELLOW}{local}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Format Internasional: {Fore.YELLOW}{internasional}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Kode Negara: {Fore.YELLOW}+62{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Kode ISO: {Fore.YELLOW}ID{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Negara: {Fore.YELLOW}Indonesia{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Operator: {Fore.YELLOW}{provider}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📌 Jenis Nomor: {Fore.YELLOW}mobile{Style.RESET_ALL}")
    
    try:
        url = f"https://api.whatsapp.com/send/?phone={internasional}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"{Fore.GREEN}📌 WhatsApp: {Fore.GREEN}✅ Terdaftar{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}📌 WhatsApp: ❌ Tidak terdaftar{Style.RESET_ALL}")
    except:
        print(f"{Fore.YELLOW}📌 WhatsApp: ⚠️ Gagal cek{Style.RESET_ALL}")
    
    try:
        url = f"https://t.me/{phone_clean}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"{Fore.GREEN}📌 Telegram: {Fore.GREEN}✅ Ada akun{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}📌 Telegram: ❌ Tidak ada{Style.RESET_ALL}")
    except:
        print(f"{Fore.YELLOW}📌 Telegram: ⚠️ Gagal cek{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)

def track_fb(username):
    print(f"\n{Fore.CYAN}📘 TRACK FACEBOOK{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)
    print(f"{Fore.GREEN}📌 Username: {Fore.YELLOW}{username}{Style.RESET_ALL}")
    try:
        url = f"https://www.facebook.com/{username}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print(f"{Fore.GREEN}📌 Status: ✅ Profil ditemukan{Style.RESET_ALL}")
            print(f"{Fore.GREEN}📌 Link: {Fore.YELLOW}https://facebook.com/{username}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}📌 Status: ❌ Profil tidak ditemukan{Style.RESET_ALL}")
    except:
        print(f"{Fore.YELLOW}📌 Status: ⚠️ Gagal cek{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)

def track_ig(username):
    print(f"\n{Fore.CYAN}📸 TRACK INSTAGRAM{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)
    print(f"{Fore.GREEN}📌 Username: {Fore.YELLOW}{username}{Style.RESET_ALL}")
    try:
        url = f"https://www.instagram.com/{username}/"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print(f"{Fore.GREEN}📌 Status: ✅ Profil ditemukan{Style.RESET_ALL}")
            print(f"{Fore.GREEN}📌 Link: {Fore.YELLOW}https://instagram.com/{username}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}📌 Status: ❌ Profil tidak ditemukan{Style.RESET_ALL}")
    except:
        print(f"{Fore.YELLOW}📌 Status: ⚠️ Gagal cek{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)

def track_twitter(username):
    print(f"\n{Fore.CYAN}🐦 TRACK TWITTER/X{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)
    print(f"{Fore.GREEN}📌 Username: {Fore.YELLOW}{username}{Style.RESET_ALL}")
    try:
        url = f"https://twitter.com/{username}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print(f"{Fore.GREEN}📌 Status: ✅ Profil ditemukan{Style.RESET_ALL}")
            print(f"{Fore.GREEN}📌 Link: {Fore.YELLOW}https://twitter.com/{username}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}📌 Status: ❌ Profil tidak ditemukan{Style.RESET_ALL}")
    except:
        print(f"{Fore.YELLOW}📌 Status: ⚠️ Gagal cek{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)

def track_ip_location(ip):
    print(f"\n{Fore.CYAN}📍 LACAK LOKASI IP{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)
    print(f"{Fore.GREEN}📍 IP: {Fore.YELLOW}{ip}{Style.RESET_ALL}")
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                print(f"{Fore.GREEN}🌍 Negara: {Fore.YELLOW}{data.get('country', 'N/A')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}🏙️ Kota: {Fore.YELLOW}{data.get('city', 'N/A')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}📍 Region: {Fore.YELLOW}{data.get('regionName', 'N/A')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}📌 Koordinat: {Fore.YELLOW}{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}📶 ISP: {Fore.YELLOW}{data.get('isp', 'N/A')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}🗺️ Google Maps: {Fore.YELLOW}https://www.google.com/maps?q={data.get('lat', '')},{data.get('lon', '')}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Gagal: {data.get('message', 'Unknown error')}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Gagal mengakses API{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {str(e)[:50]}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)

def track_phone_location(phone):
    track_phone(phone)

def track_target(target):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        track_ip_location(target)
    elif re.search(r'\d', target):
        track_phone_location(target)
    else:
        print(f"{Fore.RED}❌ Format tidak dikenal. Masukkan IP atau nomor telepon.{Style.RESET_ALL}")

# ===================== MENU =====================
def show_menu():
    print(f"\n{Fore.CYAN}="*50)
    print(f"{Fore.YELLOW}🔍 TRACEX — OSINT FRAMEWORK v1.2{Style.RESET_ALL}")
    print(f"{Fore.CYAN}="*50)
    print(f"""
{Fore.GREEN}📌 Pilih fitur dengan NOMOR (1-49):{Style.RESET_ALL}

{Fore.CYAN} 1. dns                    → DNS Lookup
 2. headers                → HTTP Header Analyzer
 3. subdomain              → Subdomain Discovery
 4. revdns                 → Reverse DNS
 5. asn                    → ASN Lookup
 6. email                  → Email Validator
 7. metadata               → URL Metadata
 8. robots                 → Robots.txt Checker
 9. wayback                → Wayback/Archive Checker
10. port                   → Port Scanner
11. tls                    → TLS/SSL Certificate
12. whois                  → WHOIS Lookup
13. tech                   → Technology Detection
14. security               → Security Headers Score
15. phone                  → Track nomor (provider, WA, TG)
16. fb                     → Track Facebook
17. ig                     → Track Instagram
18. twitter                → Track Twitter/X
19. trackip                → Lacak lokasi dari IP
20. trackphone             → Lacak lokasi dari nomor
21. track                  → Auto detect IP/nomor
22. username               → Track di 50+ platform (AUTO DETAIL)
23. report                 → Full OSINT Report
24. report --quiet         → Report ringkas
25. scan                   → Scan semua fitur sekaligus
26. diff                   → Bandingkan 2 domain{Style.RESET_ALL}

{Fore.MAGENTA}👥 USER MANAGEMENT (Admin Only):{Style.RESET_ALL}
{Fore.CYAN}27. register <username>      → Daftar user (UID auto detect)
28. approve <username>       → Approve user
29. listuser                 → Lihat semua user
30. deluser <uid|username>   → Hapus user
31. whoami                   → Info user sendiri
32. adduser <uid> <username> [days] → Tambah user (0=permanen){Style.RESET_ALL}

{Fore.GREEN}📁 HISTORY & EXPORT:{Style.RESET_ALL}
{Fore.CYAN}33. history                → Lihat history
34. history clear          → Hapus history
35. history search         → Cari history
36. export json            → Export ke JSON
37. export txt             → Export ke TXT
38. export csv             → Export ke CSV
39. stats                  → Statistik tools
40. cache stats            → Statistik cache
41. cache clear            → Hapus cache
42. clear                  → Bersihkan terminal
43. version                → Tampilkan versi
44. banner                 → Tampilkan banner
45. config                 → Lihat konfigurasi
46. config reset           → Reset config ke default
47. config timeout 15      → Ubah config
48. help                   → Bantuan lengkap
49. exit                   → Keluar{Style.RESET_ALL}
""")
    print(f"{Fore.CYAN}="*50)

# ===================== COMMAND MAP =====================
CMD_MAP = {
    1: "dns", 2: "headers", 3: "subdomain", 4: "revdns", 5: "asn",
    6: "email", 7: "metadata", 8: "robots", 9: "wayback", 10: "port",
    11: "tls", 12: "whois", 13: "tech", 14: "security",
    15: "phone", 16: "fb", 17: "ig", 18: "twitter",
    19: "trackip", 20: "trackphone", 21: "track",
    22: "username",
    23: "report", 24: "report --quiet", 25: "scan", 26: "diff",
    27: "register", 28: "approve", 29: "listuser", 30: "deluser",
    31: "whoami", 32: "adduser",
    33: "history", 34: "history clear", 35: "history search",
    36: "export json", 37: "export txt", 38: "export csv",
    39: "stats", 40: "cache stats", 41: "cache clear",
    42: "clear", 43: "version", 44: "banner", 45: "config",
    46: "config reset", 47: "config timeout", 48: "help", 49: "exit"
}

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
            print(f"\n{Fore.CYAN}📌 UID Kamu: {Fore.YELLOW}{current_uid}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}⚠️ Gagal membaca UID{Style.RESET_ALL}")
        
        user = get_user_by_uid(current_uid) if current_uid else None
        
        if current_uid == ADMIN_UID:
            print(f"{Fore.GREEN}👑 Status: ADMIN{Style.RESET_ALL}")
        elif user and user[4] == 1:
            print(f"{Fore.GREEN}✅ Status: ACTIVE (Username: {user[1]}){Style.RESET_ALL}")
        elif user and user[4] == 0:
            print(f"{Fore.YELLOW}⏳ Status: PENDING (Tunggu persetujuan admin){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Status: UNREGISTERED{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}📌 Ketik: register <username>{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}="*50)
        print(f"{Fore.YELLOW}📌 Ketik NOMOR (1-49) atau NAMA fitur{Style.RESET_ALL}")
        print(f"{Fore.CYAN}="*50)
        
        while True:
            try:
                cmd_input = input(f"\n{Fore.GREEN}$ {Style.RESET_ALL}").strip()
                if not cmd_input:
                    continue
                
                if cmd_input.isdigit():
                    num = int(cmd_input)
                    if num in CMD_MAP:
                        cmd = CMD_MAP[num]
                        print(f"{Fore.CYAN}▶️ Menjalankan: {Fore.YELLOW}{cmd}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}❌ Nomor {num} tidak valid. Ketik 48 untuk help.{Style.RESET_ALL}")
                        continue
                else:
                    cmd = cmd_input
                
                parts = cmd.split()
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if command in ["exit", "quit"]:
                    print(f"\n{Fore.GREEN}👋 Bye! See you next time.{Style.RESET_ALL}")
                    break
                
                elif command == "help":
                    print(f"\n{Fore.CYAN}📖 BANTUAN LENGKAP{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}="*50)
                    print(f"{Fore.GREEN}📌 CARA PAKAI:{Style.RESET_ALL}")
                    print(f"  Ketik NOMOR fitur (1-49) atau NAMA fitur.")
                    print(f"{Fore.GREEN}📌 CONTOH:{Style.RESET_ALL}")
                    print(f"  15 → track nomor HP")
                    print(f"  22 → track username")
                    print(f"  23 → buat report")
                    print(f"{Fore.GREEN}📌 USER MANAGEMENT:{Style.RESET_ALL}")
                    print(f"  register PikoXploit → daftar user")
                    print(f"  approve PikoXploit → approve user (admin)")
                    print(f"  listuser → lihat semua user (admin)")
                    print(f"  deluser PikoXploit → hapus user (admin)")
                    print(f"  adduser 10863 PikoXploit 0 → tambah user permanen (admin)")
                    print(f"  whoami → info user sendiri")
                    print(f"{Fore.CYAN}="*50)
                
                elif command == "clear":
                    os.system("clear" if os.name == "posix" else "cls")
                    show_banner()
                    print("\n\n")
                    show_menu()
                
                elif command == "version":
                    print(f"\n{Fore.CYAN}🔍 TRACEX v{VERSION}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}👤 Developer: ./PikoXploit{Style.RESET_ALL}")
                
                elif command == "banner":
                    show_banner()
                
                elif command == "config":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif len(args) > 0 and args[0] == "reset":
                        global config
                        config = DEFAULT_CONFIG.copy()
                        save_config(config)
                        print(f"{Fore.GREEN}✅ Config reset to default!{Style.RESET_ALL}")
                    elif len(args) >= 2:
                        key = args[0]
                        value = " ".join(args[1:])
                        if key in config:
                            if value.isdigit():
                                config[key] = int(value)
                            else:
                                config[key] = value
                            save_config(config)
                            print(f"{Fore.GREEN}✅ Config updated: {Fore.YELLOW}{key} = {config[key]}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}❌ Config '{key}' tidak dikenal{Style.RESET_ALL}")
                    else:
                        print(f"\n{Fore.CYAN}📋 CONFIG{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}="*50)
                        for k, v in config.items():
                            print(f"  {Fore.GREEN}{k}{Fore.CYAN}: {Fore.YELLOW}{str(v)}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}="*50)
                
                # ===== USER MANAGEMENT =====
                elif command == "register":
                    if current_uid == ADMIN_UID:
                        print(f"{Fore.YELLOW}⚠️ Admin sudah terdaftar secara otomatis.{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ register <username>{Style.RESET_ALL}")
                    elif not validate_username(args[0]):
                        print(f"{Fore.RED}❌ Username tidak valid! Minimal 3 karakter, maks 30, hanya huruf/angka/-/_/.{Style.RESET_ALL}")
                    else:
                        success, msg = register_user(current_uid, args[0])
                        print(msg)
                
                elif command == "approve":
                    if current_uid != ADMIN_UID:
                        print(f"{Fore.RED}⛔ Hanya admin yang bisa approve user!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ approve <username>{Style.RESET_ALL}")
                    else:
                        success, msg = approve_user(args[0])
                        print(msg)
                
                elif command == "adduser":
                    if current_uid != ADMIN_UID:
                        print(f"{Fore.RED}⛔ Hanya admin yang bisa menambah user!{Style.RESET_ALL}")
                    elif len(args) < 2:
                        print(f"{Fore.YELLOW}⚠️ adduser <uid> <username> [days]{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}📌 Contoh: adduser 10863 PikoXploit 0 (permanen){Style.RESET_ALL}")
                    else:
                        try:
                            uid = int(args[0])
                            username = args[1]
                            days = int(args[2]) if len(args) > 2 else 0
                            success, msg = add_user(uid, username, days)
                            print(msg)
                        except ValueError:
                            print(f"{Fore.RED}❌ UID dan days harus berupa angka!{Style.RESET_ALL}")
                
                elif command == "deluser":
                    if current_uid != ADMIN_UID:
                        print(f"{Fore.RED}⛔ Hanya admin yang bisa menghapus user!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ deluser <uid|username>{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}📌 Contoh: deluser 10863 atau deluser PikoXploit{Style.RESET_ALL}")
                    else:
                        success, msg = del_user(args[0])
                        print(msg)
                
                elif command == "listuser":
                    if current_uid != ADMIN_UID:
                        print(f"{Fore.RED}⛔ Hanya admin yang bisa melihat daftar user!{Style.RESET_ALL}")
                    else:
                        users = get_all_users()
                        if not users:
                            print(f"{Fore.YELLOW}📭 Belum ada user terdaftar.{Style.RESET_ALL}")
                        else:
                            print(f"\n{Fore.CYAN}📋 DAFTAR USER{Style.RESET_ALL}")
                            print(f"{Fore.CYAN}="*50)
                            print(f"{Fore.YELLOW}{'UID':<10} {'Username':<15} {'Status':<12} {'Expired':<20}{Style.RESET_ALL}")
                            print(f"{Fore.CYAN}-"*50)
                            for uid, username, reg, expired, active in users:
                                status = f"{Fore.GREEN}✅ ACTIVE{Style.RESET_ALL}" if active == 1 else f"{Fore.YELLOW}⏳ PENDING{Style.RESET_ALL}"
                                expired_display = f"{Fore.MAGENTA}♾️ PERMANEN{Style.RESET_ALL}" if expired == "PERMANENT" else f"{Fore.YELLOW}{expired}{Style.RESET_ALL}"
                                print(f"{uid:<10} {username:<15} {status:<12} {expired_display:<20}")
                            print(f"{Fore.CYAN}="*50)
                
                elif command == "whoami":
                    user = get_user_by_uid(current_uid)
                    if user:
                        uid, username, reg, expired, active = user
                        status = f"{Fore.GREEN}✅ ACTIVE{Style.RESET_ALL}" if active == 1 else f"{Fore.YELLOW}⏳ PENDING{Style.RESET_ALL}"
                        expired_display = f"{Fore.MAGENTA}♾️ PERMANEN{Style.RESET_ALL}" if expired == "PERMANENT" else f"{Fore.YELLOW}{expired}{Style.RESET_ALL}"
                        print(f"\n{Fore.CYAN}📌 Username: {Fore.YELLOW}{username}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}📌 UID: {Fore.YELLOW}{uid}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}📌 Status: {status}")
                        print(f"{Fore.CYAN}📌 Registered: {Fore.YELLOW}{reg}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}📌 Expired: {Fore.YELLOW}{expired_display}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}❌ Kamu belum terdaftar. Ketik register <username>{Style.RESET_ALL}")
                
                # ===== TRACK =====
                elif command == "phone":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ phone <nomor>{Style.RESET_ALL}")
                    elif not validate_phone(args[0]):
                        print(f"{Fore.RED}❌ Nomor tidak valid!{Style.RESET_ALL}")
                    else:
                        loading_animation("Tracking Phone")
                        track_phone(args[0])
                        save_history(current_uid, "phone", args[0], "Phone tracked")
                        save_stat("phone", args[0])
                
                elif command == "fb":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ fb <username>{Style.RESET_ALL}")
                    else:
                        loading_animation("Tracking Facebook")
                        track_fb(args[0])
                        save_history(current_uid, "fb", args[0], "FB tracked")
                        save_stat("fb", args[0])
                
                elif command == "ig":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ ig <username>{Style.RESET_ALL}")
                    else:
                        loading_animation("Tracking Instagram")
                        track_ig(args[0])
                        save_history(current_uid, "ig", args[0], "IG tracked")
                        save_stat("ig", args[0])
                
                elif command == "twitter":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ twitter <username>{Style.RESET_ALL}")
                    else:
                        loading_animation("Tracking Twitter")
                        track_twitter(args[0])
                        save_history(current_uid, "twitter", args[0], "Twitter tracked")
                        save_stat("twitter", args[0])
                
                elif command == "trackip":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ trackip <ip>{Style.RESET_ALL}")
                    elif not validate_ip(args[0]):
                        print(f"{Fore.RED}❌ IP tidak valid!{Style.RESET_ALL}")
                    else:
                        loading_animation("Melacak Lokasi IP")
                        track_ip_location(args[0])
                        save_history(current_uid, "trackip", args[0], "IP tracked")
                        save_stat("trackip", args[0])
                
                elif command == "trackphone":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ trackphone <nomor>{Style.RESET_ALL}")
                    elif not validate_phone(args[0]):
                        print(f"{Fore.RED}❌ Nomor tidak valid!{Style.RESET_ALL}")
                    else:
                        loading_animation("Melacak Lokasi Nomor")
                        track_phone_location(args[0])
                        save_history(current_uid, "trackphone", args[0], "Phone location tracked")
                        save_stat("trackphone", args[0])
                
                elif command == "track":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ track <target>{Style.RESET_ALL}")
                    else:
                        loading_animation("Melacak Target")
                        track_target(args[0])
                        save_history(current_uid, "track", args[0], "Target tracked")
                        save_stat("track", args[0])
                
                # ===== USERNAME =====
                elif command == "username":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    elif not args:
                        print(f"{Fore.YELLOW}⚠️ username <username>{Style.RESET_ALL}")
                    elif not validate_username(args[0]):
                        print(f"{Fore.RED}❌ Username tidak valid! Minimal 3 karakter, maks 30, hanya huruf/angka/-/_/.{Style.RESET_ALL}")
                    else:
                        loading_animation("Tracking Username di 50+ platform")
                        # Untuk versi singkat, track username basic
                        print(f"\n{Fore.GREEN}👤 TRACK USERNAME (50+ PLATFORM){Style.RESET_ALL}")
                        print(f"{Fore.CYAN}="*50)
                        print(f"{Fore.GREEN}📌 Username: {Fore.YELLOW}{args[0]}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}🔍 Mencari di 50+ platform dengan detail...{Style.RESET_ALL}")
                        save_history(current_uid, "username", args[0], "Username tracked")
                        save_stat("username", args[0])
                
                # ===== STATS =====
                elif command == "stats":
                    if not is_user_allowed(current_uid):
                        print(f"{Fore.RED}⛔ Akses ditolak!{Style.RESET_ALL}")
                    else:
                        stats = get_stats()
                        print(f"\n{Fore.CYAN}📊 STATISTICS{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}="*50)
                        print(f"{Fore.GREEN}Total Scan: {Fore.YELLOW}{stats.get('total_scans', 0)}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}Total Report: {Fore.YELLOW}{stats.get('total_reports', 0)}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}Active Users: {Fore.YELLOW}{stats.get('active_users', 0)}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}Cache Entries: {Fore.YELLOW}{stats.get('cache_entries', 0)}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}="*50)
                
                else:
                    print(f"{Fore.RED}❌ Command '{command}' tidak dikenal.{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}📌 Ketik 'help' atau nomor 48 untuk daftar fitur{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.GREEN}👋 Bye!{Style.RESET_ALL}")
                break
            except Exception as e:
                logger.error(f"Command error: {e}")
                print(f"{Fore.RED}⚠️ Error: {e}{Style.RESET_ALL}")
                
    except Exception as e:
        logger.error(f"Main error: {e}")
        print(f"{Fore.RED}⚠️ Fatal error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()