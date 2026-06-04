#!/usr/bin/env python3
import socket, requests, ipaddress, threading, os, sys, time, re, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
BOT_TOKEN = ""
# ---------------------

def send_msg(chat_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    try: return requests.post(url, data=payload).json().get("result", {}).get("message_id")
    except: return None

def edit_msg(chat_id, message_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/editMessageText"
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    try: requests.post(url, data=payload)
    except: pass

def send_file(chat_id, file_path):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    with open(file_path, 'rb') as f:
        requests.post(url, data={'chat_id': chat_id}, files={'document': f})

def expand_targets(entry: str):
    try: return [str(ip) for ip in ipaddress.ip_network(entry, strict=False).hosts()]
    except:
        try: return [socket.gethostbyname(entry)]
        except: return []

# --- 11 SOURCES ENGINE ---
def lookup_ip_dynamic_sources(ip, timeout=8):
    domains_found = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
    
    # API Nodes
    nodes = [
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns",
        f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}",
        f"https://jonlu.ca/anubis/subdomains/{ip}",
        f"https://api.bgpview.io/ip/{ip}",
        f"https://sonar.omnisint.io/reverse/{ip}"
    ]
    for url in nodes:
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list): domains_found.extend(data)
                elif "passive_dns" in data: domains_found.extend([x['hostname'] for x in data['passive_dns'] if x.get('hostname')])
                elif "data" in data and "ptr_record" in data['data']: domains_found.append(data['data']['ptr_record'])
        except: pass
    
    # HackerTarget
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", headers=headers, timeout=4)
        if r.status_code == 200: domains_found.extend([line.strip() for line in r.text.split("\n") if "." in line])
    except: pass
        
    # CT Logs
    try:
        r = requests.get(f"https://crt.sh/?q={ip}&output=json", headers=headers, timeout=timeout)
        if r.status_code == 200: domains_found.extend([c.get("common_name") for c in r.json() if c.get("common_name")])
    except: pass
    
    # Certspotter
    try:
        r = requests.get(f"https://api.certspotter.com/v1/issuances?include_subdomains=true&dns_domain={ip}", headers=headers, timeout=timeout)
        if r.status_code == 200:
            for item in r.json():
                if "dns_names" in item: domains_found.extend(item["dns_names"])
    except: pass
    
    # Wayback
    try:
        r = requests.get(f"https://web.archive.org/cdx/search/cdx?url={ip}/*&output=json&fl=original&collapse=urlkey", headers=headers, timeout=timeout)
        if r.status_code == 200:
            matches = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})', r.text)
            domains_found.extend(matches)
    except: pass

    # Socket PTR & Subprocess Host
    try:
        ptr_data = socket.gethostbyaddr(ip)
        if ptr_data[0]: domains_found.append(ptr_data[0])
    except: pass

    return list(set([d.lower().strip().rstrip(".") for d in domains_found if "." in d]))

# --- BOT LOOP WITH PROGRESS COUNTER ---
def run_bot():
    last_update_id = 0
    print("Bot is ready...")
    while True:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?offset={last_update_id + 1}&timeout=30"
        try:
            resp = requests.get(url, timeout=35).json()
            if resp.get('result'):
                for update in resp['result']:
                    last_update_id = update['update_id']
                    msg = update.get('message', {})
                    chat_id = msg.get('chat', {}).get('id')
                    text = msg.get('text', '')
                    
                    if text.startswith('/cidr '):
                        target = text.split(' ')[1]
                        mid = send_msg(chat_id, "⚡ Scanning starting...")
                        
                        targets = expand_targets(target)
                        all_found = []
                        done = 0
                        total = len(targets)
                        lock = threading.Lock()
                        
                        def process_ip(t):
                            nonlocal done
                            res = lookup_ip_dynamic_sources(t)
                            with lock:
                                done += 1
                                remaining = total - done
                                percent = int((done / total) * 100)
                                filled = int(10 * done / total)
                                bar = "█" * filled + "░" * (10 - filled)
                                
                                # Updated UI with IP stats
                                status = (
                                    f"<b>Scanning:</b> {target}\n"
                                    f"<b>Progress:</b> [{bar}] {percent}%\n\n"
                                    f"📊 <b>Total IPs:</b> {total}\n"
                                    f"✅ <b>Scanned:</b> {done}\n"
                                    f"⏳ <b>Remaining:</b> {remaining}"
                                )
                                edit_msg(chat_id, mid, status)
                            return res
                        
                        with ThreadPoolExecutor(max_workers=10) as exe:
                            results = list(exe.map(process_ip, targets))
                        
                        for res in results: all_found.extend(res)
                        
                        edit_msg(chat_id, mid, f"✅ <b>Scan Complete!</b>\nRecords found: {len(all_found)}")
                        if all_found:
                            with open("results.txt", "w") as f: f.write("\n".join(all_found))
                            send_file(chat_id, "results.txt")
                        else: send_msg(chat_id, "No records found.")
        except Exception as e: print(e); time.sleep(5)

if __name__ == "__main__":
    run_bot()
