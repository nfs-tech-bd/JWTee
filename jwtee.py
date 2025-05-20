import base64
import json
import sys
import time
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

def base64url_decode(data):
    padding = '=' * (4 - (len(data) % 4))
    data += padding
    return base64.b64decode(data.replace('-', '+').replace('_', '/'))

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        print(f"{Fore.RED}[-] Invalid JWT format. Expected 3 parts separated by '.'")
        return

    header_data = base64url_decode(parts[0])
    payload_data = base64url_decode(parts[1])
    signature = parts[2]

    try:
        header = json.loads(header_data)
        payload = json.loads(payload_data)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[-] Failed to parse JSON from JWT parts.")
        print(e)
        return

    print("\n" + "="*50)
    print(f"{Fore.CYAN}{Style.BRIGHT}JWT Token Decoded{Style.RESET_ALL}")
    print("="*50 + "\n")

    print(f"{Fore.YELLOW}[+] Header:{Style.RESET_ALL}")
    print(json.dumps(header, indent=4))

    print(f"\n{Fore.GREEN}[+] Payload:{Style.RESET_ALL}")
    print(json.dumps(payload, indent=4))

    print(f"\n{Fore.MAGENTA}[+] Signature:{Style.RESET_ALL}")
    print(signature)

    if 'exp' in payload:
        exp_timestamp = payload['exp']
        exp_date = datetime.utcfromtimestamp(exp_timestamp)
        now = int(time.time())
        if exp_timestamp < now:
            print(f"\n{Fore.RED}⚠️  This token has EXPIRED on {exp_date.strftime('%Y-%m-%d %H:%M:%S UTC')}{Style.RESET_ALL}")
        else:
            print(f"\n🕒 Token expires on: {exp_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")


    alg = header.get('alg', 'unknown')
    if alg == 'HS256':
        print(f"{Fore.YELLOW}ℹ️  Signature algorithm: {alg} (Symmetric){Style.RESET_ALL}")
    elif alg == 'RS256':
        print(f"{Fore.GREEN}✔️  Signature algorithm: {alg} (Asymmetric){Style.RESET_ALL}")
    elif alg == 'none':
        print(f"{Fore.RED}❌ WARNING: Token uses no signature! ('none') — Insecure!{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️  Unknown signature algorithm: {alg}{Style.RESET_ALL}")

    return header, payload, signature

def copy_to_clipboard(text):
    try:
        import pyperclip
        pyperclip.copy(text)
        print(f"\n{Fore.BLUE}📋 Decoded data copied to clipboard.{Style.RESET_ALL}")
    except ImportError:
        print(f"\n{Fore.YELLOW}ℹ️  Clipboard feature not available. Install 'pyperclip' for copying support.{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python3 jwt_decoder.py <JWT-Token>{Style.RESET_ALL}")
        sys.exit(1)

    jwt_token = sys.argv[1]
    result = decode_jwt(jwt_token)

    if result:
        header, payload, signature = result
        full_decoded = {
            "header": header,
            "payload": payload,
            "signature": signature
        }
        choice = input(f"\n{Fore.CYAN}Do you want to copy decoded JWT to clipboard? (y/n): {Style.RESET_ALL}").strip().lower()
        if choice in ['y', 'yes']:
            copy_to_clipboard(json.dumps(full_decoded, indent=4))