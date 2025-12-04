import requests
import whois
import socket
import dns.resolver
from PIL import Image
from PIL.ExifTags import TAGS

# ------------------------------
# 1) USERNAME OSINT
# ------------------------------

def username_osint():
    username = input("\n[?] Enter username: ").strip()

    sites = {
        "GitHub": f"https://github.com/{username}",
        "Twitter (X)": f"https://x.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
    }

    print(f"\n[+] Searching for username: {username}\n")

    headers = {"User-Agent": "Mozilla/5.0"}

    for site, url in sites.items():
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                print(f"[+] Found on {site}: {url}")
            else:
                print(f"[-] Not Found on {site}")
        except Exception as e:
            print(f"[!] Error checking {site}: {e}")

    print("\n[+] Username OSINT complete.\n")


# ------------------------------
# 2) IP LOOKUP (GEO + ISP INFO)
# ------------------------------

def ip_lookup():
    ip = input("\n[?] Enter IP address: ").strip()

    # Simple public API (ip-api.com)
    url = f"http://ip-api.com/json/{ip}"

    try:
        r = requests.get(url, timeout=5)
        data = r.json()

        if data.get("status") == "success":
            print("\n[+] IP Information:")
            print(f"    IP       : {data.get('query')}")
            print(f"    Country  : {data.get('country')} ({data.get('countryCode')})")
            print(f"    Region   : {data.get('regionName')}")
            print(f"    City     : {data.get('city')}")
            print(f"    ISP      : {data.get('isp')}")
            print(f"    Org      : {data.get('org')}")
            print(f"    Timezone : {data.get('timezone')}")
            print(f"    Lat,Lon  : {data.get('lat')}, {data.get('lon')}")
        else:
            print("[-] Could not fetch IP details. Maybe invalid IP.")
    except Exception as e:
        print(f"[!] Error while IP lookup: {e}")

    print("\n[+] IP lookup complete.\n")


# ------------------------------
# 3) DOMAIN WHOIS INFO
# ------------------------------

def domain_whois_lookup():
    domain = input("\n[?] Enter domain (example.com): ").strip()
    try:
        w = whois.whois(domain)
        print("\n[+] WHOIS Information:\n")
        for key, value in w.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[!] Error fetching WHOIS: {e}")

    print("\n[+] Domain WHOIS lookup complete.\n")


# ------------------------------
# 4) EMAIL OSINT (BASIC)
# ------------------------------

def email_osint():
    email = input("\n[?] Enter email address: ").strip()

    # Basic validation
    if "@" not in email or "." not in email.split("@")[-1]:
        print("[-] Email format invalid.")
        return

    user, domain = email.split("@", 1)
    print(f"\n[+] Email seems valid in format.")
    print(f"[+] Username part : {user}")
    print(f"[+] Domain part   : {domain}")

    # Check MX records of domain (mail servers)
    try:
        answers = dns.resolver.resolve(domain, "MX")
        print("\n[+] MX Records (Mail Servers):")
        for rdata in answers:
            print(f"    -> {rdata.exchange} (priority {rdata.preference})")
    except Exception as e:
        print(f"[!] Could not fetch MX records: {e}")

    print("\n[*] Note: Breach check (HaveIBeenPwned etc.) ke liye API key chahiye hoti hai.")
    print("[*] Ye tool sirf basic email/domain info de raha hai.\n")

    print("[+] Email OSINT complete.\n")


# ------------------------------
# 5) IMAGE METADATA (EXIF)
# ------------------------------

def image_metadata():
    path = input("\n[?] Enter image file path: ").strip()

    try:
        image = Image.open(path)
        exifdata = image._getexif()

        if not exifdata:
            print("[-] No EXIF metadata found in this image.")
            return

        print("\n[+] EXIF Metadata:\n")
        for tag_id, value in exifdata.items():
            tag = TAGS.get(tag_id, tag_id)
            print(f"{tag:25}: {value}")

    except FileNotFoundError:
        print("[-] File not found. Check path.")
    except Exception as e:
        print(f"[!] Error reading image metadata: {e}")

    print("\n[+] Image metadata extraction complete.\n")


# ------------------------------
# MAIN MENU
# ------------------------------

def main_menu():
    while True:
        print("""
=====================================
        ADVANCED OSINT SUITE
=====================================
1) Username OSINT
2) IP Lookup
3) Domain WHOIS Lookup
4) Email OSINT (basic)
5) Image Metadata Extractor
0) Exit
""")
        choice = input("[?] Choose an option: ").strip()

        if choice == "1":
            username_osint()
        elif choice == "2":
            ip_lookup()
        elif choice == "3":
            domain_whois_lookup()
        elif choice == "4":
            email_osint()
        elif choice == "5":
            image_metadata()
        elif choice == "0":
            print("\n[+] Exiting OSINT suite. Stay ethical!\n")
            break
        else:
            print("[-] Invalid option, try again.\n")


if __name__ == "__main__":
    print(">>> Ethical OSINT Tool - For Learning & Legal Use Only <<<")
    main_menu()
