import urllib
import requests
import urllib3
from pathlib import Path
from colorama import Fore, Style, init



banner = r"""
███████╗ ██████╗ ██╗     ██╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
██╔════╝██╔═══██╗██║     ██║    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
███████╗██║   ██║██║     ██║    ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
╚════██║██║▄▄ ██║██║     ██║    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
███████║╚██████╔╝███████╗██║    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                                   

                         SQLi Detector
                                                                                                                               
                                                                                                                               
"""
print(banner)


print("""
SQLi Types:
T : Time-Based Blind SQLi
B : Boolean-Based Blind SQLi
U : Union-Based SQLi
""")

method = input('SQLi type [T/B/U]: ').strip().lower()

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def fingerprint(res):
    text = res.text.lower()

    if any(x in text for x in ["sql syntax", "unknown column", "order clause"]):
        return "SQL_ERROR"

    if any(x in text for x in ["blocked", "forbidden", "waf", "access denied"]):
        return "BLOCKED"

    
    return "OK"


def classify_pattern(e0, e1, e2):

    
    if e0 != e1 or e1 != e2:

        if "SQL_ERROR" in [e0, e1, e2] and "OK" in [e0, e1, e2]:
            return "POSSIBLE_VULNERABLE"

        return "UNCERTAIN"
 
    if e0 == e1 == e2:
        if e0 == "OK":
            return "NO_SIGNAL"

        if e0 == "SQL_ERROR":
            return "BLOCKED_OR_NOISE"

        if e0 == "BLOCKED":
            return "WAF_DETECTED"
    
def load_order_by_payloads(filename: str):
    file_path = Path("payloads") / filename

    payloads = {
        "single_quote": [],
        "double_quote": [],
        "no_quote": []
    }


    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith("single_quote:"):
                payloads["single_quote"].append(line.split(":", 1)[1].strip())

            elif line.startswith("double_quote:"):
                payloads["double_quote"].append(line.split(":", 1)[1].strip())

            elif line.startswith("no_quote:"):
                payloads["no_quote"].append(line.split(":", 1)[1].strip())

    return payloads


def discovery_vulnerability(url, method, payloads):

    result = []

    if method == "u":

        for quote_type, payload_list in payloads.items():

            if len(payload_list) < 3:
                continue

            p0, p1, p2 = payload_list[:3]

            res0 = requests.get(url + urllib.parse.quote(p0), verify=False)
            res1 = requests.get(url + urllib.parse.quote(p1), verify=False)
            res2 = requests.get(url + urllib.parse.quote(p2), verify=False)
            
            e0, e1, e2 = map(fingerprint, [res0, res1, res2])
            status = classify_pattern(e0, e1, e2)
  
            result.append({
                "type": quote_type,
                "status": status
            })

    status_colors = {
        "POSSIBLE_VULNERABLE": Fore.RED,
        "UNCERTAIN": Fore.YELLOW,
        "NO_SIGNAL": Fore.GREEN,
        "BLOCKED_OR_NOISE": Fore.CYAN,
        "WAF_DETECTED": Fore.MAGENTA
    }

    for r in result:
        color = status_colors.get(r["status"], Fore.WHITE)
        print(f"{r['type']} → {color}{r['status']}{Style.RESET_ALL}")

    return result
    


url = input("Enter URL: ").strip()

payloads = load_order_by_payloads("union.txt")

result = discovery_vulnerability(url, method, payloads)

print(result)
    





