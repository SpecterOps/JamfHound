import requests
import json

url = "http://192.168.0.185:9090/api/v2/customnode/jamfAccount" # Replace 192.168.0.185 with IP of BloodHound server or domain name

headers = {
    "Authorization": "Bearer ey...",
    "Content-Type": "application/json"
}

payload = {
    "config": {
            "icon": {
                "type": "font-awesome",
                "name": "circle-user",
                "color": "#0098BB"
            }
        }
}

# Perform POST request without SSL verification
response = requests.put(
    url,
    headers=headers,
    json=payload,
    verify=False  # <--- disables SSL certificate verification
)

# Print status code and response content
print("Status Code:", response.status_code)
print("Response Body:", response.text)
