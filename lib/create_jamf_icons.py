import requests
import json

url = "http://127.0.0.1:8080/api/v2/custom-nodes" #Replace 127.0.0.1 with BloodHound server IP or domain name
headers = {
    "Authorization": "Bearer eyJ..", # Add bearer token
    "Content-Type": "application/json"
}

node_types = ["jamf_Account", "jamf_Computer", "jamf_Site", "jamf_Group", "jamf_ApiClient", "jamf_DisabledApiClient", "jamf_ComputerUser", "jamf_Tenant", "jamf_DisabledAccount"]
icon_names = ["circle-user", "display", "circle-nodes", "people-group", "user-gear", "user-gear", "circle-user", "cloud", "circle-user"]
colors = ["#0098BB", "#D6001C", "#D67500", "#F0FC03", "#8803FC", "#909090", "#FC03A5", "#00C08D", "#909090"]

for x in range(len(node_types)):
#   print(f"{x}: {node_types[x]}, {icon_names[x]}, {colors[x]}")
    payload = {
        "custom_types": {
            node_types[x]: {
                "icon": {
                    "type": "font-awesome",
                    "name": icon_names[x],
                    "color": colors[x]
                }
            }
        }
    }
   
    # Perform POST request without SSL verification
    response = requests.post(
        url,
        headers=headers,
        json=payload,
        verify=False  # <--- disables SSL certificate verification
    )

    # Print status code and response content
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)
