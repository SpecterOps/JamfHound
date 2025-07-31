import requests
import json

url = "http://192.168.0.185:9090/api/v2/customnode" #Replace 192.168.0.185 with BloodHound server IP or domain name

headers = {
    "Authorization": "Bearer ey...",
    "Content-Type": "application/json"
}

#Account icon
#payload = {
#    "custom_types": {
#        "jamfAccount": {
#            "icon": {
#                "type": "font-awesome",
#                "name": "circle-user",
#                "color": "#"
#            }
#        }
#    }
#}



#Computer icon
#payload = {
#    "custom_types": {
#        "jamfComputer": {
#            "icon": {
#                "type": "font-awesome",
#                "name": "display",
#                "color": "#D6001C"
#            }
#        }
#    }
#}

#Site Icon
#payload = {
#  "custom_types": {
#    "jamfSite": {
#      "icon": {
#        "type": "font-awesome",
#        "name": "circle-nodes",
#        "color": "#D67500"
#      }
#    }
#  }
#}

#Group Icon
#payload = {
#  "custom_types": {
#    "jamfGroup": {
#      "icon": {
#        "type": "font-awesome",
#        "name": "people-group",
#        "color": "#F0FC03"
#      }
#    }
#  }
#}

#API Client Icon
#payload = {
#  "custom_types": {
#    "jamfApiClient": {
#      "icon": {
#        "type": "font-awesome",
#        "name": "user-gear",
#        "color": "#8803FC"
#      }
#    }
#  }
#}

#Disabled API Client Icon
#payload = {
#  "custom_types": {
#    "jamfDisabledApiClient": {
#      "icon": {
#        "type": "font-awesome",
#        "name": "user-gear",
#        "color": "#909090"
#      }
#    }
#  }
#}

#Disabled API Client Icon
payload = {
  "custom_types": {
    "jamfComputerUser": {
      "icon": {
        "type": "font-awesome",
        "name": "circle-user",
        "color": "#FC03A5"
      }
    }
  }
}

#Tenant icon
#payload = {
#  "custom_types": {
#    "jamfTenant": {
#      "icon": {
#        "type": "font-awesome",
#        "name": "cloud",
#        "color": "#00C08D"
#      }
#    }
#  }
#}






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
