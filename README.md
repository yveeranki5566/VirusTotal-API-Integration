  # VirusTotal-API-Integration 

  ![image](https://github.com/user-attachments/assets/b08b3e36-90b4-48f8-b48e-71dbb04c8ae1)


Create a Python script that uses the VirusTotal API to check the safety of a URL and report the analysis results.
Lets import requests, json, re and time modules for this script.
These libraries are used to make HTTP requests, handle JSON data, setting time between checks, and work with regular expressions.

Defined Functions and their purpose in this project. 
# get_ip_info(ip):

Sends a request to VirusTotal to get information about the given IP address.

First, it creates the URL for the API request including the IP address you want information about. Next, it sets up the headers for the request, including your API key needed for authorization. Then sends a GET request to VirusTotal's API to get information about the IP address. Lastly, the API response is converted from JSON format to a PYthon dictionary and returns it.

# is_valid_ip(ip):

This function first uses the regex pattern to check the basic format, then splits the IP address into octets and verifies that each octet is within the range 0-255.If it matches, the function proceeds to further validation. Then it splits the IP address into a list of its four octets, and checks if each octet is within the valid range (0 to 255). This ensures that each part of the IP address is a valid number. Returns False if the IP address does not match the pattern.

# process_ips(ip_list):

This function takes a list of IP addresses and processes each one.For each IP address in the list, it checks if it’s valid and if it’s different from the last one which was processed. Then it retrieves information about the IP address and prints it. Next, it waits for 1 second before processing the next IP address.

# main():

In this function we defines a list of IP addresses to process. It calls process_ips function to start processing and to print the information.

<img width="653" alt="image" src="https://github.com/user-attachments/assets/34c6bf8e-5480-47b9-b6a1-023ab9148fb7">



# Source code

```
import requests
import json
import re
import time

# Replace with your actual VirusTotal API key
API_KEY = 'Your API Key'


def get_ip_info(ip):
    """Get information about the IP address from VirusTotal."""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}' 
    headers = {"x-apikey": API_KEY} 
    response = requests.get(url, headers=headers)
    return response.json() 


def is_valid_ip(ip):
    """Check if the IP address is in the correct format and valid range (0-255)."""
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(ip) is not None:
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    return False


def process_ips(ip_list):
    """Process a list of IP addresses and print their information."""
    last_ip = ""
    for ip in ip_list:
        if is_valid_ip(ip) and ip != last_ip:
            info = get_ip_info(ip)  # Get information about the IP
            result = {
                "IP": info.get("data", {}).get("id"),
                "Last Analysis Stats": info.get("data", {}).get("attributes", {}).get("last_analysis_stats"),
            }
            print(json.dumps(result, indent=4))  # Print the result
            last_ip = ip  # Update the last IP address checked
        time.sleep(1)  # Wait for 1 second before processing the next IP


def main():
    """Run the IP processing."""
    ip_list = [
        "192.168.1.1",
        "8.8.8.8",
        "10.0.0.1",
        "2.56.57.108",
        "8.8.4.4",
    ]
    process_ips(ip_list)


if __name__ == "__main__":
    main()
```

