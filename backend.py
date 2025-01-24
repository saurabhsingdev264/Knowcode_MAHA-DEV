import os
import requests
from dotenv import load_dotenv

# Load API keys from the .env file
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# AbuseIPDB Integration
def get_abuseipdb_data(ip):
    """Fetch IP threat data from AbuseIPDB."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# AlienVault OTX Integration
def get_alienvault_data(ip):
    """Fetch IP threat data from AlienVault OTX."""
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# VirusTotal Integration
def get_virustotal_data(ip):
    """Fetch IP threat data from VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# Main function to test the APIs
if __name__ == "__main__":
    # Test IP address
    ip_to_scan = "8.8.8.8"

    print("Fetching data from AbuseIPDB...")
    abuseipdb_data = get_abuseipdb_data(ip_to_scan)
    print(abuseipdb_data)

    print("\nFetching data from AlienVault OTX...")
    alienvault_data = get_alienvault_data(ip_to_scan)
    print(alienvault_data)

    print("\nFetching data from VirusTotal...")
    virustotal_data = get_virustotal_data(ip_to_scan)
    print(virustotal_data)
