import streamlit as st
from backend import get_abuseipdb_data, get_alienvault_data, get_virustotal_data

# Page Configuration
st.set_page_config(page_title="IP Threat Intelligence Dashboard", layout="centered")

# App Title
st.title("IP Threat Intelligence Dashboard")
st.markdown("Scan an IP address for potential cyber threats using AbuseIPDB, AlienVault OTX, and VirusTotal APIs.")

# IP Input Field
ip_address = st.text_input("Enter an IP Address:", placeholder="e.g., 8.8.8.8")

# Scan Button
if st.button("Scan IP"):
    if ip_address:
        st.write(f"### Scanning IP Address: {ip_address}")

        # AbuseIPDB Results
        st.write("#### AbuseIPDB Results:")
        abuseipdb_data = get_abuseipdb_data(ip_address)
        if "error" in abuseipdb_data:
            st.error(f"AbuseIPDB Error: {abuseipdb_data['error']}")
        else:
            st.json(abuseipdb_data)

        # AlienVault OTX Results
        st.write("#### AlienVault OTX Results:")
        alienvault_data = get_alienvault_data(ip_address)
        if "error" in alienvault_data:
            st.error(f"AlienVault OTX Error: {alienvault_data['error']}")
        else:
            st.json(alienvault_data)

        # VirusTotal Results
        st.write("#### VirusTotal Results:")
        virustotal_data = get_virustotal_data(ip_address)
        if "error" in virustotal_data:
            st.error(f"VirusTotal Error: {virustotal_data['error']}")
        else:
            st.json(virustotal_data)
    else:
        st.error("Please enter a valid IP address.")
