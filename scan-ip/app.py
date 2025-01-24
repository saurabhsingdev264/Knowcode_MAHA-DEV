import streamlit as st
from backend import get_abuseipdb_data, get_alienvault_data, get_virustotal_data


def parse_abuseipdb(data):
    """Extract malicious status from AbuseIPDB data."""
    if "error" in data:
        return {"status": "Error", "message": data["error"]}
    try:
        score = data["data"]["abuseConfidenceScore"]
        if score > 50:
            return {"status": "Malicious", "confidence": f"{score}%"}
        else:
            return {"status": "Clean", "confidence": f"{score}%"}
    except KeyError:
        return {"status": "Error", "message": "Unexpected response format"}


def parse_alienvault(data):
    """Extract malicious status from AlienVault OTX data."""
    if "error" in data:
        return {"status": "Error", "message": data["error"]}
    try:
        pulses = len(data.get("pulse_info", {}).get("pulses", []))
        if pulses > 0:
            return {"status": "Malicious", "pulses": f"{pulses} threat reports"}
        else:
            return {"status": "Clean", "pulses": "No threat reports"}
    except KeyError:
        return {"status": "Error", "message": "Unexpected response format"}


def parse_virustotal(data):
    """Extract malicious status from VirusTotal data."""
    if "error" in data:
        return {"status": "Error", "message": data["error"]}
    try:
        malicious_votes = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if malicious_votes > 0:
            return {"status": "Malicious", "votes": f"{malicious_votes} detections"}
        else:
            return {"status": "Clean", "votes": "No detections"}
    except KeyError:
        return {"status": "Error", "message": "Unexpected response format"}


# Streamlit Frontend
st.set_page_config(page_title="IP Threat Summary", layout="centered")

st.title("IP Threat Intelligence Dashboard")
st.markdown("### Quickly determine whether an IP is malicious or clean.")

# Input field for IP address
ip_address = st.text_input("Enter an IP Address:", placeholder="e.g., 8.8.8.8")

# Scan button
if st.button("Scan IP"):
    if ip_address:
        st.write(f"### Scanning IP Address: {ip_address}")

        # AbuseIPDB Results
        st.write("#### AbuseIPDB Result:")
        abuseipdb_data = get_abuseipdb_data(ip_address)
        abuseipdb_result = parse_abuseipdb(abuseipdb_data)
        if abuseipdb_result["status"] == "Malicious":
            st.error(f"Malicious ({abuseipdb_result['confidence']})")
        elif abuseipdb_result["status"] == "Clean":
            st.success(f"Clean ({abuseipdb_result['confidence']})")
        else:
            st.warning(f"Error: {abuseipdb_result['message']}")

        # AlienVault OTX Results
        st.write("#### AlienVault OTX Result:")
        alienvault_data = get_alienvault_data(ip_address)
        alienvault_result = parse_alienvault(alienvault_data)
        if alienvault_result["status"] == "Malicious":
            st.error(f"Malicious ({alienvault_result['pulses']})")
        elif alienvault_result["status"] == "Clean":
            st.success(f"Clean ({alienvault_result['pulses']})")
        else:
            st.warning(f"Error: {alienvault_result['message']}")

        # VirusTotal Results
        st.write("#### VirusTotal Result:")
        virustotal_data = get_virustotal_data(ip_address)
        virustotal_result = parse_virustotal(virustotal_data)
        if virustotal_result["status"] == "Malicious":
            st.error(f"Malicious ({virustotal_result['votes']})")
        elif virustotal_result["status"] == "Clean":
            st.success(f"Clean ({virustotal_result['votes']})")
        else:
            st.warning(f"Error: {virustotal_result['message']}")
    else:
        st.error("Please enter a valid IP address.")
