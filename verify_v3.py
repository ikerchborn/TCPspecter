import os
import sys
import asyncio
from core.firewall_manager import detect_backend, get_blocked_ips
from core.snort_manager import is_snort_installed, is_snort_running
from core.traffic_analyzer import calculate_entropy, detect_magic_bytes, check_dga_domain, get_live_metrics
from core.web_server import get_dashboard_data

def test_firewall_and_snort():
    print("--- 1. Testing Firewall & Snort Status ---")
    backend = detect_backend()
    print(f"Firewall backend detected: {backend}")
    
    blocked = get_blocked_ips()
    print(f"Blocked IPs list: {blocked}")
    
    snort_inst = is_snort_installed()
    snort_run = is_snort_running()
    print(f"Snort installed: {snort_inst}, Snort running: {snort_run}")

def test_traffic_analyzer():
    print("\n--- 2. Testing Traffic Analyzer Functions ---")
    # Test entropy
    data_low = b"AAAAA"
    data_high = bytes(range(256))
    ent_low = calculate_entropy(data_low)
    ent_high = calculate_entropy(data_high)
    print(f"Low entropy bytes: {ent_low:.2f} (Expected close to 0.0)")
    print(f"High entropy bytes: {ent_high:.2f} (Expected close to 8.0)")
    assert ent_low < 1.0
    assert ent_high > 7.0
    
    # Test magic bytes
    pdf_sig = b"%PDF-1.4"
    zip_sig = b"PK\x03\x04"
    elf_sig = b"\x7fELF"
    unknown_sig = b"hello world"
    
    assert detect_magic_bytes(pdf_sig) == "PDF Document"
    assert detect_magic_bytes(zip_sig) == "ZIP/Office Document"
    assert detect_magic_bytes(elf_sig) == "Linux Executable (ELF)"
    assert detect_magic_bytes(unknown_sig) == "UNKNOWN"
    print("Magic bytes detection works correctly!")
    
    # Test DGA heuristics
    legit_domain = "google"
    dga_domain = "qzxprmvtywldsn"
    
    print(f"Is '{legit_domain}' DGA? {check_dga_domain(legit_domain)}")
    print(f"Is '{dga_domain}' DGA? {check_dga_domain(dga_domain)}")
    assert check_dga_domain(legit_domain) is False
    assert check_dga_domain(dga_domain) is True
    print("DGA domain heuristics work correctly!")

def test_web_server_data():
    print("\n--- 3. Testing Web Server Data Aggregation ---")
    data = get_dashboard_data()
    print("Keys in dashboard data:")
    for k in data.keys():
        print(f"  - {k}")
    
    assert "snort" in data, "Missing 'snort' status in dashboard data!"
    assert "firewall" in data, "Missing 'firewall' status in dashboard data!"
    assert "scapy" in data, "Missing 'scapy' metrics in dashboard data!"
    print("Web server dashboard data verification successful!")

if __name__ == "__main__":
    test_firewall_and_snort()
    test_traffic_analyzer()
    test_web_server_data()
    print("\nALL V3 INTEGRATION TESTS PASSED SUCCESSFULLY!")
