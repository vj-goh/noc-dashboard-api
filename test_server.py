#!/usr/bin/env python3
"""Test if the server is responding"""
import httpx
import time

time.sleep(1)  # Wait for server to be ready

try:
    print("Testing root endpoint...")
    r = httpx.get('http://127.0.0.1:3000/', timeout=5)
    print(f"✓ Status: {r.status_code}")
    print(f"✓ Response: {r.text[:200]}")
    
    print("\nTesting networks endpoint...")
    r = httpx.get('http://127.0.0.1:3000/api/devices/networks/list', timeout=5)
    print(f"✓ Status: {r.status_code}")
    data = r.json()
    print(f"✓ Networks: {data.get('count', 'N/A')}")
    if data.get('networks'):
        for net in data['networks'][:3]:
            created = net.get('created_at', 'N/A')
            print(f"  - {net.get('name', 'Unknown')} (created: {created})")
            
except Exception as e:
    print(f"✗ Error: {type(e).__name__}: {e}")
