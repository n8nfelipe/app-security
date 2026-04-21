from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_api_token
from pydantic import BaseModel
from typing import List, Optional
import nmap

router = APIRouter(dependencies=[Depends(require_api_token)])

class NetworkDevice(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    state: str

class NetworkSummary(BaseModel):
    total: int
    devices: List[NetworkDevice]

@router.get("/network/devices", response_model=NetworkSummary)
def get_network_devices() -> NetworkSummary:
    nm = nmap.PortScanner()
    try:
        scan_result = nm.scan(hosts="192.168.1.0/24", arguments="-sn")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    devices = []
    for ip, value in scan_result.get('scan', {}).items():
        state = value.get('status', {}).get('state', 'unknown')
        hostname = None
        if value.get('hostnames'):
            first = value['hostnames'][0]
            hostname = first.get('name') if first else None
        mac = None
        vendor = None
        if 'addresses' in value and 'mac' in value['addresses']:
            mac = value['addresses']['mac']
            vendor_map = value.get('vendor', {})
            if mac and vendor_map:
                vendor = vendor_map.get(mac)
        devices.append(NetworkDevice(ip=ip, mac=mac, hostname=hostname, vendor=vendor, state=state))
    return NetworkSummary(total=len(devices), devices=devices)
