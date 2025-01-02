# UNIPI-VoWiFi-CaseStudy

This repository is a case study about the security of epdgs used in VoWifi (also called "Wifi Calling") for mobile devices.

> [!IMPORTANT]  
> To execute the `./server_scan` script, it is required to be a superuser due to the tcpdump library.

### Prepare the `edpg_server` environment:
``` bash
cd epdg_server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### To execute 

./server_scan.py --testcase SUPPORT_DH_1024_MODP (example)
