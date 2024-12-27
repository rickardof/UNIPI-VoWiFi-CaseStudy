# UNIPI-VoWiFi-CaseStudy

This repository is a case study about the security of epdgs used in VoWifi (also called "Wifi Calling") for mobile devices.


### Prepare the edpg_server environment:
cd epdg_server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


### Prepare the mobile_station environment:
cd mobile_station
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt