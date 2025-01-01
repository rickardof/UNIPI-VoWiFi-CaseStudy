#!/usr/bin/env python3

import argparse
import pathlib
import re
import subprocess
import time

from ikev2_class import EpdgIKEv2  # custom class for handling epdg ikev2 operations
from tests_config import TEST_CONFIG
from tqdm import tqdm
from utils import resolve_domain


def main():
    parser = argparse.ArgumentParser(description="ePDG IKE scanner for VoWiFi")
    parser.add_argument("--interface", required=False, help="target network interface", default="any")
    parser.add_argument("--ip", required=False, help="ip version", choices=["ipv4", "ipv6", "ipv4v6"], default="ipv4")
    parser.add_argument("--testcase", required=True, help="test case", choices=TEST_CONFIG.keys())
    args = vars(parser.parse_args())

    print("> Starting")
    interface = args["interface"]
    ip_version = args["ip"]

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"{args['testcase']}_{timestamp}"
    pathlib.Path("results").mkdir(parents=True, exist_ok=True)

    # load domains from file
    with open("epdg_domains_foreign.txt") as file:
        epdg_domains = [line.rstrip() for line in file]

    if args["testcase"] == "CHECK_AUTOCONF_DOMAINS":
        with open(f"results/{name}.txt", "a") as results_file:
            for domain in epdg_domains:
                domain = domain.replace("epdg.epc", "aes")  # adjust domain for auto-configuration testing
                ips = resolve_domain(domain, ip_version)  # resolve domain to ip addresses
                for ip in ips:
                    timestamp = time.strftime("%Y%m%d-%H%M%S")
                    print(f"[{timestamp}] {domain} -> {ip}")
                    results_file.write(f"[{timestamp}] {domain} -> {ip}\n")
            exit(0)

    sa_list = TEST_CONFIG[args["testcase"]]["sa_list"]  # security association configurations
    ke = TEST_CONFIG[args["testcase"]]["key_echange"]  # key exchange algorithm
    ipsec_encr = TEST_CONFIG[args["testcase"]].get("ipsec_encr")  # optional ipsec encryption settings
    ipsec_integ = TEST_CONFIG[args["testcase"]].get("ipsec_integ")  # optional ipsec integrity settings

    # start packet capture using tcpdump
    p = subprocess.Popen(
        ["tcpdump", "-i", interface, "-w", f"results/{name}.pcap", "port", "500 or 4500"], stdout=subprocess.PIPE
    )

    with open(f"results/{name}.txt", "a") as results_file:
        results_file.write(f"# key exchange: {ke}\n")
        results_file.write(f'# sa_list: [{", ".join([t.transform_id.name for sublist in sa_list for t in sublist])}]\n')

        for domain in tqdm(epdg_domains, desc="Scanning domains"):
            ips = resolve_domain(domain, ip_version)
            for ip in ips:
                # extract mobile country code and mobile network code from domain
                m = re.search(r"^epdg.epc.mnc(\d{2,3}).mcc(\d{3}).pub.3gppnetwork.org\.?$", domain)
                mnc = m[1]
                mcc = m[2]

                # instantiate the epdgikev2 object
                # this object manages ikev2 communication with the specified domain and parameters
                ike = EpdgIKEv2(ip, 500, interface=None if interface == "any" else interface, mcc=mcc, mnc=mnc)

                # perform ike_sa_init exchange
                # this establishes the initial security association (sa) with the epdg
                resp = ike.ike_sa_init(sa_list, key_exchange=ke)

                timestamp = time.strftime("%Y%m%d-%H%M%S")
                if not ipsec_encr:
                    # log the response for ike_sa_init if no ipsec encryption is required
                    print(f"[{timestamp}] {domain} -> {ip}: {resp}")
                    results_file.write(f"[{timestamp}] {domain} -> {ip}: {resp}\n")
                elif "successfull" in resp:
                    # if the initial exchange is successful, proceed with ike_auth
                    # ike_auth completes authentication and sets up ipsec sas
                    resp = ike.ike_auth(ipsec_encr, ipsec_integ)
                    print(f"[{timestamp}] {domain} -> {ip}: {resp}")
                    results_file.write(f"[{timestamp}] {domain} -> {ip}: {resp}\n")

    print("> Terminating tcpdump")
    p.terminate()
    print("> Script done")


if __name__ == "__main__":
    main()
