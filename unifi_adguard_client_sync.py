#!/usr/bin/env python3
"""
Unifi Adguard Client Sync - This will update Adguard Home with all active client information from Unifi OS.
Using a MAC Address as a primary identifier, this script will sync the IP Addresses and Names so they reflect what is in Unifi OS.

Usage:
    unifi_adguard_client_sync.py \
        --unifi-url URL { --unifi-api-key KEY | --unifi-username USER [--unifi-password PW] } \
        --adguard-url URL --adguard-username USER [--adguard-password PW] \
        [--ignored-networks NET1 NET2]

Unifi Authentication:
    Either supply an API key (UNIFI_API_KEY / --unifi-api-key) or username+password.
    API key is preferred: set it in UniFi OS under Settings > Control Plane > Integrations.

Passwords:
    You may supply passwords either via optional CLI flags or environment variables. If a flag is omitted,
    the script will look for UNIFI_PW / ADGUARD_PW. If neither a flag nor environment variable is present,
    the script exits with an error.
"""
__author__ = "PleaseStopAsking"
__maintainer__ = "PleaseStopAsking"
__version__ = "1.0.0"

import os
from datetime import timezone, datetime
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)


def parse_args():
    parser = argparse.ArgumentParser(
        description=("Sync active client data in Unifi OS with client records in AdGuard. "
                     "Passwords can be provided via flags or environment variables (UNIFI_PW, ADGUARD_PW)."))
    parser.add_argument("--unifi-url", dest="unifi_url", required=False, help="URL of Unifi Server (or set UNIFI_URL)")
    parser.add_argument("--unifi-api-key", dest="unifi_api_key", required=False,
                        help="Unifi API key (or set UNIFI_API_KEY). Preferred over username+password.")
    parser.add_argument("--unifi-username", dest="unifi_username", required=False,
                        help="Username of Unifi user (or set UNIFI_USERNAME). Not needed when --unifi-api-key is set.")
    parser.add_argument("--unifi-password", dest="unifi_password", required=False,
                        help="Unifi password (or set UNIFI_PW). Not needed when --unifi-api-key is set.")
    parser.add_argument("--adguard-url", dest="adguard_url", required=False, help="URL of AdGuard Server (or set ADGUARD_URL)")
    parser.add_argument("--adguard-username", dest="adguard_username", required=False,
                        help="Username of AdGuard user (or set ADGUARD_USERNAME)")
    parser.add_argument("--adguard-password", dest="adguard_password", required=False, help="AdGuard password (or set ADGUARD_PW)")
    parser.add_argument("--ignored-networks", dest="ignored_networks", required=False,
                        help="Comma-delimited list of network names to ignore (e.g., 'Guest,IoT')")
    args = parser.parse_args()

    # fallback to environment variables if flags not supplied
    # allow using environment for all connection parameters
    if args.unifi_url is None:
        args.unifi_url = os.environ.get("UNIFI_URL")
    if args.unifi_api_key is None:
        args.unifi_api_key = os.environ.get("UNIFI_API_KEY")
    if args.unifi_username is None:
        args.unifi_username = os.environ.get("UNIFI_USERNAME")
    if args.unifi_password is None:
        args.unifi_password = os.environ.get("UNIFI_PW")
    if args.adguard_url is None:
        args.adguard_url = os.environ.get("ADGUARD_URL")
    if args.adguard_username is None:
        args.adguard_username = os.environ.get("ADGUARD_USERNAME")
    if args.adguard_password is None:
        args.adguard_password = os.environ.get("ADGUARD_PW")
    if args.ignored_networks is None:
        args.ignored_networks = os.environ.get("IGNORED_NETWORKS", "")
    # convert comma-delimited string to list, trimming whitespace; support empty -> []
    if isinstance(args.ignored_networks, str):
        args.ignored_networks = [n.strip() for n in args.ignored_networks.split(",") if n.strip()]

    # validate presence for all required fields
    if not args.unifi_url:
        raise SystemExit("Unifi URL missing: supply --unifi-url or set UNIFI_URL")
    if not args.unifi_api_key:
        if not args.unifi_username:
            raise SystemExit("Unifi auth missing: supply --unifi-api-key (UNIFI_API_KEY) or --unifi-username (UNIFI_USERNAME)")
        if not args.unifi_password:
            raise SystemExit("Unifi password missing: supply --unifi-password or set UNIFI_PW")
    if not args.adguard_url:
        raise SystemExit("AdGuard URL missing: supply --adguard-url or set ADGUARD_URL")
    if not args.adguard_username:
        raise SystemExit("AdGuard username missing: supply --adguard-username or set ADGUARD_USERNAME")
    if not args.adguard_password:
        raise SystemExit("AdGuard password missing: supply --adguard-password or set ADGUARD_PW")
    return args


def unifi_login(s: requests.Session, arguments):
    """
    Simple POST request to log in. This will store a cookie in the session cookie jar.
    :param arguments: argparse arguments
    :param s: requests.Session
    :return: None
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {
        "username": arguments.unifi_username,
        "password": arguments.unifi_password
    }
    r = s.post("{}/api/auth/login".format(arguments.unifi_url), headers=headers, json=data, verify=False)
    r.raise_for_status()


def unifi_get_active_clients(s: requests.Session, arguments):
    """
    Simple GET request to retrieve all Active clients from Unifi.
    :param arguments: argparse arguments
    :param s: requests.Session
    :return: dict[str, dict] -> {mac_addr: client-obj}
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    clients = s.get("{}/proxy/network/v2/api/site/default/clients/active".format(arguments.unifi_url), headers=headers, verify=False)
    clients.raise_for_status()
    c = clients.json()
    active_clients = dict()
    for client in c:
        mac = client.get('mac')
        if not mac:
            continue
        if not client.get('name'):
            client['name'] = client.get('display_name')
        if client.get('network_name') not in arguments.ignored_networks:
            active_clients[mac] = client
    return active_clients


def adguard_login(s: requests.Session, arguments):
    """
    Simple POST request to log in to Adguard with username and password. Adds cookie
    to session cookie jar.
    :param arguments: argparse arguments
    :param s: requests.Session
    :return: None
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {
        "name": arguments.adguard_username,
        "password": arguments.adguard_password
    }
    r = s.post("{}/control/login".format(arguments.adguard_url), headers=headers, json=data)
    r.raise_for_status()


def adguard_get_clients(s: requests.Session, arguments) -> tuple[dict, dict, dict]:
    """
    GET all AdGuard clients, indexed three ways for conflict-free syncing.
    :return: (by_mac, by_ip, by_name) — all dict[str, client-obj]
    """
    r = s.get("{}/control/clients".format(arguments.adguard_url))
    r.raise_for_status()
    by_mac, by_ip, by_name = {}, {}, {}
    for client in r.json().get('clients') or []:
        by_name[client['name']] = client
        for id_item in client['ids']:
            if len(id_item) == 17:
                by_mac[id_item] = client
            else:
                by_ip[id_item] = client
    return by_mac, by_ip, by_name


def adguard_add_client(s: requests.Session, client, adguard_url):
    """
    POST request to create a NEW client. A Unifi OS client object/dict
    is required.
    :param adguard_url: base-url for adguard
    :param s:       requests.Session
    :param client:  unifi-os client-dict
    :return:        None
    """
    print("[sync] Adding client {} to AdGuard".format(client["display_name"]))
    ip = client.get('fixed_ip') or client.get('ip')
    if not ip or not client.get('mac'):
        print(f"[sync] Skipping {client.get('display_name', 'unknown')} — missing IP or MAC")
        return

    data = {
        "name": client['name'],
        "ids": [
            ip,
            client['mac']
        ],
        "use_global_settings": True,
        "use_global_blocked_services": True,
        "tags": [],
    }
    r = s.post("{}/control/clients/add".format(adguard_url), json=data)
    if not r.ok:
        raise requests.HTTPError(
            f"{r.status_code} {r.reason} adding '{client['name']}': {r.text}", response=r
        )


def adguard_delete_all(s: requests.Session, clients: list[str], adguard_url):
    """
    Used to clean up clients in AdGuard. Since AdGuard clients are merely names for existing
    entities, deleting all doesn't remove any data. It just deletes the relationship between
    IP-ADDR and a Name.
    :param s:       requests.Session
    :param clients: list of client names
    :param adguard_url: base-url for adguard
    :return:        None
    """
    for c in clients:
        r = s.post("{}/control/clients/delete".format(adguard_url), json={"name": c})
        r.raise_for_status()


def adguard_update_client(s: requests.Session, client, old_name, adguard_url):
    """
    POST request to update a client. This request will update the name and
    IDS (mac_addr, ip_addr) of the client object in AdGuard.
    :param s:           requests.Session
    :param client:      unifi-os client-dict
    :param old_name:    the original name (from AdGuard client-dict)
    :param adguard_url: base-url for adguard
    :return:            None
    """
    print("[sync] Updating client {} in AdGuard".format(old_name))
    ip = client.get('fixed_ip') or client.get('ip')
    data = {
        "name": old_name,
        "data": {
            "upstreams": [],
            "tags": [],
            "name": client['name'],
            "blocked_services": None,
            "ids": [
                ip,
                client['mac']
            ],
            "filtering_enabled": False,
            "parental_enabled": False,
            "safebrowsing_enabled": False,
            "safesearch_enabled": False,
            "use_global_blocked_services": True,
            "use_global_settings": True
        }
    }
    r = s.post("{}/control/clients/update".format(adguard_url), json=data)
    if not r.ok:
        raise requests.HTTPError(
            f"{r.status_code} {r.reason} updating '{old_name}': {r.text}", response=r
        )


def main():
    args = parse_args()
    start_ts = datetime.now(tz=timezone.utc)
    print(f"[sync] Start cycle at {start_ts}")
    # create session
    session = requests.Session()

    # authenticate to unifi — API key takes precedence over username/password
    if args.unifi_api_key:
        session.headers.update({"X-API-KEY": args.unifi_api_key})
        print("[sync] Using API key authentication for Unifi")
    else:
        unifi_login(session, args)
    print("[sync] Retrieving active clients from Unifi...")
    unifi_clients = unifi_get_active_clients(session, args)

    # login to adguard and retrieve clients
    adguard_login(session, args)
    print("[sync] Retrieving clients from AdGuard...")
    adguard_by_mac, adguard_by_ip, adguard_by_name = adguard_get_clients(session, args)

    # determine changes
    print("[sync] Calculating changes...")
    unifi_active_client_macs = set(unifi_clients.keys())
    adguard_client_macs = set(adguard_by_mac.keys())
    new_clients = unifi_active_client_macs - adguard_client_macs
    existing_clients = unifi_active_client_macs.intersection(adguard_client_macs)
    added_clients = 0
    modified_clients = 0
    failed_clients = 0

    # new clients — check for IP/name conflicts before adding
    for c in new_clients:
        unifi_client = unifi_clients[c]
        ip = unifi_client.get('fixed_ip') or unifi_client.get('ip')
        name = unifi_client.get('name')
        conflicting = (adguard_by_ip.get(ip) or adguard_by_name.get(name)) if name else None
        try:
            if conflicting:
                print(f"[sync] '{name}' conflicts with existing AdGuard client '{conflicting['name']}' — updating instead")
                adguard_update_client(session, unifi_client, conflicting['name'], args.adguard_url)
                modified_clients += 1
            else:
                adguard_add_client(session, unifi_client, args.adguard_url)
                added_clients += 1
        except Exception as e:
            failed_clients += 1
            print(f"[sync] Failed for client {unifi_client.get('display_name', c)}: {e}")

    # existing clients (matched by MAC) — update if IP or name drifted
    for c in existing_clients:
        ip = unifi_clients[c].get('fixed_ip') or unifi_clients[c].get('ip')
        unifi_data = {ip, unifi_clients[c]['mac']}
        adguard_client = adguard_by_mac[c]
        if (unifi_data != set(adguard_client['ids'])) or unifi_clients[c]['name'] != adguard_client['name']:
            try:
                print(f"[sync] Differences found for client {unifi_clients[c]['name']}, updating...")
                adguard_update_client(session, unifi_clients[c], adguard_client['name'], args.adguard_url)
                modified_clients += 1
            except Exception as e:
                failed_clients += 1
                print(f"[sync] Failed to update client {unifi_clients[c].get('display_name', c)}: {e}")

    if added_clients == 0 and modified_clients == 0 and failed_clients == 0:
        print("[sync] No changes required.")
    else:
        print("[sync] Changes made: {} added, {} modified, {} failed.".format(added_clients, modified_clients, failed_clients))
    end_ts = datetime.now(tz=timezone.utc)
    print(f"[sync] End cycle at {end_ts}")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        # avoid crashing container; log and continue
        print(f"[sync] Sync failed: {e}")
