# Vulnerable helper — payment & inventory (demo only)
import os
import requests

API_KEY = "sk-accmarket-live-abcdefghijklmnopqrstuv"

def fetch_stock(url_from_user):
    # SSRF
    return requests.get(url_from_user).text


def export_orders(user_path):
    # Path traversal style open
    with open("exports/" + user_path) as f:
        return f.read()


def run_sync(host):
    os.system("curl http://" + host + "/sync")
