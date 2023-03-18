#!/usr/bin/env python3

'''

Grab websites SSL certificate unique fingerprint (SHA-256)
Grab websites favicon.ico hash



Search Queries:
Shodan:
http.favicon.hash:<hash>

Censys:
fingerprint_sha256:<hash>

'''

import mmh3
import requests
import codecs
import ssl
import socket
import hashlib
import re

url = input('[?] Complete URL with protocol: ')
url = url.strip()


def finger_ssl(hostname):
  context = ssl.create_default_context()
  with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
      cert = ssl_sock.getpeercert(binary_form=True)

  cert_sha256 = hashlib.sha256(cert).hexdigest()
  print("[+] SSL SHA-256 fingerprint: ", cert_sha256)


def finger_favi(url):
  response = requests.get(url)
  favicon = codecs.encode(response.content, "base64")
  hash = mmh3.hash(favicon)
  print("[+] Favicon.ico fingerprint: ", hash)


def remove_protocol(url):
  pattern = r"(https?://)(.+)"
  match = re.match(pattern, url)
  if match:
    protocol = match.group(1)
    domain = match.group(2)
    return domain
  else:
    return url

def main():
  hostname = remove_protocol(url)
  finger_ssl(hostname)
  finger_favi(url)


if __name__ == "__main__":
    main()
