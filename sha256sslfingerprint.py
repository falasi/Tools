#!/usr/bin/env python3

# Get the hosts SSL certificate "SHA 256 fingerprint" and run it through Censys
# Censys Query: fingerprint_sha256:<hash>
import ssl
import socket
import hashlib

hostname = "example.com"  # Replace with the hostname of the website you want to check

context = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
        cert = ssl_sock.getpeercert(binary_form=True)

cert_sha256 = hashlib.sha256(cert).hexdigest()
print("SHA-256 fingerprint: ", cert_sha256)
