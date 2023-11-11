import requests
from requests.exceptions import ConnectionError
import dns.resolver
from urllib.parse import urlparse
import argparse
import ssl
import socket
import hashlib
from datetime import datetime


def print_current_datetime():
  # Get current date and time in UTC
  current_datetime = datetime.utcnow()
  # Format the datetime string as required
  formatted_datetime = current_datetime.strftime("%a %b %d %H:%M:%S UTC %Y")
  print(formatted_datetime)


def check_subdomain(url):
  try:
    response = requests.get(url)
    print("\nHTTP Response Details:")
    print(f"  Status Code: {response.status_code}")
    print("  Response Headers:")
    for header, value in response.headers.items():
      print(f"    {header}: {value}")
    print("  Response Body (snippet):")
    print(f"    {response.text[:100]}...\n")
  except ConnectionError:
    print(f"\ncurl: (6) Could not resolve host: {url}\n")
  except requests.RequestException as e:
    print(f"\nHTTP request error: {e}\n")


def check_domain(domain):
  try:
    print("\nDNS Resolution Details:")
    answers = dns.resolver.resolve(domain, 'A')
    for rdata in answers:
      print(f"  Resolved IP: {rdata}")
    print()
  except dns.resolver.NXDOMAIN:
    print(f"\nHost {domain} not found: 3(NXDOMAIN)\n")
  except Exception as e:
    print(f"\nError resolving domain {domain}: {e}\n")


def check_certificate(domain):
  try:
    # Establishing an SSL connection and getting the certificate
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
      with context.wrap_socket(sock, server_hostname=domain) as ssock:
        der_cert = ssock.getpeercert(binary_form=True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = ssock.getpeercert()

    # Calculate SHA-256 fingerprint of the certificate
    sha256_fingerprint = hashlib.sha256(der_cert).hexdigest()

    # Extract and calculate SHA-256 fingerprint of the public key
    public_key = ssl.PEM_cert_to_DER_cert(pem_cert)
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()

    # Function to parse and format the subject and issuer information
    def parse_name(entity):
      result = {}
      for item in entity:
        for key, value in item:
          # Only add if not already present (to handle repeated fields like OU)
          if key not in result:
            result[key] = value
          else:
            result[key] += f", {value}"
      return result

    subject = parse_name(cert['subject'])
    issuer = parse_name(cert['issuer'])

    # Printing the formatted information
    print("\nIssued To")
    print(
        f"  Common Name (CN): {subject.get('commonName', '<Not Part Of Certificate>')}"
    )
    print(
        f"  Organization (O): {subject.get('organizationName', '<Not Part Of Certificate>')}"
    )
    print(
        f"  Organizational Unit (OU): {subject.get('organizationalUnitName', '<Not Part Of Certificate>')}"
    )
    print("\nIssued By")
    print(
        f"  Common Name (CN): {issuer.get('commonName', '<Not Part Of Certificate>')}"
    )
    print(
        f"  Organization (O): {issuer.get('organizationName', '<Not Part Of Certificate>')}"
    )
    print(
        f"  Organizational Unit (OU): {issuer.get('organizationalUnitName', '<Not Part Of Certificate>')}"
    )
    print("\nValidity Period")
    not_before = datetime.strptime(
        cert['notBefore'],
        '%b %d %H:%M:%S %Y %Z').strftime('%A, %B %d, %Y at %I:%M:%S %p')
    not_after = datetime.strptime(
        cert['notAfter'],
        '%b %d %H:%M:%S %Y %Z').strftime('%A, %B %d, %Y at %I:%M:%S %p')
    print(f"  Issued On: {not_before}")
    print(f"  Expires On: {not_after}")

    # Print SHA-256 fingerprint of the certificate
    print(f"\nSHA-256 Fingerprint: {sha256_fingerprint.upper()}")

    # Print SHA-256 fingerprint of the public key
    print(f"Public Key SHA-256 Fingerprint: {public_key_sha256.upper()}")

  except Exception as e:
    print(f"Error checking certificate for {domain}: {e}")


def check_reverse_lookup(ip_address):
  try:
      host, _, _ = socket.gethostbyaddr(ip_address)
      print(f"\nReverse Lookup for {ip_address}:")
      print(f"  Hostname: {host}\n")
  except Exception as e:
      print(f"\nError in reverse lookup for {ip_address}: {e}\n")

# Setting up argument parser
parser = argparse.ArgumentParser(
  description="Check subdomain, domain status, and reverse IP lookup",
  formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--site', type=str, help="URL to check (e.g., http://domain.com/index.html)", required=False)
parser.add_argument('-c', '--cert', action='store_true', help="Check SSL/TLS certificate", required=False)
parser.add_argument('-r', '--reverse', type=str, help="IP address for reverse lookup", required=False)

# Parsing arguments
args = parser.parse_args()

# Check if any argument is passed
if not (args.site or args.cert or args.reverse):
  parser.print_help()
  print("\nExamples:")
  print("  python script.py -s http://domain.com/index.html")
  print("  python script.py -s http://domain.com/index.html -c")
  print("  python script.py -r 8.8.8.8")
  exit(1)


# Print the current date and time
print_current_datetime()

# Call the functions based on arguments
if args.site:
  # Extracting domain name from URL
  parsed_url = urlparse(args.site)
  domain_name = parsed_url.netloc

  check_subdomain(args.site)
  check_domain(domain_name)

  if args.cert:
      check_certificate(domain_name)
elif args.reverse:
  check_reverse_lookup(args.reverse)


