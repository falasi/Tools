#!/usr/bin/env python3

# Get favicon unique hash
# Shodan Query:  http.favicon.hash:<Hash>

import mmh3
import requests
import codecs

url = input('Hostname:   Include the protocol i.e https://example.com') 
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
hash = mmh3.hash(favicon)
print(hash)
