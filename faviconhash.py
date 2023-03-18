#!/usr/bin/env python3

# Get favicon unique hash
# Shodan Query:  http.favicon.hash:<Hash>

import mmh3
import requests
import codecs

url = 'https://example.com/favicon.ico'
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
hash = mmh3.hash(favicon)
print(hash)
