"""
Convert REST API JSON data to human-readable form.
Usage:
  jsonpretty.py URL
Example:
  sudo python jsonpretty.py http://127.0.0.1:8080/nmeta/flowtable/
"""
#*** see: http://stackoverflow.com/questions/352098/how-can-i-pretty-print-json

#*** Version 0.5

import sys
import simplejson as json
import requests

url = sys.argv[1]
s = requests.session()
r = s.get(url)
input = json.loads(r.text)
print json.dumps(input, sort_keys = True, indent = 4)

