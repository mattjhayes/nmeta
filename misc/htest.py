# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#*** htest - HTTP Test
#
# Matt Hayes
# Victoria University, New Zealand
# matthew_john_hayes@hotmail.com
# August 2014
#
# Version 1.0

"""
This code is used to test object retrieval times for HTTP GET
requests (all contained within a single HTTP/1.1 TCP connection)
.
Requests module does not do caching, so each GET retrieves the object fresh
.
Do not use this code for production deployments - it is proof of concept code
and carries no warrantee whatsoever. You have been warned.
"""

#*** Import library to do HTTP GET requests:
#*** See: http://docs.python-requests.org/en/latest/api/?highlight=elapsed#requests.Response.elapsed
#*** See: http://docs.python-requests.org/en/latest/
import requests

import datetime
import time

#*** Import sys for basic command line argument parsing:
import sys

#*** URL (can include a port number) is passed on the command line:
url = sys.argv[1]

#*** Writes output to a CSV file:
filename = time.strftime("%Y%m%d-%H%M%S.csv")
print "filename is", filename
with open(filename, 'a') as the_file:
    the_file.write(url)
    the_file.write('\n')
#*** Set up an HTTP/1.1 Keep-Alive session:
s = requests.session()
#*** Hack the HTTP adapter to set max retries to a larger value:
a = requests.adapters.HTTPAdapter(max_retries=5)
s.mount('http://', a)
#*** Set HTTP Headers to keep connection alive:
headers = {'Connection': 'keep-alive'}
#*** Start the loop:
for x in range(0, 16000):
    timenow = datetime.datetime.now()
    timestamp = timenow.strftime("%H:%M:%S")
    start_time = time.time()
    #*** Make the HTTP GET request:
    r = s.get(url, headers=headers)
    end_time = time.time()
    total_time = end_time - start_time
    #*** Put the stats into a nice string for printing and writing to file:
    result = str(timestamp) + "," + str(r.elapsed.total_seconds()) + "," + str(total_time) + "\n"
    print result
    with open(filename, 'a') as the_file:
        the_file.write(result)
    #*** 1 second sleep to keep program from running too hard out:
    time.sleep(1)




