#
# netgear_admin.py
#
# Author - Corey Anderson 
# September 2020
# 
# Updated by Marko Sluga
# May 2025
#
# Updates 2025-05-26: 
# Added reboot functionality
# Added a more comprehensive extraction to support more formats for rand, cookie and hash
# Added debug printouts for rand, cookie and hash
#
# Usage examples:
#
# Turn OFF port 4
# python3 netgear.py -a 192.168.0.163 -passwd <password> -p 4 -s off
#
# Turn ON port 4
# python3 netgear.py -a 192.168.0.163 -passwd <password> -p 4 -s on
#
# Read status of ports:
# python3 netgear.py -a 192.168.0.163 -passwd <password> -r
#
# Reboot the device:
# python3 netgear.py -a 192.168.0.163 -passwd <password> -reboot
#
# Bugs/Issues:
# * Only one port can be toggled per run.
# * The switch returns 'The maximum number of attempts has been reached' errors
#   quite frequently, even when 'sleep_between_calls' 
#   is set to a high value, even 4 seconds
#

import sys

if sys.version_info.major < 3:
    print ("\nError: Python 3 required.\n")
    exit()
    
import re
import argparse
import urllib.request
import urllib.error
import hashlib
import json
import time
import http.client

parser = argparse.ArgumentParser()

parser.add_argument('-v', action='store_true', help='Verbose') # Not used
parser.add_argument('-r', action='store_true', help='Read switch port status') # Not used
parser.add_argument('-a', action='store', dest='switch_addr', required=True, help='IP address of switch')
parser.add_argument('-passwd', action='store', dest='passwd', required=True, help='Admin password of switch')
parser.add_argument('-p', action='store', dest='port', help='Switch Port')
parser.add_argument('-s', action='store', dest='set_status', help='Set Switch Port Status: [on/off]')
parser.add_argument('-reboot', action='store_true', help='Reboot the switch')

global args
global results

args = parser.parse_args()

# Additional Validation:
#
#if len(args.port) and not len(args.store):
if args.port:
    if not args.set_status:
        print ("Error: if -p (port) is specified, -s (status) is also required")
        exit()

    if args.set_status != 'on' and args.set_status != 'off':
        print ("Error: status must be either: on, off")
        exit()

config = { 
           'switch_addr'   : args.switch_addr,
           'passwd'        : args.passwd,
           'port'          : args.port,
           'read_status'   : args.r,              # If True, will also print out the status of the switch ports.
           'set_status'    : args.set_status,
           'reboot'        : args.reboot,         # If True, will reboot the switch.
           'rand_val'      : '',                  # The pseudo-random 'rand' field from the switch, used to 'encode' plaintext passwd.
           'hash_val'      : '',                  # An input var produced from the Switch's web server, needed to change status.
           'passwd_merged' : '',                  # The passwd, interleaved with the supplied passwd.
           'passwd_md5'    : '',                  # The md5 hash of passwd_enc, what we'll actually post to the switches web interface.
           'auth_cookie'   : '',                  # The cookie we get back on a successful login.
           'sleep_between_calls' : 4,             # Time in seconds to sleep between HTTP calls
         }

#
# Get the switches 'rand' value:
#
_contents = urllib.request.urlopen("http://%s/" % config['switch_addr']).read().decode("utf-8").replace('\n','')

time.sleep(config['sleep_between_calls'])

    
print("DEBUG: Looking for rand value in login page...")
# Try different regex patterns to find the rand value
_tmp = re.findall("<input type=hidden id=\"rand\" name=\"rand\" value='(\d+)' disabled>", _contents)

if not _tmp:
    # Try alternative pattern
    _tmp = re.findall("id=['\"]rand['\"] name=['\"]rand['\"] value=['\"](\d+)['\"]", _contents)

if not _tmp:
    # Try another alternative pattern
    _tmp = re.findall("value=['\"](\d+)['\"].*name=['\"]rand['\"]", _contents)

if not _tmp:
    # Print a portion of the page to help debug
    print("DEBUG: Page content snippet:", _contents[:500])
    print("ERROR: Could not find rand value in page. Check the HTML structure.")
    exit()

config['rand_val'] = _tmp[0]
print("DEBUG: Found rand value:", config['rand_val'])


#
# Set passwd_enc by merging plaintext password and our supplied 'rand' value:
#

i = 0

for c in config['rand_val']:
    if i < len(config['passwd']):
        config['passwd_merged'] += config['passwd'][i]
        
    i += 1        
    
    config['passwd_merged'] += c

if i < len(config['passwd']):
    config['passwd_merged'] += config['passwd'][-(len(config['passwd'])-i):]
    

config['passwd_md5'] = hashlib.md5(config['passwd_merged'].encode()).hexdigest()

#
# Attempt to post to login page, so we'll get a session cookie:
#
data = { 
         'password' : config['passwd_md5'],
       }

data = urllib.parse.urlencode(data).encode()

req = urllib.request.Request("http://%s/login.cgi" % config['switch_addr'], data=data)

resp = urllib.request.urlopen(req)

time.sleep(config['sleep_between_calls'])

_success_check = resp

_success_check = _success_check.read().decode("utf-8").replace('\n','')

if 'The password is invalid' in _success_check:
    print ("ERROR: Invalid Password")
    exit()
    
if 'The maximum number of attempts has been reached' in _success_check:
    print ("ERROR: The maximum number of failed attempts has been reached. Wait a few minutes and then try again")
    exit()

# Example cookie:
# GS108SID=K^tecASxwBawbwuJftgrB`n_yGjmr`JYhnFxJ\WmTILVUasWbFduJU\igbX`[GLhUw]_b`LLqZit_\_G; path=/;HttpOnly

cookie_header = str(resp.info()['Set-Cookie'])
print("DEBUG: Cookie received:", cookie_header)

try:
    if 'GS108SID=' in cookie_header:
        # Extract everything between GS108SID= and the next semicolon
        config['auth_cookie'] = cookie_header.split('GS108SID=')[1].split(';')[0]
    else:
        # Try to get the whole cookie if GS108SID is not found
        config['auth_cookie'] = cookie_header.split(';')[0]
    
    print("DEBUG: Extracted cookie:", config['auth_cookie'])

except Exception as ex:
    print("Error reading Cookie:", ex)
    exit()

if not config['auth_cookie']:
    print ("Unable to get cookie!")
    exit()

#
# Read 'hash' input field from: status.htm
# Example: <input type="hidden" name='hash' id='hash' value='26346'>
#
req = urllib.request.Request("http://%s/status.htm" % config['switch_addr'])
req.add_header("Cookie", "GS108SID=%s" % config['auth_cookie'])

_contents = urllib.request.urlopen(req)

time.sleep(config['sleep_between_calls'])

_success_check = _contents
_success_check = _success_check.read().decode("utf-8")
_status_check_list = _success_check.splitlines()
_success_check = _success_check.replace('\n','')
    
print("DEBUG: Looking for hash in page content...")

# Search for any hash-like pattern and print it for debugging
hash_debug = re.findall("hash['\"]\\s*[:=]\\s*['\"]([^'\"]+)['\"]", _success_check)
if hash_debug:
    print("DEBUG: Found potential hash values:", hash_debug)

# Search for any input with name="hash" and print it
hash_inputs = re.findall("<input[^>]*name=['\"]hash['\"][^>]*value=['\"]([^'\"]+)['\"]", _success_check)
if hash_inputs:
    print("DEBUG: Found hash inputs:", hash_inputs)
    # Use the first hash input found as our hash value
    _tmp = hash_inputs
    config['hash_val'] = hash_inputs[0]
    print("DEBUG: Using hash value from input:", config['hash_val'])

# Try different regex patterns to find the hash (numeric format)
_tmp = re.findall("<input type=\"hidden\" name='hash' id='hash' value='(\d+)'>", _success_check)

if not _tmp:
    # Try alternative pattern (numeric format)
    _tmp = re.findall("name=['\"]hash['\"] id=['\"]hash['\"] value=['\"](\d+)['\"]", _success_check)

if not _tmp:
    # Try another alternative pattern (numeric format)
    _tmp = re.findall("value=['\"](\d+)['\"].*name=['\"]hash['\"]", _success_check)

if not _tmp:
    # Try to find hexadecimal hash format (32 character hex string)
    _tmp = re.findall("name=['\"]hash['\"] value=['\"]([0-9a-f]{32})['\"]", _success_check)

if not _tmp:
    # Try alternative hexadecimal pattern
    _tmp = re.findall("value=['\"]([0-9a-f]{32})['\"].*name=['\"]hash['\"]", _success_check)

if not _tmp:
    # Try to find hash in JavaScript code
    _tmp = re.findall("hash\\s*[:=]\\s*['\"]([0-9a-f]{32})['\"]", _success_check)

if not _tmp:
    # Try to find any hash parameter
    _tmp = re.findall("hash['\"]\\s*[:=]\\s*['\"]([^'\"]+)['\"]", _success_check)

if not _tmp and not hash_inputs:
    # Print a portion of the page to help debug
    print("DEBUG: Page content snippet:", _success_check[:500])
    print("ERROR: Could not find hash value in page. Check the HTML structure.")
    exit()

# Only set from _tmp if we didn't already set from hash_inputs
if not hash_inputs and _tmp:
    config['hash_val'] = _tmp[0]
    print("DEBUG: Found hash value from regex:", config['hash_val'])

if config['read_status'] is True:
    print ("port status:")
    
    _tmp_line = 58  # Port 1 starts on line 59

    for p in range (1, 9):
        _p_status = _status_check_list[_tmp_line].replace('<td class="def " sel="select">', "")
    
        print ("Port %d   %s" % (p, _p_status))
        
        _tmp_line += 14

#
# If specified, post the desired status to the desired port:
#
if config['port']:
    _port = 'port' + config['port']
    
    # speed:
    # 1 = Auto
    # 2 = Disable
    # 3 - 6 = Other speed/duplex options
    
    _speed = '1' if config['set_status'] == 'on' else '2'
    
    data = { 
             _port          : 'checked',
             'SPEED'        : _speed,
             'FLOW_CONTROL' : '2',
             'hash'         : config['hash_val'],
           }
    
    data = urllib.parse.urlencode(data).encode()
    
    req = urllib.request.Request("http://%s/status.cgi" % config['switch_addr'], data=data)
    req.add_header("Cookie", "GS108SID=%s" % config['auth_cookie'])
    
    resp = urllib.request.urlopen(req)
    time.sleep(config['sleep_between_calls'])

#
# If reboot is specified, reboot the device:
#
if config['reboot']:
    try:
        # Try direct reboot with the hash from status page
        data = {
            'CBox': 'on',
            'hash': config['hash_val']  # Use the hash from status page
        }
        
        data = urllib.parse.urlencode(data).encode()
        
        req = urllib.request.Request("http://%s/device_reboot.cgi" % config['switch_addr'], data=data)
        req.add_header("Cookie", "GS108SID=%s" % config['auth_cookie'])
        
        try:
            resp = urllib.request.urlopen(req)
            print("Reboot command sent successfully. Device is rebooting...")
        except (urllib.error.URLError, http.client.RemoteDisconnected):
            # This is expected - the switch disconnects during reboot
            print("Reboot command sent successfully. Device is rebooting...")
    except Exception as ex:
        print("Error during reboot:", ex)
        exit()
    