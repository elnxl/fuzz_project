#!/usr/bin/env python3

import argparse
from pwn import log
from yacc_parse import ASan, UBSan
import json
import re
from base64 import b64decode

parser = argparse.ArgumentParser(description='python script for parsing libfuzzer output')
parser.add_argument('logfile', help='crash log of libfuzzer')
parser.add_argument('-t', '--timeout', help='add timeout for fuzzer', type=int)
parser.add_argument('-o', '--output', help='output file')
parser.add_argument('--json', help='return json string to stdout', action='store_true')
args = parser.parse_args()

timeout = args.timeout

data = open(args.logfile, 'r').read()
lines = data.split('\n')[:-1]

shadow_map = []

if 'UndefinedBehaviorSanitizer' in data:
    sanitizer = UBSan()
elif 'AddressSanitizer' in data:
    sanitizer = ASan()
    for i in range(len(lines)):
        if lines[i] == 'Shadow bytes around the buggy address:':
            i += 1
            while lines[i] != 'Shadow byte legend (one shadow byte represents 8 application bytes):':
                splited = lines[i][2:].split(': ')
                shadow_map.append(splited)

                if '[' in shadow_map[-1][1]:
                    shadow_map[-1][1] = shadow_map[-1][1].replace('[', ' [').replace(']', '] ')
                shadow_map[-1][1] = shadow_map[-1][1].split(' ')

                shadow_map[-1] = {shadow_map[-1][0]: shadow_map[-1][1]}

                i += 1

else:
    log.critical('Unknown sanitizer or incorrect log file!')
    exit()

is_hash = False; is_equal = False
parse_str = ''

crash_input = re.findall(r'Base64: (.*)', data)
if crash_input != []:
    crash_input = str(b64decode(crash_input[0].encode()))[2:]


for line in lines:
    if line != '':
        if line[0] == '#':
            is_hash = True

        if '====' in line:
            is_equal = True

        if 'SUMMARY' in line:
            break

        if line[0] != '#' and (is_hash or is_equal) and not '====' in line:
            parse_str += line + '\n'
    
parse_str = parse_str[:-1]
sanitizer.parse_data(parse_str)
info = sanitizer.get_info()

if shadow_map:
    info.append({'type': 'shadow map', 'field': shadow_map})

if crash_input != []:
    info.append({'type': 'crash input', 'value': crash_input})

if args.json:
    print(json.dumps(info, indent=3))

if args.output:
    with open(args.output, 'w') as out:
        json.dump(info, out)