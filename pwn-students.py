#!/usr/bin/env python3
import base64
import json

import requests

# Name of the cookie
COOKIE = "session"
MAC_SIZE = 4

def mh5(x):
    state = 0

    # Apply padding
    x = x + b"\x80" # Terminate message with 0x80
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"

    # Split into chunks
    for i in range(0,len(x), MAC_SIZE):
        state += int.from_bytes(x[i:i+MAC_SIZE], byteorder="big")
        state &= (2**32 - 1)
    return state.to_bytes(length=MAC_SIZE, byteorder="big")

with requests.Session() as session:

    r = session.get(f'https://t13.itsec.sec.in.tum.de/d23b5c35913a41b1')
    cookie = session.cookies[COOKIE]

    decoded = bytes.fromhex(cookie)

    mac, session_data = decoded[:MAC_SIZE], decoded[MAC_SIZE:]

    json_hash = mh5(b'{"u": "tester"}')

    secret_key = int.from_bytes(mac, "big") - int.from_bytes(json_hash, "big")

    new_mac = secret_key + int.from_bytes(mh5(b'{"u": "admin"}'), "big")

    admin_json = b'{"u": "admin"}'

    new_cookie = hex(new_mac)[2:] + admin_json.hex()

    session.cookies.set(name = COOKIE, value = new_cookie, domain = "https://t13.itsec.sec.in.tum.de")

    # Cookie is now modified for this (and the following) requests
    r = session.get(f'https://t13.itsec.sec.in.tum.de/d23b5c35913a41b1')
    print(r.text)

    for i in range(2 ** 32):  # Range from 0 to 2^32 - 1
        hex_representation = format(i,'08x')  # '08x' pads the hex representation with zeros to ensure a length of 8 characters
        session.cookies.set(name=COOKIE, value= hex_representation + admin_json.hex(), domain="https://t13.itsec.sec.in.tum.de")

        # Cookie is now modified for this (and the following) requests
        r = session.get(f'https://t13.itsec.sec.in.tum.de/d23b5c35913a41b1')
        if "flag" in r.text:
            print(r.text)
        if i % 5000 == 0:  # Check if the current value of i is a multiple of 5000
            print(
                f"At integer {i}: Hex representation is {hex_representation}")  # Print the integer value and its corresponding 32-bit hexadecimal representation