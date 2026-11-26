#!/usr/bin/env python3

from pwn import *
from math import gcd
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import inverse

e1 = 65539
e2 = 65543

m1 = "1"
m2 = "2"
m3 = "3"
messages = []


def conn():
    r = remote("challs.glacierctf.com", 13374)
    return r


def prepare_payload(msg):
    payload = json.dumps({"msg": msg, "e": e1})
    return payload


def prepare_payload_flag(e):
    payload = json.dumps({"e": e})
    return payload


def gather_messages(r, msg):
    r.sendlineafter(b"> ", msg.encode())

    raw = r.recvline().decode().strip()
    match = re.search(r"0x[0-9a-fA-F]+", raw)

    if not match:
        raise ValueError(raw)

    c = int(match.group(), 16)
    messages.append(c)

    return c


def recover_message_flag(r, msg):
    r.sendlineafter(b"> ", msg.encode())

    raw = r.recvline().decode().strip()
    match = re.search(r"0x[0-9a-fA-F]+", raw)

    if not match:
        raise ValueError(raw)

    c = int(match.group(), 16)
    return c


def get_n():
    plaintexts = [m1, m2, m3]

    differences = []

    for m, c in zip(plaintexts, messages):
        m_int = bytes_to_long(m.encode())
        differences.append(pow(m_int, e1) - c)

    n = 0

    for diff in differences:
        n = gcd(n, diff)

    return abs(n)


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def signed_pow(c, exponent, n):
    if exponent < 0:
        return pow(inverse(c, n), -exponent, n)
    return pow(c, exponent, n)


def main():
    r = conn()
    payload1 = prepare_payload(m1)
    payload2 = prepare_payload(m2)
    payload3 = prepare_payload(m3)
    r.recvuntil(b"Please provide us with the message to sign and the public exponents")
    gather_messages(r, payload1)
    gather_messages(r, payload2)
    gather_messages(r, payload3)

    n = get_n()
    print("messages:", messages)
    print("n:", n)

    payload_flag1 = prepare_payload_flag(e1)
    payload_flag2 = prepare_payload_flag(e2)
    c1 = recover_message_flag(r, payload_flag1)
    c2 = recover_message_flag(r, payload_flag2)
    _, a, b = egcd(e1, e2)
    m = signed_pow(c1, a, n) * signed_pow(c2, b, n) % n
    print("[FELLAS] : ", long_to_bytes(m))
    r.interactive()


if __name__ == "__main__":
    main()
