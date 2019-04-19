#!/usr/bin/env python
import socket
from snowflake import snowflake
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from base64 import b64encode

HOST, PORT = "localhost", 514

def signMessage(message):
    digest = SHA256.new()
    digest.update(message.encode('utf-8'))

    with open('private_key.pem') as privfile:
        priv_key = privfile.read()
        signer = PKCS1_v1_5.new(RSA.importKey(priv_key))

    return b64encode(signer.sign(digest))

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# As you can see, there is no connect() call; UDP has no connections.
# Instead, data is directly sent to the recipient via sendto().
with open('MOCK_DATA.txt') as fp:
    lines = fp.readlines()

for l in lines:
    l = l.strip()
    sig = bytes.decode(signMessage(l))
    sock.sendto(bytes("{} SIGNATURE: {}\n".format(l, sig), "utf-8"), (HOST, PORT))
    received = str(sock.recv(1024), "utf-8")

    print("Sent:     {}".format(l))
    print("Received: {}".format(received))