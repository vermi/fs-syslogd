#!/usr/bin/env python
import socket
from base64 import b64encode
import keyring
import json
import requests
from time import time, sleep
from random import randint
import pysectools
from pygtail import Pygtail as tail

VAULT_URL = 'http://127.0.0.1:8200'
HOST, PORT = 'localhost', 514
LOG_FILE = 'MOCK_DATA.txt'
interval = randint(3, 5)

# Protect our memory from leaking secrets
pysectools.disallow_swap()
pysectools.disallow_core_dumps()

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

token = keyring.get_password('dev-vault', 'syslogd')
headers = {'X-Vault-Token': token}


def rotate_key(name):
    url = VAULT_URL + '/v1/transit/keys/{}/rotate'.format(name)

    try:
        r = requests.post(url, headers=headers)
        r.raise_for_status()
        return True
    except:
        return False


def sign_message(name, message):
    url = VAULT_URL + '/v1/transit/sign/{}'.format(name)
    m = message.encode()
    payload = {'input': b64encode(m).decode('ascii')}

    try:
        r = requests.post(url, headers=headers, json=payload)
        return r.json()['data']['signature']
    except:
        return None


for l in tail(LOG_FILE):
    l = l.strip()
    sleep(randint(0, 3))
    # Generate new key sort-of-randomly
    if not (round(time() % interval)):
        interval = randint(3, 5)
        if not rotate_key('syslogd'):
            print('Unable to rotate key!!! THIS IS INSECURE BUT I WILL KEEP GOING!!!')

    # Sign message and send
    sig = sign_message('syslogd', l)
    if sig is None:
        print('Unable to sign message!!!')
        break

    # Send message to server.
    # As you can see, there is no connect() call; UDP has no connections.
    # Instead, data is directly sent to the recipient via sendto().
    sock.sendto(bytes('{} SIGNATURE: {}\n'.format(
        l, sig), 'utf-8'), (HOST, PORT))
    received = str(sock.recv(1024), 'utf-8')

    print('Sent:     {}'.format(l))
    print('Received: {}'.format(received))
