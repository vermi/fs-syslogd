#!/usr/bin/env python
import socket
from base64 import b64encode
import keyring
import json
import requests

VAULT_URL = 'http://127.0.0.1:8200'

HOST, PORT = 'localhost', 514

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
    payload = { 'input': b64encode(m).decode('ascii') }

    try:
        r = requests.post(url, headers=headers, json=payload)
        return r.json()['data']['signature']
    except:
        return None


# As you can see, there is no connect() call; UDP has no connections.
# Instead, data is directly sent to the recipient via sendto().
with open('MOCK_DATA.txt') as fp:
    lines = fp.readlines()

for l in lines:
    l = l.strip()

    # Generate new key and sign message
    if rotate_key('syslogd'):
        sig = sign_message('syslogd', l)
        if sig is None:
            print('Unable to sign message!!!')
            break

        # Send message to server.
        sock.sendto(bytes('{} SIGNATURE: {}\n'.format(
            l, sig), 'utf-8'), (HOST, PORT))
        received = str(sock.recv(1024), 'utf-8')

        print('Sent:     {}'.format(l))
        print('Received: {}'.format(received))
    else:
        print('Unable to rotate key!!!')
        break
