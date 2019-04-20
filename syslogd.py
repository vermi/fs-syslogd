#!/usr/bin/env python

from base64 import b64encode
from syslog_rfc5424_parser import SyslogMessage, ParseError
import keyring
import json
from tinydb import TinyDB
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import requests

HOST, PORT = '0.0.0.0', 514
VAULT_URL = 'http://127.0.0.1:8200'

# Basic syslog functionality taken from @marcelom on github
# https://gist.github.com/marcelom/4218010

db = TinyDB('syslog.json')
token = keyring.get_password('dev-vault', 'syslogd')
headers = {'X-Vault-Token': token}


def verify_sig(name, msg, sig):
    url = VAULT_URL + '/v1/transit/verify/{}'.format(name)
    m = msg.encode()
    payload = {'input': b64encode(m).decode('ascii'), 'signature': sig}

    try:
        r = requests.post(url, headers=headers, json=payload)
        return r.json()['data']['valid']
    except:
        return False


class SyslogUDPHandler(DatagramProtocol):

    def datagramReceived(self, data, addr):
        raw_message = bytes.decode(data).rstrip()
        self.transport.write("recv'd\n".encode(), addr)
        verified = True

        if 'SIGNATURE:' in raw_message:
            raw_message, sig = raw_message.split(' SIGNATURE: ')
            verified = verify_sig('syslogd', raw_message, sig)

        if (verified):
            message = SyslogMessage.parse(raw_message)
            msgDict = message.as_dict()
            print(msgDict)
            msgDict['raw_msg'] = raw_message
            msgDict['sig'] = sig
            db.insert(msgDict)
        else:
            print('Unable to verify signature.\n>>> ', raw_message)


if __name__ == '__main__':
    try:
        reactor.listenUDP(514, SyslogUDPHandler())
        reactor.run()
    except (IOError, SystemExit, ParseError):
        raise
    except KeyboardInterrupt:
        print('User initiated shutdown.')
