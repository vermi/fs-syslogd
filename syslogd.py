#!/usr/bin/env python

LOG_FILE = 'youlogfile.log'
HOST, PORT = "0.0.0.0", 514

import socketserver
from tinydb import TinyDB
from syslog_rfc5424_parser import SyslogMessage, ParseError
import json
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from base64 import b64decode

# Basic syslog functionality taken from @marcelom on github
# https://gist.github.com/marcelom/4218010

db = TinyDB('syslog.json')


def verifyMessage(message, signature):
    digest = SHA256.new()
    digest.update(message.encode('utf-8'))

    with open('public_key.pem') as pub_fp:
        pub_key = pub_fp.read()
        verifier = PKCS1_v1_5.new(RSA.importKey(pub_key))

    return verifier.verify(digest, b64decode(signature))


class SyslogUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        raw_message = bytes.decode(data)
        verified = True

        if 'SIGNATURE:' in raw_message:
            raw_message, sig = raw_message.split(' SIGNATURE: ')
            verified = verifyMessage(raw_message, sig)

        if (verified):
            message = SyslogMessage.parse(raw_message)
            msgDict = message.as_dict()
            jsonMsg = json.dumps(msgDict)
            print(jsonMsg)
            msgDict['raw_msg'] = raw_message
            msgDict['sig'] = sig
            db.insert(msgDict)
            socket.sendto(jsonMsg.encode(), self.client_address)
        else:
            socket.sendto(b'Unable to verify signature.', self.client_address)


if __name__ == "__main__":
    try:
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            server.serve_forever()
    except (IOError, SystemExit, ParseError):
        raise
    except KeyboardInterrupt:
        print("User initiated shutdown.")
