from os import path, chmod
from Crypto.PublicKey import RSA

keydir = './keys/'

def genkey():
    key = RSA.generate(2048)
    with open(path.join(keydir, "private.key"), 'wb') as content_file:
        chmod("/tmp/private.key", 0o600)
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(path.join(keydir, "public.key"), 'wb') as content_file:
        content_file.write(pubkey.exportKey('PEM'))
