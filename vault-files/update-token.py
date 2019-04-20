#!/usr/bin/env python

import keyring

token = open(0).read().rstrip()
keyring.get_keyring()
keyring.set_password('dev-vault', 'syslogd', token)
print('Token successfully set to {}'.format(
    keyring.get_password('dev-vault', 'syslogd')))
