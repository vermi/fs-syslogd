# Forward-Secure Syslog Using Commercial Tools

## System Requirements
For running the vault server, make sure you have Docker installed

## Installation and Setup (Devel)

1. Clone this repo.
2. `git submodule update --init`
3. `docker build -f docker-vault/0.X/Dockerfile -t vault:latest .`
4. `pip install -r requirements.txt`
5. `vault-files/vault-setup.sh`
6. Modify syslogd.py and sender.py to use the actual vault server IP (currently set to localhost)
7. On the log server, run `syslogd.py`
8. Modify sender.py to point to the file you want to monitor for log entries
9. On the client, run `sender.py`
10. ???
11. Profit

## Installation and Setup (Prod)

!!! Not recommended.
Use your brain and figure it out (for now).
