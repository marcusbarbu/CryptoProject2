# CryptoProject2

## Install

## How to Run
### Server
python server.py

python server.py --host \<host\> --port \<port\>

Host defaults to 0.0.0.0

Port defaults to 8000
### Client
python client.py

python client.py --host \<host\> --port \<port\>

python client.py --host \<host\> --port \<port\> --pass \<passphrase\>

Host defaults to 0.0.0.0

Port defaults to 8000

If pass is not specified, client is assigned one (printed to screen)

Two clients need to agree on a passphrase to connect to a room
