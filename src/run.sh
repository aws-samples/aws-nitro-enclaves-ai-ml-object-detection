# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/bin/sh

# Assign an IP address to local loopback 

ip addr add 127.0.0.1/32 dev lo

ip link set dev lo up

touch /app/libnsm.so

# Start the server running inside the enclave
python3 /app/server.py





