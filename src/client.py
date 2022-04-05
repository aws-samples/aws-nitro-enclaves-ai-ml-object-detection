# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Summary
# This python program takes in as input an encrypted image and passes it on to the enclave for object detection

# Usage Example
# cd ./src
# python3 client-uc4.py \
# --filePath ./images/air-show.jpg.encrypted --debug

"""
 Input:
    --filePath ./images/air-show.jpg.encrypted
    (optional) --debug
 Output:
    Prints JSON response from enclave server of the objects detected and their score.
"""

import json
import base64
import socket
import subprocess
import argparse
import requests

debug = False
region, account = '', ''


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filePath", required=True, help="Path of the image file")
    parser.add_argument("--debug", action="store_true", help="Whether to run in debug mode")

    return parser.parse_args()


def get_identity_document():
    """
    Get identity document for current EC2 Host
    """
    r = requests.get(
        "http://169.254.169.254/latest/dynamic/instance-identity/document")
    return r


def get_region(identity):
    """
    Get region of current instance identity
    """
    global region
    region = identity.json()["region"]
    return region


def get_account(identity):
    """
    Get account of current instance identity
    """
    global account
    account = identity.json()["accountId"]
    return account


def set_identity():
    if debug:
        return 'Debug-Region', 'Debug Account'
    identity = get_identity_document()
    global region
    region = get_region(identity)
    global account
    account = get_account(identity)
    return region, account


def prepare_server_request(encrypted_file_base64):
    """
    Get the AWS credential from EC2 instance metadata
    """
    if debug:
        response = {
            'AccessKeyId': 'Debug',
            'SecretAccessKey': 'Debug',
            'Token': 'Debug'
        }
    else:
        r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        instance_profile_name = r.text
        r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s" % instance_profile_name)
        response = r.json()

    credential = {
        'access_key_id': response['AccessKeyId'],
        'secret_access_key': response['SecretAccessKey'],
        'token': response['Token'],
        'region': region,
        'encrypted_file': encrypted_file_base64
    }
    
    return credential


def get_cid():
    """
    Determine CID of Current Enclave
    """
    proc = subprocess.Popen(["/bin/nitro-cli", "describe-enclaves"],
                            stdout=subprocess.PIPE)
    output = json.loads(proc.communicate()[0].decode())
    enclave_cid = output[0]["EnclaveCID"]
    return enclave_cid


def parse_input(values):
    arr = values.read().splitlines()
    values.close()
    return arr


def read_file(path):
    with open(path, "rb") as file:
        file_contents = file.read()
    return file_contents


def main():
    args = parse_args()
    image_path = args.filePath
    global debug
    debug = args.debug

    global region
    global account
    region, account = set_identity()

    # Read file from File Path
    encrypted_file = read_file(image_path)

    # Convert file to base64 prior to sending to server.py
    encrypted_file_base64 = base64.b64encode(encrypted_file)
    encrypted_file_base64_string = encrypted_file_base64.decode('utf-8')

    # Construct JSON doc
    server_json_payload = prepare_server_request(encrypted_file_base64_string)

    # Send data to server
    # The port should match the server running in enclave
    port = 5000
    # Create a vsock socket object and Connect to the server
    if debug:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', port))
    else:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        # Get CID from command line parameter
        cid = get_cid()
        s.connect((cid, port))

    # Send AWS credential to the server running in enclave
    s.send(str.encode(json.dumps(server_json_payload)))

    # receive data from the server
    response = s.recv(4096).decode()

    # print response
    print(response)

    # close the connection
    s.close()
    exit()


if __name__ == '__main__':
    main()
