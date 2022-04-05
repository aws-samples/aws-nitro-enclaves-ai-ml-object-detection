# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Summary
# This python program takes in as input an image and a KMS key to generate an encrypted image using envelope encryption.
# As an optional input, it takes an aws profile name
# The program will then proceed to encrypt the image using envelope encryption and
#   store both the encrypted image and the encrypted data key into an output folder.

# Usage Example
# cd ./src
# python3 ./envelope-encryption/encryptor.py \
# --filePath ./images/ait-show.jpg --cmkId alias/EnclaveKMSkey --profile AWS_CLI_Profile_Name --region ca-central-1

"""
 Input:
    --filePath ./images/air-show.jpg
    --cmkId alias/EnclaveKMSkey
    --region ca-central-1
    (optional) --profile AWS_CLI_Profile_Name
"""

import argparse
import base64

import boto3
import logging

from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
NUM_BYTES_FOR_LEN = 4


def encrypt_file(filename, cmk_id, profile, region):
    """Encrypt a file using an AWS KMS CMK

    A data key is generated and associated with the CMK.
    The encrypted data key is saved with the encrypted file. This enables the
    file to be decrypted at any time in the future and by any program that
    has the credentials to decrypt the data key.
    The encrypted file is saved to <filename>.encrypted
    Limitation: The contents of filename must fit in memory.

    :param filename: File to encrypt
    :param cmk_id: AWS KMS CMK ID or ARN
    :return: True if file was encrypted. Otherwise, False.
    """

    # Read the entire file into memory
    try:
        with open(filename, 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        logging.error(e)
        return False

    # Generate a data key associated with the CMK
    # The data key is used to encrypt the file. Each file can use its own
    # data key or data keys can be shared among files.
    # Specify either the CMK ID or ARN
    data_key_encrypted, data_key_plaintext = create_data_key(cmk_id, profile=profile, region=region)

    if data_key_encrypted is None:
        return False
    logging.info('Created new AWS KMS data key')

    # Store data key encrypted on disk
    with open(filename + '.data_key.encrypted', 'wb') as data_key_file_encrypted:
        data_key_file_encrypted.write(data_key_encrypted)

    # Encrypt the file
    f = Fernet(data_key_plaintext)
    file_contents_encrypted = f.encrypt(file_contents)

    # Write the encrypted data key and encrypted file contents together
    try:
        with open(filename + '.encrypted', 'wb') as file_encrypted:
            file_encrypted.write(len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN,
                                                                  byteorder='big'))
            file_encrypted.write(data_key_encrypted)
            file_encrypted.write(file_contents_encrypted)
    except IOError as e:
        logging.error(e)
        return False

    # For the highest security, the data_key_plaintext value should be wiped
    # from memory. Unfortunately, this is not possible in Python. However,
    # storing the value in a local variable makes it available for garbage
    # collection.
    return True


def create_data_key(cmk_id, key_spec='AES_256', region='', profile=None):
    """Generate a data key to use when encrypting and decrypting data

    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
        'AES_128': Generate a 128-bit symmetric key
        'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
        EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
        PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """

    # Create data key
    if profile is None:
        kms_client = boto3.client('kms', region_name=region)
    else:
        aws_session = boto3.Session(profile_name=profile)
        kms_client = aws_session.client('kms', region_name=region)

    try:
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
    except ClientError as e:
        logging.error(e)
        return None, None

    # Return the encrypted and plaintext data key
    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filePath", required=True, help="File or image to encrypt")
    parser.add_argument("--cmkId", required=True, help="CMK ID to use to encrypt the file")
    parser.add_argument("--region", required=True, help="Region your KMS CMK is in")
    parser.add_argument("--profile", required=False, help="Select the profile to use to make SDK call")

    return parser.parse_args()


def main():
    # Retrieve Command Line Arguments
    args = parse_args()
    print('Args received:', args)
    imagePath = args.filePath
    cmkId = args.cmkId
    profile = args.profile
    region = args.region

    fileEncrypted = encrypt_file(imagePath, cmkId, profile, region)
    print("file encrypted?", fileEncrypted)

    exit()


if __name__ == '__main__':
    main()
