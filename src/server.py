# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# ML Libraries
import tensorflow as tf
import tensorflow_hub as hub

# Utilities
import time
import json
import base64
import os
import socket
import subprocess
import traceback
import argparse
import logging
from cryptography.fernet import Fernet

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
debug = False
KMS_PROXY_PORT = "8001"
NUM_BYTES_FOR_LEN = 4


class TFObject:
    def __init__(self, name, score, detection_box):
        self.name = name
        self.score = score
        self.detection_box = detection_box


def load_img(image_read):
    image_64_encode = base64.urlsafe_b64encode(image_read)
    img = tf.io.decode_base64(image_64_encode)
    img = tf.image.decode_jpeg(img, channels=3)
    logging.debug('img loaded successfully')
    return img


def run_detector(detector, file_contents):
    img = load_img(file_contents)

    converted_img = tf.image.convert_image_dtype(img, tf.float32)[tf.newaxis, ...]

    start_time = time.time()
    result = detector(converted_img)
    end_time = time.time()

    result = {key: value.numpy() for key, value in result.items()}

    inference_time = end_time - start_time
    logging.info(f"Inference time: {inference_time}")
    return result


def decrypt_cipher(access, secret, token, ciphertext, region):
    """
    use KMS Tool Enclave Cli to decrypt cipher text
    """

    proc = subprocess.Popen(
        [
            "/app/kmstool_enclave_cli",
            "decrypt",
            "--region", region,
            "--proxy-port", KMS_PROXY_PORT,
            "--aws-access-key-id", access,
            "--aws-secret-access-key", secret,
            "--aws-session-token", token,
            "--ciphertext", ciphertext,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    ret = proc.communicate()
    if ret[0]:
        ret0 = proc.communicate()[0].decode()
        plaintext = ret0.split(":")[1]
        return plaintext
    else:
        return "KMS Error. Decryption Failed."


def get_plaintext(payload):
    """
    prepare inputs and invoke decrypt function
    """

    # take all data from client
    access = payload['access_key_id']
    secret = payload['secret_access_key']
    token = payload['token']
    encrypted_file = payload['encrypted_file']
    region = payload['region']

    file_contents = base64.b64decode(encrypted_file.encode('utf-8'))
    # The first NUM_BYTES_FOR_LEN tells us the length of the encrypted data key
    # Bytes after that represent the encrypted file data
    data_key_encrypted_len = int.from_bytes(file_contents[:NUM_BYTES_FOR_LEN], byteorder="big") + NUM_BYTES_FOR_LEN
    data_key_encrypted = file_contents[NUM_BYTES_FOR_LEN:data_key_encrypted_len]

    local_data_key_encrypted = base64.b64encode(data_key_encrypted)
    local_data_key_encrypted_string = local_data_key_encrypted.decode('utf-8')

    # Decrypt the data key before using it
    data_key_plaintext = decrypt_cipher(access, secret, token, local_data_key_encrypted_string, region)

    f = Fernet(data_key_plaintext)
    file_contents_decrypted = f.decrypt(file_contents[data_key_encrypted_len:])

    return data_key_plaintext, file_contents_decrypted


def receive_all(sock):
    buffer_size = 4096  # 4 KiB
    data = b''
    while True:
        part = sock.recv(buffer_size)
        data += part
        if len(part) < buffer_size:
            # either 0 or end of data
            break
    return data


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Whether to run in debug mode")

    return parser.parse_args()


def main():
    args = parse_args()
    global debug
    debug = args.debug
    inference_results: dict

    # Default to Production settings
    socket_address = socket.AF_VSOCK
    port = 5000
    cid = socket.VMADDR_CID_ANY
    if debug:
        # For Debugging
        logging.basicConfig(level=logging.DEBUG)
        socket_address = socket.AF_INET
        cid = '127.0.0.1'

    s = socket.socket(socket_address, socket.SOCK_STREAM)
    s.bind((cid, port))
    s.listen()
    logging.info(f"Started server on port {port} and cid {cid} and pid {os.getpid()}")

    # module_handle = "/app/models/openimages_v4_ssd_mobilenet_v2_1"  # 10 seconds
    module_handle = "/app/models/faster_rcnn_openimages_v4_inception_resnet_v2_1"  # 50 seconds
    detector = hub.load(module_handle).signatures['default']
    logging.info('Successfully loaded ML model')

    # Print Tensorflow version
    logging.info(f"Tensorflow version: {tf.__version__}")

    # Check available devices.
    logical_devices = tf.config.list_logical_devices()
    logging.info(f"The following logical devices are available: {logical_devices}")
    physical_devices = tf.config.list_physical_devices()
    logging.info(f"The following physical devices are available: {physical_devices}")

    # Check available GPU devices.
    logical_gpu = tf.config.list_logical_devices('GPU')
    logging.info(f"The following logical GPU's are available: {logical_gpu}")
    physical_gpu = tf.config.list_physical_devices('GPU')
    logging.info(f"The following physical GPU's are available: {physical_gpu}")

    while True:
        print('Waiting to accept...')
        c, address = s.accept()
        payload = receive_all(c)

        min_score_pct = 50
        objects_detected = []
        response = {}

        try:
            payload_decoded = json.loads(payload.decode())

            decrypt_response, file_contents_decrypted = get_plaintext(payload_decoded)

            if decrypt_response == "KMS Error. Decryption Failed.":
                response["error"] = decrypt_response

            inference_results = run_detector(detector, file_contents_decrypted)

            for index, entity in enumerate(inference_results['detection_class_entities']):
                score = int(100 * inference_results['detection_scores'][index])
                detection_box = inference_results['detection_boxes'][index].tolist()
                entity_name = entity.decode("ascii")
                if score < min_score_pct:
                    continue
                objects_detected.append(TFObject(entity_name, score, detection_box))
                logging.info(f"index: {index} Entity: {entity_name} Score: {score} Detection_Box: {detection_box}")

            response["objects_detected"] = objects_detected
            json_response = json.dumps(response, default=vars)
            logging.info(json_response)

            c.send(str.encode(json_response))
            c.close()
        except Exception as e:
            c.close()
            logging.error(f'Exception raised: {e}')
            traceback.print_exc()


if __name__ == '__main__':
    main()
