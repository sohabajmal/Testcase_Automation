import logging
import paramiko
import os
import time
import math
import pexpect
from subprocess import Popen, PIPE
import subprocess
from openstack_api_functions.barbican import *

def create_ssl_certificate(settings):
    logging.info("Generating Certificate")
    os.popen("openssl genrsa -out ~/testcase_private_key.pem 1024")
    time.sleep(2)
    os.popen("openssl rsa -pubout -in ~/testcase_private_key.pem -out ~/testcase_public_key.pem")
    time.sleep(2)
    proc = subprocess.Popen("openssl req -new -key ~/testcase_private_key.pem -out ~/testcase_cert_request.csr", shell=True, stdin=PIPE)
    time.sleep(2)
    s= "aa\naa\naa\naa\naa\naa\naa\naaaa\naaaa\n"
    s= s.encode('utf-8')
    proc.communicate(s)
    time.sleep(10)    
    os.popen("openssl x509 -req -days 14 -in ~/testcase_cert_request.csr -signkey ~/testcase_private_key.pem -out ~/x509_testcase_signing_cert.crt")
    time.sleep(4)
    private_key=os.popen("base64 ~/x509_testcase_signing_cert.crt") 
    time.sleep(4)
    private_key= private_key.read()
    return private_key
def sign_image(settings):
    #Sign image with Private Key
    logging.info("Signing image with private key")
    command= "openssl dgst -sha256 -sign ~/testcase_private_key.pem -sigopt rsa_padding_mode:pss -out ~/testcase_cirros-0.4.0.signature {}".format(os.path.expanduser(settings["image_file"]))
    os.popen(command)
    time.sleep(4)
    os.popen("base64 -w 0 ~/testcase_cirros-0.4.0.signature  > ~/testcase_cirros-0.4.0.signature.b64")
    time.sleep(4)
    image_signature= os.popen("cat ~/testcase_cirros-0.4.0.signature.b64")
    image_signature=image_signature.read()
    print(image_signature)
    return image_signature

def create_barbican_secret(barbican_ep, token):
    secret_id= create_secret(barbican_ep, token, "testcae_secret", "test_case payload")
    return secret_id

#def update_barbican_sercret():


#def delete_barbican_secret():





