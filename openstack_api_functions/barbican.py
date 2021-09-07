import requests
import json
import os
import time
import logging
import paramiko

def send_get_request(api_url, token, header="application/json"):
    try:
        return requests.get(api_url, headers= {'content-type': header, 'X-Auth-Token': token}) 
    except Exception as e:
        logging.error( "request processing failure ", stack_info=True)
        logging.exception(e)

def send_put_request(api_url, token, payload, header='application/json'):
    try:
       return requests.put(api_url, headers= {'content-type':header, 'X-Auth-Token': token}, data=json.dumps(payload))
    except Exception as e:
        logging.error( "request processing failure ", stack_info=True)
        logging.exception(e)

def send_post_request(api_url, token, payload, header='application/json'):
    try:
        #'OpenStack-API-Version': 'compute 2.74',
        return requests.post(api_url, headers= {'content-type':header, 'OpenStack-API-Version': 'compute 2.74', 'X-Auth-Token': token}, data=json.dumps(payload))
    except Exception as e:
       logging.error( "request processing failure ", stack_info=True)
       logging.exception(e)
def send_delete_request(api_url, token, header='application/json' ):
    try:
        requests.delete(api_url, headers= {'content-type':header, 'X-Auth-Token': token})
        time.sleep(5)
    except Exception as e:
       logging.error( "request processing failure ", stack_info=True)
       logging.exception(e)
def delete_resource(api_url, token):
    send_delete_request(api_url, token)


def parse_json_to_search_resource(data, resource_name, resource_key, resource_value, return_key):
    data= data.json()
    for res in (data[resource_name]):
        if resource_value in res[resource_key]:
            logging.warning("{} already exists".format(resource_value))
            return res[return_key]
            break
    else:
        logging.info("{} does not exist".format(resource_value))

#Barbican
def add_key_to_store(barbican_ep, token, key):
    payload= {"name": "signing-cert", "algorithm": "RSA", "mode": "cbc", "bit_length": 256,
                "secret_type": "certificate", 
                "payload": key,
                "payload_content_type": "application/octet-stream", 
                "payload_content_encoding": "base64"}

    response= send_post_request("{}/v1/secrets/".format(barbican_ep), token, payload)
    key_id= str(response.text)
    key_id= key_id.split("/")
    key_id= key_id[-1]
    key_id= key_id.strip('"}')
    
    print("Key is: "+key_id)
    logging.info("successfully add key to barbican") if response.ok else response.raise_for_status()
    return key_id
def add_symmetric_key_to_store(barbican_ep, token):
    payload= {"type": "key", "meta": {"name": "swift_key", "algorithm": "aes", "bit_length": 256, "payload_content_type": "application/octet-stream", "mode": "ctr"}}


    response= send_post_request("{}/v1/orders/".format(barbican_ep), token, payload)
    key_id= str(response.text)
    key_id= key_id.split("/")
    key_id= key_id[-1]
    key_id= key_id.strip('"}')
    
    print("Key is: "+key_id)
    logging.info("successfully add key to barbican") if response.ok else response.raise_for_status()
    return key_id

def create_secret(barbican_ep, token, name, payload):
    key_id=""
    payload= {"name": name, "algorithm": "aes", "mode": "cbc", "bit_length": 256, "secret_type": "opaque" ,
                "payload": payload, 
                "payload_content_type": "text/plain"}

    response= send_post_request("{}/v1/secrets/".format(barbican_ep), token, payload)
    logging.debug(response.text)
    print(response.status_code)
    if (response.status_code==201):
        key_id= str(response.text)
        key_id= key_id.split("/")
        key_id= key_id[-1]
        key_id= key_id.strip('"}')
        logging.info("successfully add secret to barbican") if response.ok else response.raise_for_status()
    else:
        logging.info("failed to create secret")
    return key_id
def update_secret(barbican_ep, token, url, data):
    payload= {"data"}
    #payload= bytes("data", 'utf-8')
    #payload= {payload}
    #print(payload)
    response=""
    #payload= {"payload_content_type": "text/plain"}
    try:
       response= requests.put("{}/v1/secrets/".format(barbican_ep), headers= {"Accept":"text/plain", 'X-Auth-Token': token}, data=json.dumps(payload))
    except Exception as e:
        logging.error( "request processing failure ", stack_info=True)
        logging.exception(e)
    #response= send_put_request("{}/v1/secrets/".format(barbican_ep), token, payload)
    print(response)
    if (response.status_code==201):
        logging.info("successfully updated secret to barbican") if response.ok else response.raise_for_status()
        return True
    else:
        logging.info("failed to update secret")
        return False
def get_secret(barbican_ep, token, secret_id):
    response= send_get_request("{}/v1/secrets/{}".format(barbican_ep,secret_id), token)
    logging.debug(response.text)
    if response.status_code==200:
        return response.text
    else:
        return None 
def get_key(barbican_ep, token, secret_id):
    response= send_get_request("{}/v1/orders/{}".format(barbican_ep,secret_id), token)
    logging.debug(response.text)
    if response.status_code==200:
        return response.text
    else:
        return None 
def get_payload(barbican_ep, token, secret_id):
    response= send_get_request("{}/v1/secrets/{}/payload".format(barbican_ep,secret_id), token)
    logging.debug(response.text)
    return response.text
