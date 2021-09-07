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

def attach_volume_to_server( nova_ep, token, project_id, server_id, volume_id, mount_point):
    payload= {"volumeAttachment": {"volumeId": volume_id}}
    response= requests.post("{}/v2.1/servers/{}/os-volume_attachments".format(nova_ep, server_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    logging.info("volume successfully attached to server") if response.ok else response.raise_for_status()

def search_volume(storage_ep, token, volume_name, project_id):
    response= send_get_request("{}/v3/{}/volumes".format(storage_ep, project_id), token)
    logging.debug(response.text)
    logging.info("successfully received volume list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "volumes", "name",volume_name, "id")

'''
Volume
'''

def get_volume_metadata(storage_ep, token, volume_id, project_id):
    response= send_get_request("{}/v3/{}/volumes/{}".format(storage_ep, project_id,volume_id), token)
    logging.debug(response.text)
    logging.info("successfully received volume list") if response.ok else response.raise_for_status()
    data= response.json()

    return data["volume"]["volume_image_metadata"]

def create_volume(storage_ep, token, project_id, volume_name, volume_size, image_id=None):
    payload= {"volume":{
                "size": volume_size,
                "project_id":project_id,
                "name": volume_name
                }
            }
    payload2={
        "imageRef": image_id
    }
    if image_id is not None:
        payload= {"volume":{**payload["volume"], **payload2}}
    response= requests.post("{}/v3/{}/volumes".format(storage_ep, project_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    logging.debug(response.text)
    logging.info("successfully created volume {}".format(volume_name)) if response.ok else response.raise_for_status()
    data= response.json()
    return data["volume"]["id"]
def upscale_voume(storage_ep, token, project_id, volume_id, volume_size):
    payload= {"os-extend": {"new_size": volume_size}}
    response= requests.post("{}/v3/{}/volumes/{}/action".format(storage_ep, project_id, volume_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    if(response.status_code ==202):
        logging.debug(response.text)
        #print(response.text)
        logging.info("successfully updated  volume") if response.ok else response.raise_for_status()
        return True
    else:
        return False
def migrate_voume(storage_ep, token, project_id, volume_id):
    payload={
    "os-migrate_volume": {
        "host":"r185-controller-2"
        }
    }
    #payload= {"os-extend": {"new_size": volume_size}}
    response= requests.post("{}/v3/{}/volumes/{}/action".format(storage_ep, project_id, volume_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    if(response.status_code ==202):
        logging.debug(response.text)
        #print(response.text)
        logging.info("successfully migrated  volume") if response.ok else response.raise_for_status()
        return True
    else:
        return False

def search_and_create_volume(storage_ep, token, project_id, volume_name, volume_size, image_id=None):
    volume_id= search_volume(storage_ep, token, volume_name, project_id)
    if volume_id is None:
        volume_id= create_volume(storage_ep, token, project_id, volume_name, volume_size, image_id )
    logging.debug("Volume id: "+volume_id)    
    return volume_id
def check_volume_status(storage_ep, token, volume_id, project_id):
    response = send_get_request("{}/v3/{}/volumes/{}".format(storage_ep, project_id, volume_id), token)
    data= response.json()
    return data["volume"]["status"] if response.ok else response.raise_for_status()

def create_volume_snapshot(storage_ep, token, project_id, volume_id, snapshot_name):
    payload= {"snapshot": {"volume_id": volume_id, 
    "force": "false", 
    "name": snapshot_name }
            }
    response= requests.post("{}/v3/{}/snapshots".format(storage_ep, project_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    #print(response.text)
    if(response.status_code == 202):
        logging.info("successfully created snapshot {}".format(snapshot_name)) if response.ok else response.raise_for_status()
        data= response.json()
        return data["snapshot"]["id"]
    else:
        return None

def replicate_volume(storage_ep, token, project_id, volume_name, source_id):
    payload= {"volume":{
                "source_volid": source_id,
                "name": volume_name
                
                }
            }
    response= requests.post("{}/v3/{}/volumes".format(storage_ep, project_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    #print(response.text)
    if(response.status_code== 202):
        logging.info("successfully replicated volume {}".format(volume_name)) if response.ok else response.raise_for_status()
        data= response.json()
        return data["volume"]["id"]
    else: 
        return None

def create_volume_from_snapshot(storage_ep, token, project_id, volume_name, snapshot_id):

    payload= {"volume":{
                "snapshot_id": snapshot_id,
                "name": volume_name
                }
            }
    response= requests.post("{}/v3/{}/volumes".format(storage_ep, project_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    #print(response.text)
    if(response.status_code== 202):
        logging.info("successfully created volume {}".format(volume_name)) if response.ok else response.raise_for_status()
        data= response.json()
        return data["volume"]["id"]
    else: 
        return None
