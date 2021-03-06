import requests
import json
import os
import time
import logging
import paramiko

def send_post_request(api_url, token, payload, header='application/json'):
    """ send post request."""
    try:
        return requests.post(api_url, headers={'content-type':header, 'OpenStack-API-Version': 'compute 2.74', 'X-Auth-Token': token}, data=json.dumps(payload))
    except Exception as e:
       logging.error( "request processing failure")
       logging.exception(e)
def send_get_request(api_url, token, header="application/json"):
    """ send get request."""
    try:
        return requests.get(api_url, headers= {'content-type': header, 'X-Auth-Token': token}) 
    except Exception as e:
        logging.error( "request processing failure ", stack_info=True)
        logging.exception(e)

def parse_json_to_search_resource(data, resource_name, resource_key, resource_value, return_key):
    """get value from API response e.g Id of objects."""
    #load data as json
    data= data.json()
    #search for key
    for res in (data[resource_name]):
        if resource_value in res[resource_key]:
            logging.debug("{} already exists".format(resource_value))
            return res[return_key]
            break
    else:
        logging.debug("{} does not exist".format(resource_value))

def get_authentication_token(keystone_ep, username, password):
    """get authentication token from keystone."""
    logging.info("Getting authentication token")
    payload= {"auth": 
                {"identity": 
                    {"methods": ["password"],"password":
                      {"user": 
                        {"name": username, 
                            "domain": {"name": "Default"},"password": password} }},
                         "scope": {"project": {"domain": {"id": "default"},"name": "admin"}
                    }
                }
            }
    logging.debug("authenticating user")
    response= send_post_request("{}/v3/auth/tokens".format(keystone_ep), None, payload)
    logging.debug("successfully authenticated") if response.ok else response.raise_for_status()
    logging.debug(response.text)
    return response.headers.get('X-Subject-Token')

def find_admin_project_id(keystone_ep, token):
    """find project id of admin user."""
    response= send_get_request("{}/v3/projects".format(keystone_ep), token)
    logging.debug("successfully received project details") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "projects", "name", "admin", "id")
