
#Load Balancer
def create_loadbalancer(loadbal_ep, token, loadbalancer_name, subnet_id):
    #create loadbalancer
    payload= {
        "loadbalancer": {
            "name": loadbalancer_name,
            "vip_subnet_id": subnet_id,
            "admin_state_up": "true"
            }
        }

    response= send_post_request('{}/v2.0/lbaas/loadbalancers'.format(loadbal_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created loadbalancer {}".format(loadbalancer_name)) if response.ok else response.raise_for_status()
    data=response.json()
    return data['loadbalancer']['id']
def search_loadbalancer(loadbal_ep, token, loadbalancer_name):
    #get list of loadbalancer
    response= send_get_request("{}/v2.0/lbaas/loadbalancers".format(loadbal_ep), token)
    logging.info("successfully received loadbalancer list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "loadbalancers", "name", loadbalancer_name, "id")

def check_loadbalancer_status(loadbal_ep, token, loadbalancer_id):
    response = send_get_request("{}/v2.0/lbaas/loadbalancers/{}".format(loadbal_ep, loadbalancer_id), token)
    logging.debug(response.text)
    data= response.json()
    return data["loadbalancer"]["provisioning_status"] if response.ok else response.raise_for_status()
def check_loadbalancer_vipport(loadbal_ep, token, loadbalancer_id):
    response = send_get_request("{}/v2.0/lbaas/loadbalancers/{}".format(loadbal_ep, loadbalancer_id), token)
    logging.debug(response.text)
    data= response.json()
    return data["loadbalancer"]["vip_port_id"] if response.ok else response.raise_for_status()

def search_and_create_loadbalancer(loadbal_ep, token, loadbalancer_name, subnet_id):
    loadbalancer_id= search_loadbalancer(loadbal_ep, token, loadbalancer_name)    
    if loadbalancer_id is None:
        loadbalancer_id =create_loadbalancer(loadbal_ep, token, loadbalancer_name, subnet_id )  
    logging.debug("loadbalancer id is: {}".format(loadbalancer_id))
    return loadbalancer_id
#Listener
def create_listener(loadbal_ep, token, listener_name, loadbalancerid, protocol, protocol_port):
    #create loadbalancer
    payload= {
        "listener": {
            "name": listener_name,
            "loadbalancer_id": loadbalancerid,
            "protocol": protocol, 
            "protocol_port": protocol_port,
            "admin_state_up": "true"
            }
        }
    try:
        response= send_post_request('{}/v2.0/lbaas/listeners'.format(loadbal_ep), token, payload)
        logging.debug(response.text)
        logging.info("successfully created loadbalancer {}".format(listener_name)) if response.ok else response.raise_for_status()
        data=response.json()
        return data['listener']['id']
    except:
        return "failed"
def search_listener(loadbal_ep, token, listener_name):
    #get list of loadbalancer
    response= send_get_request("{}/v2.0/lbaas/listeners".format(loadbal_ep), token)
    logging.info("successfully received listener list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "listeners", "name", listener_name, "id")

def check_listener_status(loadbal_ep, token, listener_id):
    response = send_get_request("{}/v2.0/lbaas/listeners/{}".format(loadbal_ep, listener_id), token)
    data= response.json()
    return data["listener"]["provisioning_status"] if response.ok else response.raise_for_status()
def search_and_create_listener(loadbal_ep, token, listener_name, loadbalancer_id, protocol, protocol_port):
    listener_id= search_listener(loadbal_ep, token, listener_name)    
    if listener_id is None:
        listener_id =create_listener(loadbal_ep, token, listener_name, loadbalancer_id, protocol, protocol_port)  
    logging.debug("listener id is: {}".format(listener_id))
    return listener_id
#Pool
def create_pool(loadbal_ep, token, pool_name, listenerid, loadbalancerid, protocol, algorithm, session=None):
    #create loadbalancer
    payload= {
        "pool": {
            "name": pool_name,
            "protocol": protocol, 
            "listener_id":listenerid,
            "lb_algorithm": algorithm,
            "protocol": protocol,
            "admin_state_up": "true"
            }
        }
    payload_session= {"session_persistence": 
        {"type": "APP_COOKIE", 
        "cookie_name": "PHPSESSIONID"}
        }
    if session is not None:
        payload= {"pool":{**payload["pool"], **payload_session}}
    try:
        response= send_post_request('{}/v2.0/lbaas/pools'.format(loadbal_ep), token, payload)
        logging.debug(response.text)
        logging.info("successfully created loadbalancer {}".format(pool_name)) if response.ok else response.raise_for_status()
        data=response.json()
        return data['pool']['id']
    except:
        return "failed"
def search_pool(loadbal_ep, token, listener_name):
    #get list of loadbalancer
    response= send_get_request("{}/v2.0/lbaas/pools".format(loadbal_ep), token)
    logging.info("successfully received listener list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "pools", "name", listener_name, "id")

def check_pool_status(loadbal_ep, token, listener_id):
    response = send_get_request("{}/v2.0/lbaas/pools/{}".format(loadbal_ep, listener_id), token)
    logging.debug(response.text)
    data= response.json()
    return data["pool"]["provisioning_status"] if response.ok else response.raise_for_status()
def search_and_create_pool(loadbal_ep, token, pool_name, listener_id, loadbalancerid, protocol, algorithm):
    pool_id= search_pool(loadbal_ep, token, pool_name)    
    if pool_id is None:
        pool_id =create_pool(loadbal_ep, token,  pool_name, listener_id, loadbalancerid, protocol, algorithm)  
    logging.debug("listener id is: {}".format(listener_id))
    return pool_id
def add_instance_to_pool(loadbal_ep, token, pool_id, ip, subnet_id, protocol_port ):
    payload= {
        "member": {
            "address": ip,
            "subnet_id": subnet_id,
            "protocol_port": protocol_port,
            }
        }
    response= send_post_request("{}/v2.0/lbaas/pools/{}/members".format(loadbal_ep, pool_id), token, payload)
    logging.info("successfully added instance to pool") if response.ok else response.raise_for_status()

def health_monitor_pool(loadbal_ep, token, pool_id, type):
    payload= {
        "healthmonitor": {
            "pool_id": pool_id,
             "delay": 5, 
             "timeout": 10, 
             "max_retries": 4, 
             "type": type, 
             "admin_state_up": "true",
             #"url_path": "/healthcheck"
            }
        }
    try:
        response= send_post_request("{}/v2.0/lbaas/healthmonitors".format(loadbal_ep), token, payload)
        logging.info("successfully added health monitor to pool") if response.ok else response.raise_for_status()
    except:
        return "failed"
def create_loadbalancer_floatingip(neutron_ep, token, network_id ):
    payload= {
        "floatingip": {
            "floating_network_id": network_id
            }
        }
    response= send_post_request("{}//v2.0/floatingips".format(neutron_ep), token, payload)
    logging.debug(response.text)
    data=response.json()
    logging.info("successfully created floating ip for load balancer") if response.ok else response.raise_for_status()
    return data["floatingip"]["id"], data["floatingip"]["floating_ip_address"]
def assign_lb_floatingip(neutron_ep, token, port_id, floatingip_id ):
    payload= {
        "floatingip": {
            "port_id": port_id
            }
        }
    response= send_put_request("{}/v2.0/floatingips/{}".format(neutron_ep, floatingip_id), token, payload)
    logging.debug(response.text)
    logging.info("successfully assigned floating ip to vip port") if response.ok else response.raise_for_status()
def get_pool_member(loadbal_ep, token, pool_id):
    response = send_get_request("{}/v2.0/lbaas/pools/{}".format(loadbal_ep, pool_id), token)
    logging.debug(response.text)
    data= response.json()
    logging.info("successfully assigned member of pool") if response.ok else response.raise_for_status()
    return data["pool"]["members"][0]["id"] 
def down_pool_member(loadbal_ep, token, pool_id, member_id ):
    payload= {
        "member": {
           "admin_state_up": 'false'
            }
        }
    response= send_put_request("{}/v2.0/lbaas/pools/{}/members/{}".format(loadbal_ep, pool_id, member_id), token, payload)
    time.sleep(5)
    logging.debug(response.text)
    logging.info("successfully down a member in pool") if response.ok else response.raise_for_status()
def up_pool_member(loadbal_ep, token, pool_id, member_id ):
    time.sleep(5)
    payload= {
        "member": {
           "admin_state_up": 'true'
            }
        }
    response= send_put_request("{}/v2.0/lbaas/pools/{}/members/{}".format(loadbal_ep, pool_id, member_id), token, payload)
    logging.debug(response.text)
    time.sleep(5)
    logging.info("successfully up a member in pool") if response.ok else response.raise_for_status()
def disable_loadbalancer(loadbal_ep, token, loadbalancer_id ):
    payload= {
        "loadbalancer": {
           "admin_state_up": 'false'
            }
        }
    response= send_put_request("{}/v2.0/loadbalancers/{}".format(loadbal_ep, loadbalancer_id), token, payload)
    time.sleep(30)
    logging.debug(response.text)
    logging.info("successfully disabled loadbalancer") if response.ok else response.raise_for_status()
def enable_loadbalancer(loadbal_ep, token, loadbalancer_id ):
    payload= {
        "loadbalancer": {
           "admin_state_up": 'true'
            }
        }
    response= send_put_request("{}/v2.0/loadbalancers/{}".format(loadbal_ep, loadbalancer_id), token, payload)
    time.sleep(30)
    logging.debug(response.text)
    logging.info("successfully disabled loadbalancer") if response.ok else response.raise_for_status()
def check_loadbalancer_operating_status(loadbal_ep, token, loadbalancer_id):
    response = send_get_request("{}/v2.0/lbaas/loadbalancers/{}".format(loadbal_ep, loadbalancer_id), token)
    logging.debug(response.text)
    data= response.json()
    return data["loadbalancer"]["operating_status"] if response.ok else response.raise_for_status()

def create_l7policy(loadbal_ep, token, policy_name, listener_id):
    #create loadbalancer
    payload= {
        "l7policy": {
            "name": policy_name,
            "listener_id": listener_id,
            "action": "REDIRECT_TO_URL", 
            "redirect_url": "https://www.example.com/",
            "admin_state_up": "true"
            }
        }
    response= send_post_request('{}/v2.0/lbaas/l7policies'.format(loadbal_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created l7policy {}".format(policy_name)) if response.ok else response.raise_for_status()

def create_l7policy(loadbal_cdep, token, policy_id):
    #create loadbalancer
    payload= {
        "rule": {
            "compare_type": "STARTS_WITH", 
            "value": "/", 
            "type": "PATH",
            "admin_state_up": "true"
            }
        }
    response= send_post_request('{}/v2.0/lbaas/l7policies/{}/rules'.format(loadbal_ep, policy_id), token, payload)
    logging.debug(response.text)
    logging.info("successfully added rule to policy {}".format(policy_id)) if response.ok else response.raise_for_status()