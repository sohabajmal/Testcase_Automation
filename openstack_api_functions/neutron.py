def search_network(neutron_ep, token, network_name):
    #get list of networks
    response= send_get_request("{}/v2.0/networks".format(neutron_ep), token)
    logging.info("successfully received networks list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "networks", "name", network_name, "id")
def get_network_detail(neutron_ep, token, network_id):
    #get list of networks
    response= send_get_request("{}/v2.0/networks/{}".format(neutron_ep, network_id), token)
    logging.info("successfully received networks list") if response.ok else response.raise_for_status()
    response= response.json()
    return response
'''
Networks
'''
def create_network(neutron_ep, token, network_name, mtu_size, network_provider_type, is_external):
    #create network
    payload= {
        "network": {
            "name": network_name,
            "admin_state_up": True,
            "mtu": mtu_size,
            "provider:network_type": network_provider_type,
            "router:external": is_external,
            "provider:physical_network": "physint"
            }
        }

    response= send_post_request('{}/v2.0/networks'.format(neutron_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created network {}".format(network_name)) if response.ok else response.raise_for_status()
    data=response.json()
    return data['network']['id']
def search_and_create_network(neutron_ep, token, network_name, mtu_size, network_provider_type, is_external):
    network_id= search_network(neutron_ep, token, network_name)    
    if network_id is None:
        network_id =create_network(neutron_ep, token, network_name, mtu_size, network_provider_type, False)  
    logging.debug("network id is: {}".format(network_id))
    return network_id
def create_port(neutron_ep, token, network_id, subnet_id, name, property=None ):
    payload= {"port": {
        "binding:vnic_type": "direct", 
        "network_id": network_id, 
	    "admin_state_up": 'true', 
        "fixed_ips": [{"subnet_id": subnet_id}], "name": name}}
    
    payload_port_property= {"binding:profile": {"capabilities": ["switchdev"]},
}
    if property is not None:
        payload= {"port":{**payload["port"], **payload_port_property}}
    response= send_post_request('{}/v2.0/ports'.format(neutron_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created port") if response.ok else response.raise_for_status()
    data=response.json()
    return data["port"]["id"], data["port"]["fixed_ips"][0]["ip_address"]

'''
Subnets
'''
def search_subnet(neutron_ep, token, subnet_name):
    #get list of subnets
    response= send_get_request("{}/v2.0/subnets".format(neutron_ep), token)
    logging.info("Successfully Received Subnet List") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "subnets", "name", subnet_name, "id")

def create_subnet(neutron_ep, token, subnet_name, network_id, cidr, external= False, gateway=None, pool_start= None, pool_end= None):
    #create internal subnet
    payload= {
        "subnet": {
            "name": subnet_name,
            "network_id": network_id,
            "ip_version": 4,
            "cidr": cidr
            }
        }
    payload_external_subnet={"enable_dhcp": "true","gateway_ip": gateway,
               "allocation_pools": [{"start": pool_start, "end": pool_end}]}
    if external== True:
        payload= {"subnet":{**payload["subnet"], **payload_external_subnet}}
    response= send_post_request("{}/v2.0/subnets".format(neutron_ep), token, payload)
    logging.info("successfully created subnet") if response.ok else response.raise_for_status()
    data= response.json()
    return data['subnet']['id']
def search_and_create_subnet(neutron_ep, token, subnet_name, network_id, subnet_cidr):
    subnet_id= search_subnet(neutron_ep, token, subnet_name)    
    if subnet_id is None:
        subnet_id =create_subnet(neutron_ep, token, subnet_name, network_id, subnet_cidr) 
    logging.debug("subnet id is: {}".format(subnet_id)) 
    return subnet_id

'''
Router
'''
def search_router(neutron_ep, token, router_name):
    response= send_get_request("{}/v2.0/routers".format(neutron_ep), token)
    logging.info("successfully received router list") if response.ok else response.raise_for_status()

    return parse_json_to_search_resource(response, "routers", "name", router_name, "id")

def create_router(neutron_ep, token, router_name, network_id, subnet_id):
    payload={"router":
        {"name": router_name,
        "admin_state_up":" true",
        "external_gateway_info": {
            "network_id": network_id,
            "enable_snat": "true",
            "external_fixed_ips": [
                {
                    "subnet_id": subnet_id
                }
            ]
        }
        }

    }
    response= send_post_request('{}/v2.0/routers'.format(neutron_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created router {}".format(router_name)) if response.ok else response.raise_for_status()  
    data= response.json()
    return data['router']['id']
def set_router_gateway(neutron_ep, token, router_id, network_id):
    print(router_id)
    payload={"router": {"external_gateway_info": {"network_id": network_id}}}
    response= send_post_request("{}/v2.0/routers/{}".format(neutron_ep,router_id), token, payload)
    logging.debug(response.text)
    logging.info("successfully set gateway to router {}".format(router_id)) if response.ok else response.raise_for_status()  
def add_interface_to_router(neutron_ep, token, router_id, subnet_id):
    payload={
    "subnet_id": subnet_id
    }
    
    response= send_put_request('{}/v2.0/routers/{}/add_router_interface'.format(neutron_ep,router_id), token, payload)
    logging.debug(response.text)
    logging.info("successfully added interface to router {}".format(router_id)) if response.ok else response.raise_for_status()  
def remove_interface_to_router(neutron_ep, token, router_id, subnet_id):
    payload={
    "subnet_id": subnet_id
    }
    
    response= send_put_request('{}/v2.0/routers/{}/remove_router_interface'.format(neutron_ep,router_id), token, payload)
    logging.debug(response.text)
    logging.info("successfully removed interface from router {}".format(router_id)) if response.ok else response.raise_for_status()  

def get_default_security_group_id(neutron_ep, token, project_id):
    response= send_get_request("{}/v2.0/security-groups".format(neutron_ep), token)
    logging.info("successfully received security group list") if response.ok else response.raise_for_status()
    data= response.json()
    for res in (data["security_groups"]):
        if(res["name"]== "default" and res["tenant_id"]== project_id):
            return res["id"]
            break
def search_security_group(neutron_ep, token, security_group_name):
    response= send_get_request("{}/v2.0/security-groups".format(neutron_ep), token)
    logging.info("successfully received security group list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "security_groups", "name", security_group_name, "id")

def create_security_group(neutron_ep, token, security_group_name):
    payload= {
    "security_group": {
        "name": security_group_name,
        }
    }
    response = send_post_request('{}/v2.0/security-groups'.format(neutron_ep), token, payload)
    logging.info("successfully created security Group {}".format(security_group_name)) if response.ok else response.raise_for_status()
    data= response.json()
    return data["security_group"]["id"]

def search_and_create_security_group(neutron_ep, token, security_group_name):
    security_group_id= search_security_group(neutron_ep, token, security_group_name) 
    if security_group_id is None:
        security_group_id= create_security_group(neutron_ep, token, security_group_name)
    logging.debug("security group id is: {}".format(security_group_id)) 
    return security_group_id

def add_icmp_rule_to_security_group(neutron_ep, token, security_group_id):
    payload= {"security_group_rule":{
            "direction": "ingress",
            "ethertype":"IPv4",
            "direction": "ingress",
            "remote_ip_prefix": "0.0.0.0/0",
            "protocol": "icmp",
            "security_group_id": security_group_id
        }
    }
    response= send_post_request('{}/v2.0/security-group-rules'.format(neutron_ep), token, payload)
    logging.info("Successfully added ICMP rule to Security Group") if response.ok else response.raise_for_status()
def add_ssh_rule_to_security_group(neutron_ep, token, security_group_id):
    payload= {"security_group_rule": {
        "direction": "ingress",
        "ethertype":"IPv4",
        "direction": "ingress",
         "remote_ip_prefix": "0.0.0.0/0",
        "protocol": "tcp",
        "port_range_min": "22",
        "port_range_max": "22",
        "security_group_id": security_group_id
        }
        }
    response= send_post_request('{}/v2.0/security-group-rules'.format(neutron_ep), token, payload)
    logging.info("Successfully added SSH rule to Security Group") if response.ok else response.raise_for_status()

def parse_port_response(data, server_fixed_ip):
    data= data.json()
    for port in data["ports"]:
        if port["fixed_ips"][0]["ip_address"] == server_fixed_ip:
            return port["id"]   

def get_ports(neutron_ep, token, network_id, server_ip):
    response= send_get_request("{}/v2.0/ports?network_id={}".format(neutron_ep, network_id), token)
    logging.info("successfully received ports list ") if response.ok else response.raise_for_status()
    return parse_port_response(response, server_ip)

def create_floating_ip(neutron_ep, token, network_id, subnet_id, server_ip_address, server_port_id):
    payload= {"floatingip": 
             {"floating_network_id":network_id,
             
              "subnet_id": subnet_id,
              "fixed_ip_address": server_ip_address,
               "port_id": server_port_id
              }
             } 
    time.sleep(10)
    response= send_post_request("{}/v2.0/floatingips".format(neutron_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully assigned floating ip to server") if response.ok else response.raise_for_status()
    data= response.json()
    return data["floatingip"]["floating_ip_address"], data["floatingip"]["id"]
def create_floatingip_wo_port(neutron_ep, token, network_id ):
    payload= {
        "floatingip": {
            "floating_network_id": network_id
            }
        }
    response= send_post_request("{}//v2.0/floatingips".format(neutron_ep), token, payload)
    time.sleep(10)
    logging.debug(response.text)
    data=response.json()
    logging.info("successfully created floating ip") if response.ok else response.raise_for_status()
    return data["floatingip"]["floating_ip_address"], data["floatingip"]["id"]
def assign_ip_to_port(neutron_ep, token, port_id, floatingip_id ):
    payload= {
        "floatingip": {
            "port_id": port_id
            }
        }
    response= send_put_request("{}/v2.0/floatingips/{}".format(neutron_ep, floatingip_id), token, payload)
    logging.debug(response.text)
    time.sleep(10)
    logging.info("successfully assigned floating to port") if response.ok else response.raise_for_status()

