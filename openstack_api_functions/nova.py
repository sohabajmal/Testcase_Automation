
'''
Flavor
'''

def search_flavor(nova_ep, token, flavor_name):
    # get list of flavors
    response= send_get_request("{}/v2.1/flavors".format(nova_ep), token)
    logging.info("successfully received flavor list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "flavors", "name", flavor_name, "id")

def create_flavor(nova_ep, token, flavor_name, flavor_ram, flavor_vcpus, flavor_disks):
    # create Flavor
    payload={
        "flavor": {
            "name": flavor_name,
            "ram":  flavor_ram,
            "vcpus": flavor_vcpus,
            "disk": flavor_disks,
            "rxtx_factor" : "1",
            "os-flavor-access:is_public": "true"
        }
    }
    response= send_post_request("{}/v2.1/flavors".format(nova_ep), token, payload)
    logging.info("successfully created flavor") if response.ok else response.raise_for_status()
    data= response.json()
    return data['flavor']['id']
def search_and_create_flavor(nova_ep, token, flavor_name, ram, vcpu, disks):
    flavor_id= search_flavor(nova_ep, token, flavor_name)    
    if flavor_id is None:
        flavor_id= create_flavor(nova_ep, token, flavor_name, ram, vcpu, disks)   
    logging.debug("flavor id is: {}".format(flavor_id))
    return flavor_id
def put_extra_specs_in_flavor(nova_ep, token, flavor_id,is_numa, mem_page_size="large"):
    #add extra specs to flavors
    if is_numa== True:
        payload= {
            "extra_specs": {
                "hw:cpu_policy": "dedicated", 
                "hw:cpu_thread_policy": "require",
                "hw:numa_nodes": "1", 
                "hw:mem_page_size": "large"
                }
        }
    else: 
        payload={
                "extra_specs": {
                    "hw:cpu_policy": "dedicated",
                    "hw:mem_page_size": mem_page_size,
                    "hw:cpu_thread_policy": "prefer",
                    "hw:numa_nodes": "1",
                    #"hw:emulator_threads_policy": "isolate"
                }  

        }
    response= send_post_request("{}/v2.1/flavors/{}/os-extra_specs".format(nova_ep, flavor_id), token, payload)
    logging.debug(response.text)
    logging.info("successfully added extra specs to  flavor {}".format(flavor_id)) if response.ok else response.raise_for_status()
def put_ovs_dpdk_specs_in_flavor(nova_ep, token, flavor_id):
    payload={
                "extra_specs": {
                    "hw:cpu_policy": "dedicated",
                    "hw:mem_page_size": "large",
                    "hw:cpu_thread_policy": "require",
                    "hw:numa_nodes": "1", 
                    "hw:numa_mempolicy":"preferred",
                    #"dpdk": "true"
                }
        }  
    response= send_post_request("{}/v2.1/flavors/{}/os-extra_specs".format(nova_ep, flavor_id), token, payload)
    logging.info("successfully added extra specs to  flavor {}".format(flavor_id)) if response.ok else response.raise_for_status()
'''
Keypair
'''
def search_keypair(nova_ep, token, keypair_name):
    response= send_get_request("{}/v2.1/os-keypairs".format(nova_ep), token)
    logging.info("successfully received keypair list") if response.ok else response.raise_for_status()
    data= response.json()
    for res in (data["keypairs"]):
        if keypair_name in res["keypair"]["name"]:
            logging.warning("{} already exists".format(keypair_name))
            return res["keypair"]["public_key"]
            break      
    else:
        logging.info("{} does not exist".format(keypair_name))

def create_keypair(nova_ep, token, keypair_name):
    payload={
        "keypair":{
            "name": keypair_name,
            #"type": "ssh" 
            }
        }
    #nova_ep="http://192.168.140.252:8774/V2.2"
    response= send_post_request('{}/v2.1/os-keypairs'.format(nova_ep), token, payload)
    logging.info("successfully created keypair {}".format(keypair_name)) if response.ok else response.raise_for_status()
    data= response.json()
    return data["keypair"]["private_key"]
def search_and_create_kaypair(nova_ep, token, key_name):
    keypair_public_key= search_keypair(nova_ep, token, key_name)
    if keypair_public_key is None:
        keypair_public_key= create_keypair(nova_ep, token, key_name)
    logging.debug("Keypair public key is: {}".format(keypair_public_key))
    return keypair_public_key

'''
Image
'''
def search_image(nova_ep, token, image_name):
    response= send_get_request("{}/v2.1/images".format(nova_ep), token)
    logging.info("successfully received images list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "images", "name", image_name, "id")

def create_image(nova_ep, token, image_name, container_format, disk_format, image_visibility):
    payload ={
        "container_format": container_format,
        "disk_format":disk_format,
        "name": image_name,
        "visibility":  image_visibility,
    }
    response = send_post_request("{}/v2.1/images".format(nova_ep), token, payload)
    logging.info("successfully created image {}".format(image_name)) if response.ok else response.raise_for_status()
    data= response.json()
    return data["id"]
    
def get_image_status(nova_ep, token, image_id):
    response= send_get_request("{}/v2.1/images/{}".format(nova_ep, image_id), token)
    logging.info("successfully received image status") if response.ok else response.raise_for_status()
    data= response.json()
    return(data["status"])

def upload_file_to_image(image_ep, token, image_file, image_id):
    #image_file= open("cirros-0.5.1-x86_64-disk.img", "r")
    #response = send_put_request("{}/v2.1/images/{}/file".format(image_ep, image_id), token, image_file, "application/octet-stream")
    try:
        response= requests.put("{}/v2.1/images/{}/file".format(image_ep, image_id), headers= {'content-type':"application/octet-stream", 'X-Auth-Token': token}, data=image_file)
        logging.debug(response.text)
    except Exception as e:
        logging.error( "request processing failure ", stack_info=True)
        print(e)
    logging.info("successfully uploaded file to image") if response.ok else response.raise_for_status()
def search_and_create_image(image_ep, token, image_name, container_format, disk_format, image_visibility, image_file_path):
    image_id= search_image(image_ep, token, image_name)
    if image_id is None:
        image_id= create_image(image_ep, token, image_name, container_format, disk_format, image_visibility)    
    status= get_image_status(image_ep, token, image_id)
    print(status)
    if status== "queued":
        print("Successfully Queued")
        image_file= open(image_file_path, 'rb')
        logging.info("uploading image file")
        upload_file_to_image(image_ep, token, image_file, image_id)
        logging.debug("image id is: {}".format(image_id))
    return image_id


'''
Servers
'''
def receive_all_server(nova_ep, token):
    response= send_get_request("{}/v2.1/servers/detail".format(nova_ep), token)
    logging.info("successfully received server list") if response.ok else response.raise_for_status()
    return response.json()

def search_server(nova_ep, token, server_name):
    response= send_get_request("{}/v2.1/servers".format(nova_ep), token)
    logging.info("successfully received server list") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "servers", "name", server_name, "id")

def create_server(nova_ep, token, server_name, image_id, keypair_name, flavor_id,  network_id, security_group_id, host=None, availability_zone= None):
    payload= {"server": {"name": server_name, "imageRef": image_id,
        "key_name": keypair_name, "flavorRef": flavor_id, 
        "max_count": 1, "min_count": 1, "networks": [{"uuid": network_id}], 
        "security_groups": [{"name": security_group_id}]}}   
    payload_manual_host={
        "host": host
        }
    #"networks": [{"uuid": network_id}]
    payload_availability_zone={
        "availability_zone": availability_zone
        }
    if host is not None:
        payload= {"server":{**payload["server"], **payload_manual_host}}
    if availability_zone is not None:
        payload= {"server":{**payload["server"], **payload_availability_zone}}
    response = send_post_request('{}/v2.1/servers'.format(nova_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created server {}".format(server_name)) if response.ok else  response.raise_for_status()
    data= response.json()
    return data["server"]["links"][0]["href"]  
def create_sriov_server(nova_ep, token, server_name, image_id, keypair_name, flavor_id,  port_id, availability_zone ,security_group_id, host=None):
    print("Securit Group Id is: "+security_group_id)
    payload= {"server": {"name": server_name, "imageRef": image_id,
        "key_name": keypair_name, "flavorRef": flavor_id, "security_groups": [{"name": security_group_id}],
        "max_count": 1, "min_count": 1, "networks": [{"port": port_id}], 
         "availability_zone": availability_zone}}   
    payload_manual_host={
        "host": host
        }
    if host is not None:
        payload= {"server":{**payload["server"], **payload_manual_host}}
    response = send_post_request('{}/v2.1/servers'.format(nova_ep), token, payload)
    logging.debug(response.text)
    logging.info("successfully created sriov server {}".format(server_name)) if response.ok else  response.raise_for_status()
    data= response.json()
    return data["server"]["links"][0]["href"]  
def get_server_detail(token, server_url):
    response = send_get_request(server_url, token)
    logging.info("Successfully Received Server Details") if response.ok else response.raise_for_status()
    data= response.json()
    return data["server"]["id"]
def get_server_host(nova_ep, token, server_id):
    response = send_get_request("{}/v2.1/servers/{}".format(nova_ep, server_id) , token)
    logging.info("Successfully Received Server Details") if response.ok else response.raise_for_status()
    data= response.json()
    return data["server"]["OS-EXT-SRV-ATTR:host"]

def check_server_status(nova_ep, token, server_id):
    response = send_get_request("{}/v2.1/servers/{}".format(nova_ep, server_id), token)
    logging.debug(response.text)
    data= response.json()
    return data["server"]["OS-EXT-STS:vm_state"] if response.ok else response.raise_for_status()

def parse_server_ip(data, network, network_type):
    data=data.json()
    for networks in data["server"]["addresses"][str(network)]:
        if networks["OS-EXT-IPS:type"] == network_type:
            #logging.info("received {} ip address of server".format())
            return networks["addr"]

def get_server_ip(nova_ep, token, server_id, network):
    
    response = send_get_request('{}/v2.1/servers/{}'.format(nova_ep, server_id), token)
    logging.debug(response.text)
    logging.info("received server network detail") if response.ok else response.raise_for_status()
    return parse_server_ip(response, network, "fixed")

def get_server_floating_ip(nova_ep, token, server_id, network):
    response = send_get_request('{}/v2.1/servers/{}'.format(nova_ep, server_id), token)
    logging.info("received server network detail") if response.ok else response.raise_for_status()
    return parse_server_ip(response, network, "floating")

def get_server_instance_name(nova_ep, token, server_id):
    response = send_get_request("{}/v2.1/servers/{}".format(nova_ep, server_id) , token)
    logging.info("Successfully Received Server Details") if response.ok else response.raise_for_status()
    data= response.json()
    return data["server"]["OS-EXT-SRV-ATTR:instance_name"]
def perform_action_on_server(nova_ep,token, server_id, action):
    payload={
    action: None
    }
    response= send_post_request("{}/v2.1/servers/{}/action".format(nova_ep, server_id), token, payload)
    return response.status_code
def create_server_snapshot (nova_ep,token, server_id, snapshot_name):
    payload={
    "createImage" : {
        "name" : snapshot_name,
        "metadata": {}
        }
    }
    
    response= send_post_request("{}/v2.1/servers/{}/action".format(nova_ep, server_id), token, payload)
    logging.debug(response.text)
    if(response.status_code == 202):
        data= response.json()
        return data["image_id"]
    else:
        return None

def resize_server(nova_ep,token, server_id, flavor_id):
    payload= {
    "resize" : {
        "flavorRef" : flavor_id,
        "OS-DCF:diskConfig": "AUTO"
        }
    }
    response= send_post_request("{}/v2.1/servers/{}/action".format(nova_ep, server_id), token, payload)
    logging.debug(response.text)
    return response.status_code
def reboot_server(nova_ep,token, server_id):
    payload={
    "reboot" : {
        "type" : "HARD"
         }
    }
    response=send_post_request("{}/v2.1/servers/{}/action".format(nova_ep, server_id), token, payload)
    logging.debug(response.text)
    return response.status_code

def live_migrate_server(nova_ep,token, server_id, host=None, block_migration="auto"):
    payload= {
        "os-migrateLive": {
            "block_migration": block_migration,
            "host": host
        }
        }
    response=send_post_request("{}/v2.1/servers/{}/action".format(nova_ep, server_id), token, payload)
    logging.debug(response.text)
    #logging.info(response.text)
    return response.status_code

def search_and_create_server(nova_ep, token, server_name, image_id, key_name, flavor_id,  network_id, security_group_id, host=None, availability_zone= None):
    server_id= search_server(nova_ep, token, server_name)
    if server_id is None:
        time.sleep(5)
        server_url= create_server(nova_ep, token, server_name, image_id, key_name, flavor_id,  network_id, security_group_id, host, availability_zone)
        time.sleep(5)
        server_id= get_server_detail(token, server_url)
    logging.debug("Server id: "+server_id)    
    return server_id
def search_and_create_sriov_server(nova_ep, token, server_name, image_id, key_name, flavor_id,  port_id, availability_zone, security_group_id, host=None):
    server_id= search_server(nova_ep, token, server_name)
    if server_id is None:
        server_url= create_sriov_server(nova_ep, token, server_name, image_id, key_name, flavor_id, port_id, availability_zone, security_group_id, host)
        server_id= get_server_detail(token, server_url)
    logging.debug("Server id: "+server_id)  
    return server_id
def attach_volume_to_server( nova_ep, token, project_id, server_id, volume_id, mount_point):
    payload= {"volumeAttachment": {"volumeId": volume_id}}
    response= requests.post("{}/v2.1/servers/{}/os-volume_attachments".format(nova_ep, server_id), headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    logging.debug(response.text)
    logging.info("volume successfully attached to server") if response.ok else response.raise_for_status()

def get_baremeta_nodes_ip(nova_ep, undercloud_token):
    servers= receive_all_server(nova_ep, undercloud_token)
    server_ip={}
    for server in servers["servers"]:
        server_ip[server["name"]]= server["addresses"]["ctlplane"][0]["addr"]
    return server_ip
def get_compute_host_list(nova_ep, token):
    response= send_get_request("{}/v2.1/os-hosts".format(nova_ep), token)
    logging.info("successfully received host list") if response.ok else response.raise_for_status()
    data= response.json()
    hosts=[]
    for host in data["hosts"]:
        hosts.append(host["host_name"])
    return hosts
def set_quota(nova_ep, token, project_id, vcpus, instances, ram):
    payload= {"quota_set": {
        "instances": instances,
        "cores": vcpus,
        "ram": ram
        }}
    #data=json.dumps(payload)
    response= requests.put("{}/v2.1/os-quota-sets/{}".format(nova_ep, project_id),  headers= {'content-type': "application/json", 'X-Auth-Token': token}, data=json.dumps(payload))
    #response= send_post_request("{}/v2.1/os-quota-sets/{}".format(nova_ep, project_id), token, payload)
    #print(response.text)
    logging.info("successfully updated quota") if response.ok else response.raise_for_status()
    
def get_availability_zones(nova_ep, token):
    response= send_get_request("{}/v2.1/os-aggregates".format(nova_ep), token)
    logging.info("successfully received availibility zones list") if response.ok else response.raise_for_status()
    data= response.json()   
    return data["aggregates"][0]["id"]
def create_availability_zones(nova_ep, token, name):
    payload= {
    "aggregate":
        {
        "name": name,
        "availability_zone": name
        }
    }
    response= send_post_request("{}/v2.1/os-aggregates".format(nova_ep), token, payload)
    logging.info("successfully created availibility zone") if response.ok else response.raise_for_status()
    data= response.json()   
    return data["aggregate"]["id"]

def remove_host_from_zone(nova_ep, token, zone_id, host_name):
    payload= {
    "remove_host": {
        "host": host_name
        }
    }
    response= send_post_request("{}/v2.1/os-aggregates/{}/action".format(nova_ep,zone_id), token, payload)
    logging.info("successfully removed host from availability zones ") if response.ok else response.raise_for_status()
def add_host_to_zone(nova_ep, token, zone_id, host_name):
    payload= {
    "add_host": {
        "host": host_name
        }
    }
    response= send_post_request("{}/v2.1/os-aggregates/{}/action".format(nova_ep,zone_id), token, payload)
    logging.info("successfully added host to availability zones ") if response.ok else response.raise_for_status()
def add_property_availability_zones(nova_ep, token, zone_id):
    payload= {"set_metadata": {"metadata": {"dpdk": "true"}}}
    response= send_post_request("{}/v2.1/os-aggregates/{}/action".format(nova_ep, zone_id), token, payload)
    logging.info("successfully added property availability zone") if response.ok else response.raise_for_status()

def create_barbican_image(nova_ep, token, image_name, container_format, disk_format, image_visibility, image_signature, key_id):
    payload ={
        "container_format": container_format,
        "disk_format":disk_format,
        "name": image_name,
        "visibility":  image_visibility,
        "img_signature": image_signature,
        "img_signature_certificate_uuid": key_id,
        "img_signature_hash_method":"SHA-256",
        "img_signature_key_type": "RSA-PSS"
    }
    response = send_post_request("{}/v2.1/images".format(nova_ep), token, payload)
    logging.info("successfully created image {}".format(image_name)) if response.ok else response.raise_for_status()
    data= response.json()
    return data["id"]
#
#Server Functions
#

def server_build_wait(nova_ep, token, server_ids):
    while True:
        flag=0
        for server in server_ids:
            status= check_server_status(nova_ep, token, server)
            print(status)
            if not (status == "active" or status=="error"):
                logging.info("Waiting for server/s to build")
                flag=1
                time.sleep(10)
        if flag==0:
            break
def wait_instance_boot(ip):
    retries=0
    while(1):
        response = os.system("ping -c 3 " + ip)
        if response == 0:
            logging.info ("Ping successfull!") 
            return True
        logging.info("Waiting for server to boot")
        time.sleep(30)
        retries=retries+1
        if(retries==5):
            return False




