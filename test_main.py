from features.numa import *
from functions import *
from openstack_api_functions.keystone import *
from openstack_api_functions.neutron import *
import pytest
import json
import os
import sys
import requests
import argparse
import logging
import subprocess
import time



#Fixtures
@pytest.fixture(scope="session", name="settings")
def read_user_settings():
    return read_settings("settings.json")

@pytest.fixture(scope="session", name="undercloud")
def read_stackrc_file():
    return read_rc_file(os.path.expanduser("~/stackrc"))

@pytest.fixture(scope="session", name="overcloud")
def read_overcloudrc_file():
    return read_rc_file(os.path.expanduser("~/r62rc"))

@pytest.fixture(scope="session", name="endpoints")
def get_services_endpoints(undercloud, overcloud):
    return create_services_endpoints(undercloud.get("ip"), overcloud.get("ip"))

@pytest.fixture(scope="session", name="undercloud_token")
def undercloud_authentication_token(undercloud, endpoints ):
    return get_authentication_token(endpoints.get("undercloud_keystone"), undercloud.get("username"), undercloud.get("password"))

@pytest.fixture(scope="session", name="overcloud_token")
def overcloud_authentication_token(overcloud, endpoints):
    return get_authentication_token(endpoints.get("keystone"), overcloud.get("username"), overcloud.get("password"))
     
@pytest.fixture(scope="session", name="environment")
def create_basic_openstack_environment(settings, endpoints, overcloud_token):
    features = ["numa", "hugepages", "barbican"]
    #create networks
    if features[0]== "mtu9000":
        network1_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network1_name"], 9000, settings["network_provider_type"], False)
        network2_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network2_name"], 9000, settings["network_provider_type"], False)
    else: 
        network1_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network1_name"], 1500, settings["network_provider_type"], False)
        network2_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network2_name"], 1500, settings["network_provider_type"], False)

    #cereate subnets
    subnet1_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet1_name"], network1_id, settings["subnet1_cidr"]) 
    subnet2_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet2_name"], network2_id, settings["subnet2_cidr"]) 

    #update security group rules
    project_id= find_admin_project_id(endpoints.get("keystone"), overcloud_token)
    security_group_id= get_default_security_group_id(endpoints.get("neutron"), overcloud_token, project_id)
    try:
        add_icmp_rule_to_security_group(endpoints.get("neutron"), overcloud_token, security_group_id)
        add_ssh_rule_to_security_group(endpoints.get("neutron"), overcloud_token, security_group_id)
    except:
        pass
    
    #create router and add network interfaces
    router_id= search_router(endpoints.get("neutron"), overcloud_token, settings["router_name"])
    if router_id is None:
        public_network_id= search_network(endpoints.get("neutron"), overcloud_token, "public")
        public_subnet_id= search_subnet(endpoints.get("neutron"), overcloud_token, settings["external_subnet"])
        router_id= create_router(endpoints.get("neutron"), overcloud_token, settings["router_name"], public_network_id,public_subnet_id )
        add_interface_to_router(endpoints.get("neutron"), overcloud_token, router_id, subnet2_id)
        add_interface_to_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)

    #### SSH Keypair
    keypair_public_key= "" 
    keypair_key= search_keypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    keypair_private_key=""
    logging.info("searching ssh key")
    keyfile_name= os.path.expanduser(settings["key_file"])
    if(keypair_key != None):
        logging.info("deleting old ssh key")
        delete_resource("{}/v2.1/os-keypairs/{}".format(nova_ep, settings["key_name"]), token)

    keypair_private_key= create_keypair(endpoints.get("nova"), token, settings["key_name"])
    logging.info("ssh key created")
    try:
        logging.info("deleting old private file")
        os.system("sudo rm "+keyfile_name)
    except OSError:
        pass
    logging.info("creating key file")
    keyfile = open(keyfile_name, "w")
    keyfile.write(keypair_private_key)
    keyfile.close()
    logging.info("setting permission to private key file")
    command= "chmod 400 "+keyfile_name
    os.system(command)

    #create image
    if ("barbican" not in features):
        image_id= search_and_create_image(endpoints.get("image"), overcloud_token, settings["image_name"], "bare", "qcow2", "public", os.path.expanduser(settings["image_file"]))
    else:
        image_id= search_image(endpoints.get("nova"), overcloud_token, settings["image_name"])
        if(image_id is None):
            key= create_ssl_certificate(settings)
            image_signature= sign_image(settings)
            barbican_key_id= add_key_to_store(endpoints.get("barbican"), overcloud_token, key)
            image_id= create_barbican_image(endpoints.get("barbican"), overcloud_token, settings["image_name"], "bare", "qcow2", "public", image_signature, barbican_key_id)
        status= get_image_status(image_ep, token, image_id)
        if status== "queued":
            image_file= open(os.path.expanduser(settings["image_file"]), 'rb')
            upload_file_to_image(endpoints.get("image"), overcloud_token, image_file, image_id)

    #create flavor    
    flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, settings["flavor1"], 4096, 2, 150)
    if(features[0] == "ovsdpdk"):
        logging.info("putting ovsdpdk specs in flavor")
        put_ovs_dpdk_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
    elif("numa" in features or features[0]=="sriov" or features[0]=="sriov_vflag"):
        logging.info("putting numa specs in flavor")
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
    
    return network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key
    

@pytest.mark.test
def test_setup(settings):
    print(settings.get("network2_name"))

@pytest.mark.numa
def test_addition(undercloud):
    assert numa_add(2,6)== 8
    print (undercloud.get("username"))


@pytest.mark.hugepages
<<<<<<< HEAD
def test_addition2(undercloud_token):
    assert numa_add(2,6)==8
    print(undercloud_token)

def test_addition3(overcloud_token):
    assert numa_add(4,6)==10
    print(overcloud_token)

def test_addition4(environment):
    print(environment[0])
    print(environment[1])



=======
def test_addition2():
    assert numa_add(2,6)==10
>>>>>>> c67d28c239de10560745d4d2c06c6b9747bbc4b6
