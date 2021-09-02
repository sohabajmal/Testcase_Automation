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
    # Create Networks
    network1_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network1_name"], 1500, settings["network_provider_type"], False)
    network2_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network2_name"], 1500, settings["network_provider_type"], False)

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
    #### SSH Keypair
    try:
        keypair_public_key= "" 
        keypair_key= search_keypair(nova_ep, token, settings["key_name"])
        keypair_private_key=""
        logging.info("searching ssh key")
        keyfile_name= os.path.expanduser(settings["key_file"])
        if(keypair_key != None):
            logging.info("deleting old ssh key")
            delete_resource("{}/v2.1/os-keypairs/{}".format(nova_ep, settings["key_name"]), token)

        keypair_private_key= create_keypair(nova_ep, token, settings["key_name"])
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



    return network1_id, network2_id, subnet1_id, subnet2_id

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
