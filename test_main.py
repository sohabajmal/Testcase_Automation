from functions import *
from features.numa import *
from features.barbican import *
#from features.barbican import *
from openstack_api_functions.keystone import *
from openstack_api_functions.neutron import *
from openstack_api_functions.barbican import *
from openstack_api_functions.loadbalancer import *
from openstack_api_functions.nova import *
from openstack_api_functions.volume import *
import pytest
import json
import os
import sys
import requests
import argparse
import logging
import subprocess
import time



if not os.path.exists('logs'):
    os.makedirs('logs')
#log_file= "logs/"+ time.strftime("%d-%m-%Y-%H-%M-%S")+".log"
#logging.basicConfig(level=logging.DEBUG,
#                    format='%(asctime)s %(message)s',
#                    handlers=[logging.FileHandler(log_file),
#                             logging.StreamHandler()])


# Fixtures provide a fixed baseline so that tests execute reliably and produce consistent, repeatable, results. 
# They have 4 scopes: classes, modules, packages or session

#read settings from settings.json
deployed_features=[]
@pytest.fixture(scope="session", name="settings")
def read_user_settings():
    return read_settings("settings.json")

#read settings from ini file
@pytest.fixture(scope="session", name="ini_file")
def read_ini_file(settings):
    settings= read_ini_settings(settings.get("sah_ip"), settings.get("ini_file"))
    return settings

#read stackrc file
@pytest.fixture(scope="session", name="undercloud")
def read_stackrc_file():
    return read_rc_file(os.path.expanduser("~/stackrc"))

#read overcloud rc file
@pytest.fixture(scope="session", name="overcloud")
def read_overcloudrc_file(ini_file):
    return read_rc_file(os.path.expanduser("~/{}rc".format(ini_file.get("overcloud_name"))))

#get endpoints of overcloud
@pytest.fixture(scope="session", name="endpoints")
def get_services_endpoints(undercloud, overcloud):
    return create_services_endpoints(undercloud.get("ip"), overcloud.get("ip"))

#get undercloud token
@pytest.fixture(scope="session", name="undercloud_token")
def undercloud_authentication_token(undercloud, endpoints):
    return get_authentication_token(endpoints.get("undercloud_keystone"), undercloud.get("username"), undercloud.get("password"))

#get overcloud token
@pytest.fixture(scope="session", name="overcloud_token")
def overcloud_authentication_token(overcloud, endpoints):
    return get_authentication_token(endpoints.get("keystone"), overcloud.get("username"), overcloud.get("password"))

#get name and IP adress of bareetal nodes
@pytest.fixture(scope="session", name="baremetal_nodes")
def get_baremetal_nodes_detail(endpoints, undercloud_token):
    baremetal_nodes_detail= get_baremeta_nodes_ip(endpoints.get("undercloud_nova"), undercloud_token)
    return baremetal_nodes_detail

    
#create basic openstack environment     
@pytest.fixture(scope="session", name="environment", autouse=True)
def create_basic_openstack_environment(settings, endpoints, overcloud_token, ini_file):
    #list of features enabled
    print("Creating OpenStack Environment")
    print("\n")
    for key, value in ini_file.items():
        if(value== "true"):
            key=key.split("_")
            deployed_features.append(key[0])
            if(key[0]== "smart"):
                print("Hardware Offloading is Enabled")
            else:
                print("{} is Enabled".format(key[0].capitalize()))
    #create networks
    if ini_file.get("mtu_size")== "9000":
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

    #create ssh keypair and create new .pem file on director
    keypair_public_key= "" 
    keypair_key= search_keypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    keypair_private_key=""
    logging.debug("searching ssh key")
    keyfile_name= os.path.expanduser(settings["key_file"])
    if(keypair_key != None):
        #delete_resource("{}/v2.1/os-keypairs/{}".format(endpoints.get("nova"), settings["key_name"]), overcloud_token)
        delete_kaypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    keypair_private_key= create_keypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    logging.debug("ssh key created")
    try:
        logging.debug("deleting old private file")
        os.system("sudo rm "+keyfile_name)
    except OSError:
        pass
    logging.debug("creating key file")
    keyfile = open(keyfile_name, "w")
    keyfile.write(keypair_private_key)
    keyfile.close()
    logging.debug("setting permission to private key file")
    command= "chmod 400 "+keyfile_name
    os.system(command)

    #download centos imgae if it is not downloaded
    if (os.path.isfile(os.path.expanduser(ini_file.get("image_file_name")))):
        logging.info("centos image file aready exists")
    else:
        download_qcow_image(ini_file.get("sanity_image_url"))

    #create image
    if ini_file.get("barbican_enabled")=="false":
        image_id= search_and_create_image(endpoints.get("image"), overcloud_token, settings["image_name"], "bare", "qcow2", "public", os.path.expanduser(ini_file.get("image_file_name")))
    else:
        image_id= search_image(endpoints.get("nova"), overcloud_token, settings["image_name"])
        if(image_id is None):
            key= create_ssl_certificate(settings)
            image_signature= sign_image(settings, ini_file.get("image_file_name"))
            barbican_key_id= add_key_to_store(endpoints.get("barbican"), overcloud_token, key)
            image_id= create_barbican_image(endpoints.get("image"), overcloud_token, settings["image_name"], "bare", "qcow2", "public", image_signature, barbican_key_id)
        status= get_image_status(endpoints.get("image"), overcloud_token, image_id)
        if status== "queued":
            image_file= open(os.path.expanduser(ini_file.get("image_file_name")), 'rb')
            upload_file_to_image(endpoints.get("image"), overcloud_token, image_file, image_id)

    #create flavor    
    flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, settings["flavor1"], 4096, 2, 150)
    if(ini_file.get("ovs_dpdk_enabled")=="true"):
        logging.debug("putting ovsdpdk specs in flavor")
        put_ovs_dpdk_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
    elif(ini_file.get("numa_enable")=="true" or ini_file.get("sriov_enabled")=="true"):
        logging.debug("putting numa specs in flavor")
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
    yield network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key
    
    #Clean Environment
    '''
    print("\n Cleaning Environment")
    delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
    delete_image(endpoints.get("image"), overcloud_token, image_id)
    remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet2_id)
    remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)
    delete_network(endpoints.get("neutron"), overcloud_token, network1_id)
    delete_network(endpoints.get("neutron"), overcloud_token, network2_id)
    delete_router(endpoints.get("neutron"), overcloud_token, router_id)
    delete_kaypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    '''
   

#Numa testcases
@pytest.mark.numa
@pytest.mark.functional
def test_verify_instance_creation_with_numa_flavor(settings, environment, endpoints, overcloud_token):
    if "numa" not in deployed_features:
        pytest.skip("Numa is disabled in ini file")
    #create flavor
    flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor", 4096, 4, 10)
    #create server
    server_id= create_numa_instance(settings, environment, endpoints.get("nova"), overcloud_token, flavor_id)
    #check status of server is active or not
    assert check_server_status(endpoints.get("nova"), overcloud_token, server_id) == "active"
    #delete server
    #delete_server(endpoints.get("nova"), overcloud_token, server_id)
    #delete falvor
    #delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)    


@pytest.mark.numa
@pytest.mark.negative
def test_number_of_vcpus_pinned_are_same_as_the_vcpus_in_numa_flavour(settings, environment, endpoints, overcloud_token, baremetal_nodes):
    #verify vcpus of instance are 4 or not 
    if "numa" not in deployed_features:
        pytest.skip("Numa is disabled in ini file")
    assert get_vcpus_of_instance(settings, environment, endpoints.get("nova"), overcloud_token, baremetal_nodes) == "4"

#Barbican Testases
@pytest.mark.barbican
@pytest.mark.functional
def test_create_barbican_secret(endpoints, overcloud_token):
    if "barbican" not in deployed_features:
        pytest.skip("Barbican is disabled in ini file")
    assert create_barbican_secret(endpoints.get("barbican"), overcloud_token) != "" or None

#SRIOV Testases
@pytest.mark.numa
def test_dummy_sriov(endpoints, overcloud_token, environment):
    if "sriov" not in deployed_features:
        pytest.skip("Sriov is disabled in ini file")
    assert create_barbican_secret(endpoints.get("barbican"), overcloud_token) != "" or None

