from common_utils import *
from openstack_features.numa import *
from openstack_features.barbican import *
from openstack_features.hugepage import *
from openstack_features.sriov import *
from openstack_features.dvr import *
from openstack_features.dpdk import *
from openstack_features.mtu9000 import *
from openstack_features.volume import *
from openstack_features.offloading import *
from openstack_features.octavia import *
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


# Fixtures provide a fixed baseline so that tests execute reliably and produce consistent, repeatable, results. 
# They have 4 scopes: classes, modules, packages or session

deployed_features=[]
testcases_detail={}

#read settings from settings.json
@pytest.fixture(scope="session", name="settings")
def read_user_settings():
    #read settings from settings.json and return values
    return read_settings("settings.json")

#read settings from ini file
@pytest.fixture(scope="session", name="ini_file")
def read_ini_file(settings):
    #encrypting rsa key file to enable ssh throgh paramiko
    command= "ssh-keygen -f ~/.ssh/id_rsa -p -m PEM -f ~/.ssh/id_rsa -N ''"
    os.system(command)
    #read ini file
    settings= read_ini_settings(settings.get("sah_ip"), settings.get("ini_file"))
    return settings

#print list of deployed features and results
@pytest.fixture(scope="session", name="report", autouse=True)
def print_features_list_and_results(ini_file, endpoints, settings, overcloud):
    #print features enabled ini file
    for key, value in ini_file.items():
        if(value== "true"):
            key=key.split("_")
            if(key[0]== "smart"):
                key[0]= "offloading"
            if(key[0]== "ovs"):
                key[0]= "dpdk"
            if(key[1]== "powerflex"):
                key[0]= "powerflex"
            deployed_features.append(key[0])
            logging.info("{} is Enabled".format(key[0].capitalize()))
        if(value == "9000"):
            key="mtu9000"
            deployed_features.append(key)
            logging.info("{} is Enabled".format(key.capitalize()))
          
    yield 
    '''
    This part of code wil execute after execution of all tests. 
    It will clean environment and print report
    '''
    #cleaning environment at end of testcases
    overcloud_token= get_authentication_token(endpoints.get("keystone"), overcloud.get("username"), overcloud.get("password"))
    clean_all_environment(ini_file, endpoints, settings, overcloud_token)
    #custom report
    logging.info("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    logging.info("-------- Custom Report ------------")
    logging.info("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ \n")    
    #generate table
    summary_table=get_testcases_summary(testcases_detail, deployed_features)
    #print(summary_table)
    logging.info("\n{}".format(summary_table))

#read stackrc file
@pytest.fixture(scope="session", name="undercloud")
def read_stackrc_file():
    #read stackrc file
    return read_rc_file(os.path.expanduser("~/stackrc"))

#read overcloud rc file
@pytest.fixture(scope="session", name="overcloud")
def read_overcloudrc_file(ini_file):
    # #read overcloud file
    return read_rc_file(os.path.expanduser("~/{}rc".format(ini_file.get("overcloud_name"))))

#get endpoints of overcloud
@pytest.fixture(scope="session", name="endpoints")
def get_services_endpoints(undercloud, overcloud):
    return create_services_endpoints(undercloud.get("ip"), overcloud.get("ip"))

#get undercloud token
@pytest.fixture(scope="session", name="undercloud_token")
def undercloud_authentication_token(undercloud, endpoints):
    #get undercloud token 
    return get_authentication_token(endpoints.get("undercloud_keystone"), undercloud.get("username"), undercloud.get("password"))

#get overcloud token
@pytest.fixture(scope="function", name="overcloud_token")
def overcloud_authentication_token(overcloud, endpoints):
    #get overcloud token 
    return get_authentication_token(endpoints.get("keystone"), overcloud.get("username"), overcloud.get("password"))

#get name and ip adress of baremetal nodes
@pytest.fixture(scope="session", name="baremetal_nodes")
def get_baremetal_nodes_detail(endpoints, undercloud_token):
    #get name and ip adress of baremetal nodes 
    baremetal_nodes_detail= get_baremeta_nodes_ip(endpoints.get("undercloud_nova"), undercloud_token)
    return baremetal_nodes_detail


#create basic openstack environment     
@pytest.fixture(scope="function", name="environment", autouse=True)
def create_basic_openstack_environment(settings, endpoints, overcloud_token, ini_file):
    ids={}    
    #create networks
    if ini_file.get("mtu_size")== "9000":
        network1_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network1_name"], 9000, settings["network_provider_type"], False)
        network2_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network2_name"], 9000, settings["network_provider_type"], False)
    else: 
        network1_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network1_name"], 1500, settings["network_provider_type"], False)
        network2_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, settings["network2_name"], 1500, settings["network_provider_type"], False)
    ids["network1_id"]= network1_id
    ids["network2_id"]= network2_id
    
    #cereate subnets
    subnet1_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet1_name"], network1_id, settings["subnet1_cidr"]) 
    subnet2_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet2_name"], network2_id, settings["subnet2_cidr"]) 
    ids["subnet1_id"]= subnet1_id
    ids["subnet2_id"]= subnet2_id

    #verify and create public network
    public_network_id= search_network(endpoints.get("neutron"), overcloud_token, "public")
    if public_network_id is None:
        public_network_id = search_and_create_network(endpoints.get("neutron"), overcloud_token, "public", 1500, "vlan", "true", "physext", ini_file.get("floating_ip_network_vlan"))
        public_subnet_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, "external_sub", public_network_id, ini_file.get("floating_ip_network_cidr"), "true", ini_file.get("floating_ip_network_gateway"), ini_file.get("floating_ip_network_start_ip"), ini_file.get("floating_ip_network_end_ip"))
    else:
        public_subnet_id= search_subnet(endpoints.get("neutron"), overcloud_token, settings["external_subnet"])
        logging.info("Public network exists")

    #update security group rules
    project_id= find_admin_project_id(endpoints.get("keystone"), overcloud_token)
    ids["project_id"]= project_id
    security_group_id= get_default_security_group_id(endpoints.get("neutron"), overcloud_token, project_id)
    try:
        add_icmp_rule_to_security_group(endpoints.get("neutron"), overcloud_token, security_group_id)
        add_ssh_rule_to_security_group(endpoints.get("neutron"), overcloud_token, security_group_id)
    except:
        pass
    ids["security_group_id"]= security_group_id

    #create router and add network interfaces
    router_id= search_router(endpoints.get("neutron"), overcloud_token, settings["router_name"])
    if router_id is None:        
        router_id= create_router(endpoints.get("neutron"), overcloud_token, settings["router_name"], public_network_id,public_subnet_id )
    try:
        add_interface_to_router(endpoints.get("neutron"), overcloud_token, router_id, subnet2_id)
    except Exception as e:
        logging.debug("can not add port to router")
    try:     
        add_interface_to_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)
    except Exception as e:
        logging.debug("can not add port to router")
    ids["router_id"]= router_id

    #create ssh keypair and create new .pem file on director
    keypair_key= search_keypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    logging.debug("searching ssh key")
    keyfile_name= os.path.expanduser(settings["key_file"])

    if (keypair_key == None):
        keypair_private_key= create_keypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
        logging.debug("ssh key created")
        if os.path.exists(keyfile_name):
            try:
                #delete if .pem file already exists
                logging.debug("deleting old private file")
                os.system("sudo rm "+keyfile_name)
            except OSError:
                pass
        logging.debug("creating key file")
        #create new .pem file
        keyfile = open(keyfile_name, "w")
        keyfile.write(keypair_private_key)
        keyfile.close()
        #set permissions to .pem file
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
        #create encrypted image if barbican is enabled
        image_id= search_image(endpoints.get("nova"), overcloud_token, settings["image_name"])
        if(image_id is None):
            key= create_ssl_certificate(settings)
            image_signature= sign_image(settings, ini_file.get("image_file_name"))
            barbican_key_id= add_key_to_store(endpoints.get("barbican"), overcloud_token, key)
            image_id= create_barbican_image(endpoints.get("image"), overcloud_token, settings["image_name"], "bare", "qcow2", "public", image_signature, barbican_key_id)
        status= get_image_status(endpoints.get("image"), overcloud_token, image_id)
        if status== "queued":
            try:
                image_file= open(os.path.expanduser(ini_file.get("image_file_name")), 'rb')
                upload_file_to_image(endpoints.get("image"), overcloud_token, image_file, image_id)
            except:
                pass
    ids["image_id"]= image_id
    #Temporary changing quota
    logging.debug("temporary changing quota")
    project_id= find_admin_project_id(endpoints.get("keystone"), overcloud_token)
    try: 
        set_quota(endpoints.get("nova"), overcloud_token, project_id, 200, 25, 204800)
    except:
        pass
    
    return ids

#delete environment if testcase failes
def delete_environment(endpoints, overcloud_token, environment, settings):
    logging.info("\nCleaning Environment")
    #delete image    
    delete_image(endpoints.get("image"), overcloud_token, environment.get("image_id"))
    #remove interfaces from router
    try:
        remove_interface_from_router(endpoints.get("neutron"), overcloud_token, environment.get("router_id"), environment.get("subnet2_id"))
    except Exception as e:
        logging.debug("can not remove port from router")
    try:    
        remove_interface_from_router(endpoints.get("neutron"), overcloud_token, environment.get("router_id"), environment.get("subnet1_id"))
    except Exception as e:
        logging.debug("can not remove port from router")
    #delete networks
    delete_network(endpoints.get("neutron"), overcloud_token, environment.get("network1_id"))
    delete_network(endpoints.get("neutron"), overcloud_token, environment.get("network2_id"))
    #delete router
    delete_router(endpoints.get("neutron"), overcloud_token, environment.get("router_id"))
    #delete keypair
    delete_kaypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    #delete keypair file
    keyfile_name= os.path.expanduser(settings["key_file"])
    try:
        logging.debug("deleting old private file")
        os.system("sudo rm "+keyfile_name)
    except OSError:
        pass
    #delte servers if exist
    server1_id= search_server(endpoints.get("nova"), overcloud_token, settings["server_1_name"])
    if server1_id is not None:
        delete_server_with_id(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, server1_id)
    server2_id= search_server(endpoints.get("nova"), overcloud_token, settings["server_1_name"])
    if server2_id is not None:
        delete_server_with_id(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, server2_id)
    #delte flavors if exist
    flavor1_id=search_flavor(endpoints.get("nova"), overcloud_token, settings["flavor1_name"])
    if flavor1_id is not None:
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor1_id)
    flavor2_id=search_flavor(endpoints.get("nova"), overcloud_token, settings["flavor2_name"])
    if flavor2_id is not None:
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor2_id)

'''
OpenStack Testcases
'''
class TestOpenStack():
    '''
    Numa Testcases
    '''
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_flavor_creation(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(flavor_id is not None, "flavor is not successfully created", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_with_numa_flavor(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_number_of_vcpus_pinned_are_same_as_the_vcpus_in_numa_flavour(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        #verify vcpus of instance are 4 or not 
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 4)

        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Get VCPUS
        if(instance.get("status") == "active"):
            vcpus= get_vcpus_count_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #Get VCPUS of instance 
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(vcpus == "4", "instance do not have correct number of pinned vcpus", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_resizing(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 4)
        #create flavor to resize
        upscale_flavor= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor2_name"], settings, deployed_features, 8)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        vcpus_before= get_vcpus_count_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #resize server
        resize_status= resize_server(endpoints.get("nova"),overcloud_token, instance.get("id"), upscale_flavor)        
        time.sleep(30)
        #verisfy resizinf
        perform_action_on_server(endpoints.get("nova"), overcloud_token, instance.get("id"), "confirmResize")
        vcpus_after= get_vcpus_count_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, upscale_flavor)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        # verify instance resizing
        Assert(vcpus_before !=vcpus_after , "instance is not resized", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_ping(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)

        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_cold_migration(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)

        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        if instance.get("status") =="active":
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #cold migrate instance
            response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
            #new host
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_live_migration(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        if instance.get("status") =="active": 
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #live migrate instance
            response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
            #get host of instance
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)        
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instances_are_assigned_different_vcpus(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        
        #Get vcpus of instances
        if instance1.get("status") =="active" and instance2.get("status") =="active":
            instance1_vcpus= get_vcpus_list_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance1)
            instance2_vcpus= get_vcpus_list_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance2)
            #verify if any vcpu is assigned to both instances
            validate = [vcpu for vcpu in instance1_vcpus if vcpu in instance2_vcpus]
            if not validate:
                validate=True
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance1.get("status") == "active" and instance2.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(validate==True, "instacnes share vcpus on same compute node", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instances_will_have_vcpus_from_single_numa_node(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        
        if instance1.get("status") =="active" and instance2.get("status") =="active":
            #Get vcpus of instances
            instance1_vcpus= get_vcpus_list_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance1)
            instance2_vcpus= get_vcpus_list_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance2)
            #verify if list contains all even elements
            instance1_validation= verify_list_is_even_or_odd(instance1_vcpus)
            instance2_validation= verify_list_is_even_or_odd(instance2_vcpus)
        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance1.get("status") == "active" and instance2.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance1_validation==True and instance2_validation==True, "instacnes sdo not have vcpus from single numa node", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_numa_instances(compute0_ip, 20)
        print("Instances Possible")
        print(instances_possible)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)

        #create Instances
        for i in range (0, instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status[:-1] , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_with_20_vcpu_numa_flavor(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_numa_instances(compute0_ip, 20)
        print("Instances Possible")
        print(instances_possible)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)

        #create Instances
        for i in range (0, instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status[:-1] , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed_and_all_instances_are_paused(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)
        #create Instances    
        for i in range (0, instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0,"Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
            #pause all servers
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "pause")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status[:-1] , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed_and_all_instances_are_suspended(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)

        #create Instances    
        for i in range (0, instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
            #pause all servers
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "suspend")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status[:-1] , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed_and_all_instances_are_shutdown(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)
        #create Instances    
        for i in range (0, instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
            #pause all servers
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "shutdown")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status[:-1] , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.numa
    @pytest.mark.volume
    def test_verify_attach_volume_to_numa_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume successfully attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.volume
    def test_verify_detach_volume_from_numa_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.volume
    def test_verify_migration_of_numa_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("numa")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.volume
    def test_verify_create_snapshot_from_numa_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.numa
    @pytest.mark.volume
    def test_verify_create_numa_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            instance2= search_and_create_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id,  environment.get("network1_id"), environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
    
    '''
    Hugepage Testcases
    '''
    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_hugepage_flavor_creation(self, settings, baremetal_nodes, ini_file, endpoints, overcloud_token, environment):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(flavor_id is not None, "flavor is not successfully created", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_validate_hugepage_deplyment_with_size_set_to_1_GB_or_2_MB(self, settings, baremetal_nodes, ini_file, endpoints, overcloud_token, environment):
        skip_test_if_feature_not_enabled("hugepage")
        hugepages=[]
        #get ip adresses of all compute nodes
        compute_node_ips= [val for key, val in baremetal_nodes.items() if "compute" in key]
        for compute in compute_node_ips:
            output= ssh_into_node(compute, " grep Huge /proc/meminfo")
            huge_page_size= parse_hugepage_size(output[0], "Hugepagesize:")
            hugepages.append(huge_page_size)
        #check that all copute nodes have same hugepages size
        verify_hugepages= hugepages.count(hugepages[0]) == len(hugepages) 
        Assert(verify_hugepages == True, "Compute nodes do not have same hugepages", endpoints, overcloud_token, environment, settings)
        if(ini_file["hugepage_size"]== "1GB"):
            Assert(hugepages[0] == "1048576", "Compute nodes do not have 1GB hugepage size", endpoints, overcloud_token, environment, settings)
        else:
            Assert(hugepages[0] == "2048", "Compute nodes do not have 2MB hugepage size", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_with_hugepage_flavor(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepages", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_with_hugepage_1GB_flavor_and_1GB_deployment(self, settings, environment, endpoints, overcloud_token, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        if(ini_file["hugepage_size"] == "1GB"):
            Assert(instance.get("status") == "active", "instance state should be failed", endpoints, overcloud_token, environment, settings)
        else:
            Assert(instance.get("status") == "error", "instance state is not active", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.hugepage
    @pytest.mark.functional  
    def test_verify_instance_creation_with_hugepage_2MB_flavor_and_1GB_deployment(self, settings, environment, endpoints, overcloud_token, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, None, None, 2048)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        if(ini_file["hugepage_size"] == "1GB"):
            Assert(instance.get("status") == "error", "instance state should be failed", endpoints, overcloud_token, environment, settings)
        else:
            Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_hugepage_instance_ping(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_hugepage_instance_consumed_correct_number_of_hugepages(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        
        if(instance.get("status") == "active"):
            hugepage_size= get_hugepages_consumed_by_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #validate instance status
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        #validate hugepage size
        if(ini_file["hugepage_size"]== "1GB"):
            Assert(hugepage_size == "1048576", "instance have not consumed valid number of hugepages", endpoints, overcloud_token, environment, settings)
        else:
            Assert(gepage_size == "2048", "instance have not consumed valid number of hugepages", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_hugepage_instance_resizing(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")

        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 4)
        #create flavor to resize
        upscale_flavor= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor2_name"], settings, deployed_features, 8)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        vcpus_before= get_vcpus_count_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #resize server
        resize_status= resize_server(endpoints.get("nova"),overcloud_token, instance.get("id"), upscale_flavor)        
        time.sleep(30)
        #verisfy resizinf
        perform_action_on_server(endpoints.get("nova"), overcloud_token, instance.get("id"), "confirmResize")
        vcpus_after= get_vcpus_count_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, upscale_flavor)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        # verify instance resizing
        Assert(vcpus_before !=vcpus_after , "instance is not resized", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage    
    @pytest.mark.functional
    def test_verify_hugepage_instance_cold_migration(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #cold migrate instance
        response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
        #new host
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage 
    @pytest.mark.functional
    def test_verify_hugepage_instance_live_migration(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)        
        
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_hugepages_are_consumed(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_hugepage_instances(compute0_ip, 20)
        print(instances_possible)
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, 20480)
        #create Instances
        for i in range (0,instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status and instances_possible>0, "instances are not created as expected when hugaepages are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created  as expected when hugaepages are consumed ", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_hugepages_are_consumed_and_all_instances_are_paused(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_hugepage_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, 20480)
        #create Instances
        for i in range (0,instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #pause all instances
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "pause")
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status and instances_possible>0 , "instances are not created as expected when hugaepages are not consumed and all instances are paused", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created  as expected when hugaepages are consumed and all instances are paused", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_hugepages_are_consumed_and_all_instances_are_suspended(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_hugepage_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, 20480)
        #create Instances
        for i in range (0,instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #suspend instances
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "suspend")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status and instances_possible>0 , "instances are not created as expected when hugaepages are not consumed and all instances are suspended", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created  as expected when hugaepages are consumed and all instances are suspended", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_hugepages_are_consumed_and_all_instances_are_shutdown(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_hugepage_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, 20480)
        #create Instances
        for i in range (0,instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #shutdown all instances
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "shutdown")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status and instances_possible>0 , "instances are not created as expected when hugaepages are not consumed and all instances are shutdown", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created  as expected when hugaepages are consumed and all instances are shutdown", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_maximum_instance_creation_with_hugepage_flavor_size_22GB(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        available_ram= get_available_ram_of_node(compute0_ip)
        instances_possible= math.floor(int(available_ram)/22)
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, 22528)
        #create Instances
        for i in range (0, instances_possible-3):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status and instances_possible>0  , "instances are not created as expected with 22GB flavor", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.volume
    def test_verify_attach_volume_to_hugepage_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume successfully attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.volume
    def test_verify_detach_volume_from_hugepage_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.volume
    def test_verify_migration_of_hugepage_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("hugepage")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.volume
    def test_verify_create_snapshot_from_hugepage_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.hugepage
    @pytest.mark.volume
    def test_verify_create_hugepage_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            instance2= search_and_create_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id,  environment.get("network1_id"), environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
    
    '''
    Sriov Testcases 
    '''
    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_sriov_vfs_are_created_and_in_up_state(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("sriov")
        #get ip of compute nodes
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        #check status of interfaces
        sriov_interfaces_status= get_sriov_enabled_interfaces(nodes_ips)
        #Validate interfaces
        Assert(sriov_interfaces_status == True, "SRIOV interface/s are not up", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_the_mode_for_sriov_pci_device(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("sriov")
        #get ip of compute nodes
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        #get swtch dev mode
        pci_device_mode= get_mode_of_sriov_pci_devices(nodes_ips)
        #Validate switch mode
        Assert(pci_device_mode == True, "switch mode is not legacy", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_sriov_instance_creation(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        #ping test instance
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_ssh_into_sriov_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None,"No", "sriov", environment.get("subnet1_id"))
        #ping test instance
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        if ping_response==0:
            ssh= instance_ssh_test(instance.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ssh == True, "can not ssh into instance", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_two_sriov_instance_on_same_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_two_sriov_instance_on_different_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute1, "No", "sriov", environment.get("subnet1_id"))
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_two_sriov_instance_on_same_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute0, "No", "sriov", environment.get("subnet2_id"))
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_two_sriov_instance_on_different_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute1, "No", "sriov", environment.get("subnet2_id"))
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_sriov_and_simple_instance_on_same_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"),compute0)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_sriov_and_simple_instance_on_different_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"),compute1)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_sriov_and_simple_instance_on_same_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"),compute0)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_communication_of_sriov_and_simple_instance_on_different_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"),compute1)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_sriov_instance_cold_migration(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        if instance.get("status") =="active":
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #cold migrate instance
            response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
            #new host
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.sriov
    @pytest.mark.functional
    def test_verify_sriov_instance_live_migration(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        if instance.get("status") =="active": 
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #live migrate instance
            response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
            #get host of instance
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)        
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.functional
    def test_reboot_the_sriov_instance_and_check_the_vf_connectivity(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        #ping test instance
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
            #reboot instance
            print("rebooting")
            reboot_server(endpoints.get("nova"), overcloud_token, instance.get("id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance.get("id")])
            ping_test= ping_test_between_instances(instance.get("floating_ip"), "8.8.8.8", settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test[0] == True, "instance failed to ping 8.8.8.8", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.volume
    def test_verify_attach_volume_to_sriov_instance_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume not attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.volume
    def test_verify_detach_volume_from_sriov_instance_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.volume
    def test_verify_migration_of_sriov_instance_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("sriov")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "sriov", environment.get("subnet1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.volume
    def test_verify_create_snapshot_from_sriov_instance_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.sriov
    @pytest.mark.volume
    def test_verify_create_sriov_instance_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("sriov")
        #create flavor
        flavor_id= get_flavor_id("sriov", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "sriov", environment.get("subnet1_id"))
        #create snapshot
        instance_snapshot_id=instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            port2_id, port2_ip= create_port(endpoints.get("neutron"), overcloud_token, environment.get("network1_id"), environment.get("subnet1_id"), settings["sriov_port_name"], "vflag")
            instance2= search_and_create_sriov_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id, port2_id, environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token,port2_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
  
    '''
    Barbican Testcases 
    '''
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_create_barbican_secret(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("barbican")
        secret_id= create_barbican_secret(endpoints.get("barbican"), overcloud_token)
        delete_secret(endpoints.get("barbican"), secret_id, overcloud_token)
        Assert(secret_id !="" or None, "barbican secret creation failed", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_search_barbican_secret(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("barbican")
        secret_id= create_barbican_secret(endpoints.get("barbican"), overcloud_token)
        search_secret= get_secret(endpoints.get("barbican"), overcloud_token, secret_id)
        delete_secret(endpoints.get("barbican"), secret_id, overcloud_token)
        Assert(search_secret !="" or None, "barbican secret not found", endpoints, overcloud_token, environment, settings)
 
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_barbican_secret_payload(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("barbican")
        secret_id= create_barbican_secret(endpoints.get("barbican"), overcloud_token)
        payload= get_payload(endpoints.get("barbican"), overcloud_token, secret_id)
        delete_secret(endpoints.get("barbican"), secret_id, overcloud_token)
        Assert(payload =="test_case payload", "secret has incorrect payload", endpoints, overcloud_token, environment, settings)
  
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_deletion_of_barbican_secret(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("barbican")
        secret_id= create_barbican_secret(endpoints.get("barbican"), overcloud_token)
        delete_secret(endpoints.get("barbican"), secret_id, overcloud_token)
        search_secret= get_secret(endpoints.get("barbican"), overcloud_token, secret_id)
        Assert(search_secret ==None, "failed to delete barbican secret", endpoints, overcloud_token, environment, settings)
  
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_creation_of_symmetric_key(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("barbican")
        secret_id= add_symmetric_key_to_store(endpoints.get("barbican"), overcloud_token)
        search_secret= get_secret(endpoints.get("barbican"), overcloud_token, secret_id)
        delete_secret(endpoints.get("barbican"), secret_id, overcloud_token)
        Assert(search_secret !="None", "failed to create symmetric key", endpoints, overcloud_token, environment, settings)
  
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_barbican_image_creation(self, settings, environment, endpoints, overcloud_token, ini_file):
        skip_test_if_feature_not_enabled("barbican")
        #create barbican image
        key= create_ssl_certificate(settings)
        image_signature= sign_image(settings, ini_file.get("image_file_name"))
        barbican_key_id= add_key_to_store(endpoints.get("barbican"), overcloud_token, key)
        image_id= create_barbican_image(endpoints.get("image"), overcloud_token, settings["image2_name"], "bare", "qcow2", "public", image_signature, barbican_key_id)
        status= get_image_status(endpoints.get("image"), overcloud_token, image_id)
        #if image is queued upload file
        if status== "queued":
            try:
                image_file= open(os.path.expanduser(ini_file.get("image_file_name")), 'rb')
                upload_file_to_image(endpoints.get("image"), overcloud_token, image_file, image_id)
            except:
                pass
        #get image status
        image_status= get_image_status(endpoints.get("image"), overcloud_token, image_id)
        #delete image
        delete_image(endpoints.get("image"), overcloud_token, image_id)
        Assert(image_status == "active", "barbican image is not in active state", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_barbican_instance_creation(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create flavor
        flavor_id= get_flavor_id("barbican", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_volume_creation_with_signed_image(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create instance
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), None, environment.get("image_id"))
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #verify volume creation
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.barbican
    @pytest.mark.functional
    def test_verify_image_signatures_of_volume(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create instance
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), None, environment.get("image_id"))
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #Get volume metadata
        volume_metadata= get_volume_metadata(endpoints.get("cinder"), overcloud_token, volume_id, environment.get("project_id"))
        #delete instance
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #verify volume creation
        Assert("'signature_verified': 'True'" in str(volume_metadata), "volume signature verification failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.barbican
    @pytest.mark.volume
    def test_verify_attach_volume_to_barbican_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create flavor
        flavor_id= get_flavor_id("barbican", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume successfully attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.barbican
    @pytest.mark.volume
    def test_verify_detach_volume_from_barbican_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create flavor
        flavor_id= get_flavor_id("barbican", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.barbican
    @pytest.mark.volume
    def test_verify_migration_of_barbican_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("barbican")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("barbican", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.barbican
    @pytest.mark.volume
    def test_verify_create_snapshot_from_barbican_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create flavor
        flavor_id= get_flavor_id("barbican", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.barbican
    @pytest.mark.volume
    def test_verify_create_barbican_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("barbican")
        #create flavor
        flavor_id= get_flavor_id("barbican", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            instance2= search_and_create_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id,  environment.get("network1_id"), environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)


    '''
    DVR Testcases 
    '''
    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_is_deployed_on_all_controller_nodes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        nodes_ips= get_node_ip(baremetal_nodes, "controller")
        dvr_enabled= verify_dvr_agent_on_nodes(nodes_ips, "controller")
        Assert(dvr_enabled == True, "dvr is not enabled on all controller nodes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_is_deployed_on_all_compute_nodes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        dvr_enabled= verify_dvr_agent_on_nodes(nodes_ips, "compute")
        Assert(dvr_enabled == True, "dvr is not enabled on all compute nodes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_that_l3agent_must_be_distributed_on_all_the_compute_nodes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        agents= get_agent_list(endpoints.get("neutron"), overcloud_token)
        total_l3_agents= agents.count("L3 agent")
        total_compute_nodes= len(get_node_ip(baremetal_nodes, "compute"))
        total_controller_nodes= len(get_node_ip(baremetal_nodes, "controller"))
        Assert(total_l3_agents == (total_compute_nodes+total_controller_nodes), "L3 agent is not distributed on all nodes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_that_metadata_agent_must_be_distributed_on_all_the_compute_nodes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        agents= get_agent_list(endpoints.get("neutron"), overcloud_token)
        total_l3_agents= agents.count("Metadata agent")
        total_compute_nodes= len(get_node_ip(baremetal_nodes, "compute"))
        total_controller_nodes= len(get_node_ip(baremetal_nodes, "controller"))
        Assert(total_l3_agents == (total_compute_nodes+total_controller_nodes), "Metadata agent is not distributed on all nodes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_that_L2_population_driver_must_be_enabled_on_all_the_compute_and_controller_nodes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        #get IP's of compte nodes
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        #get IP's of controller nodes
        compute_drivers= verify_l2_population_driver_on_nodes(nodes_ips)
        nodes_ips= get_node_ip(baremetal_nodes, "controller")
        controller_drivers= verify_l2_population_driver_on_nodes(nodes_ips)
        Assert(compute_drivers == True, "L2population driver is not enabled on all compute nodes", endpoints, overcloud_token, environment, settings)
        Assert(controller_drivers == True, "L2population driver is not enabled on all controller nodes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_settings_of_dvr_are_persistent_when_compute_is_restsarted(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        nodes_ip= get_node_ip(baremetal_nodes, "compute")
        #restart compute node
        restart_baremetal_node(nodes_ip[0], settings)
        #verify dvr
        dvr_enabled= verify_dvr_agent_on_nodes(nodes_ip, "compute")
        Assert(dvr_enabled == True, "dvr is enabled persistent restarting compute", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_settings_of_dvr_are_persistent_when_controller_is_restsarted(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        nodes_ip= get_node_ip(baremetal_nodes, "controller")
        #restart compute node
        restart_baremetal_node(nodes_ip[0], settings)
        #verify dvr
        dvr_enabled= verify_dvr_agent_on_nodes(nodes_ip, "controller")
        Assert(dvr_enabled == True, "dvr is persistent after restarting controller", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_instance_ping(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_that_traffic_between_two_compute_nodes_bypass_the_controller_node(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        controller0_ip=  get_node_ip(baremetal_nodes, "controller-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute1)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            router_namespace= "qrouter-"+environment.get("router_id")  
            received_icmp=verify_traffic_on_namespace(controller0_ip, router_namespace, instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp== False, "icmp packets received on controllers", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_the_snat_traffic_transverse_through_the_controller_node(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        controller0_ip=  get_node_ip(baremetal_nodes, "controller-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if(instance1.get("floating_ip") is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
        if ping_response1==0:
            router_namespace= "snat-"+environment.get("router_id")  
            received_icmp=verify_traffic_on_namespace(controller0_ip, router_namespace, instance1.get("floating_ip"), "8.8.8.8", settings)        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance1.get("status") , "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 , "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp== True, "external traffic did not pass through SNAT namespace", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_external_traffic_must_bypass_the_floating_ip_namespace_of_controller_node(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        controller0_ip=  get_node_ip(baremetal_nodes, "controller-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if(instance1.get("floating_ip") is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
        if ping_response1==0:
            fip_namespace= get_namespace_id(controller0_ip, "fip-") 
            received_icmp=verify_traffic_on_namespace(controller0_ip, fip_namespace, instance1.get("floating_ip"), "8.8.8.8", settings)
        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance1.get("status") , "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 , "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp== False, "external traffic did not bypassed controller fip namespace", endpoints, overcloud_token, environment, settings)  

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_that_traffic_from_compute_is_routed_through_the_l3_agent_hosted_by_itself(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if(instance1.get("floating_ip") is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
        if ping_response1==0:
            router_namespace= "qrouter-"+environment.get("router_id")  
            received_icmp=verify_traffic_on_namespace(compute0_ip, router_namespace, instance1.get("floating_ip"), "8.8.8.8", settings)
        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance1.get("status"), "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp== True, "icmp packets received on compute router namespace", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_external_traffic_must_pass_through_the_floating_ip_namespace_of_compute_node(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if(instance1.get("floating_ip") is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
        if ping_response1==0:
            fip_namespace= get_namespace_id(compute0_ip, "fip-")  
            received_icmp=verify_traffic_on_namespace(compute0_ip, fip_namespace, instance1.get("floating_ip"), "8.8.8.8", settings)
        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance1.get("status"), "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp== True, "icmp packets received on compute router namespace", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_l3_ha_disabled_on_controllers(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        nodes_ips= get_node_ip(baremetal_nodes, "controller")
        l3_ha= verify_l3_ha_on_nodes(nodes_ips)
        Assert(l3_ha == True, "l3_ha is not disabled on controller", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_qrouter_namespace_is_created_on_compute(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Get namespace
        namespace_id= get_namespace_id(compute0_ip, "qr-")
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(namespace_id != "", "qrouter namespace not found", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_flotaing_ip_namespace_is_created_on_compute(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Get namespace
        namespace_id= get_namespace_id(compute0_ip, "fip-")
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(namespace_id != "", "floating ip namespace not found", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_delete_all_the_instance_from_one_of_the_compute_node_to_see_that_router_namespace_still_exits(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("dvr")
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #Get namespace
        namespace_id= get_namespace_id(compute0_ip, "qr-")        
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(namespace_id is not None, "qrouter existes on compute node", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_down_the_L3_agent_on_one_of_compute_node_and_send_traffic_from_this_node(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #get compute node name and ip
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute1)
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
            ping_test_before_service_stop= ping_test_between_instances(instance.get("floating_ip"), instance2.get("ip"), settings)
        #stop l3 service
        stop_service_on_node(compute0_ip, "tripleo_neutron_l3_agent.service")
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response_after_serice_stop =ping_test_between_instances(instance.get("floating_ip"), instance2.get("ip"), settings)
        start_service_on_node(compute0_ip, "tripleo_neutron_l3_agent.service")
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        
        print(ping_test_before_service_stop)
        print(ping_response_after_serice_stop)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_test_before_service_stop[0] == True, "instance can not ping other network", endpoints, overcloud_token, environment, settings)
        Assert(ping_response_after_serice_stop[0] != True, "instance can ping other network after l3 service is disabled", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_is_work_fine_with_numa(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        skip_test_if_feature_not_enabled("numa")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)

        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_is_work_fine_with_hugepage(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        skip_test_if_feature_not_enabled("hugepage")
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_instance_cold_migration(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)

        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        if instance.get("status") =="active":
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #cold migrate instance
            response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
            #new host
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.dvr
    @pytest.mark.functional
    def test_verify_dvr_instance_live_migration(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        if instance.get("status") =="active": 
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #live migrate instance
            response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
            #get host of instance
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)        
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.dvr
    @pytest.mark.volume
    def test_verify_attach_volume_to_dvr_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume successfully attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.volume
    def test_verify_detach_volume_from_dvr_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.volume
    def test_verify_migration_of_dvr_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dvr")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.volume
    def test_verify_create_snapshot_from_dvr_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dvr
    @pytest.mark.volume
    def test_verify_create_dvr_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dvr")
        #create flavor
        flavor_id= get_flavor_id("dvr", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            instance2= search_and_create_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id,  environment.get("network1_id"), environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)


    '''
    OVS DPDK Testcases
    '''
    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_ovs_dpdk_is_deployed_on_all_compute_nodes_after_script_execution(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        dpdk_service_status= verify_status_of_ovs_dpdk_service(nodes_ips)
        Assert(dpdk_service_status == True, "OVS-DPDK service is not active on all computes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_ports_are_assigned_correctly_to_ovs_dpdk_in_mode_I_and_II(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        dpdk_ports= get_ovs_dpdk_ports(nodes_ips, ini_file.get("dpdk_ports"))
        Assert(dpdk_ports == True, "DPDK don not have correct ports", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_ports_assigned_to_ovs_dpdk_are_active_after_the_deployment(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        active_ports= verify_status_of_dpdk_ports(nodes_ips, ini_file.get("dpdk_ports"))
        Assert(active_ports == True, "DPDK dports are not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional 
    def test_verify_neutron_service_is_working_fine_with_ovs_dpdk(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        command= "timeout 2 systemctl status tripleo_neutron_ovs_agent.service"
        neutron_service_status= subprocess.run([command], shell=True, stdout=subprocess.PIPE)
        Assert("active (running)" in neutron_service_status.stdout.decode('utf-8'), "Neutron service is not working properly", endpoints, overcloud_token, environment, settings)
     
    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_hugegages_are_consumed_appropriately_after_deployment_of_ovsdpdk(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        #get ip of compuye node
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get hugepage info
        output= ssh_into_node(compute0_ip, " grep Huge /proc/meminfo")
        print("@@@@@@")
        print(output)
        output=output[0]
        #get free hugepage
        total_hugepage= parse_hugepage_size(output, "HugePages_Total:")
        #get free hugepage
        hugepg_free= parse_hugepage_size(output, "HugePages_Free:")
        print("@@@@@@")
        print((int(total_hugepage)-int(hugepg_free)))
        #validate hugepage size
        Assert((int(total_hugepage)-int(hugepg_free))== 5, "hugepages are not consumed appropriately after deployment", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_that_ovs_service_is_working_properly_when_deployed(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        ovs_service_status= verify_status_of_ovs_service(nodes_ips)
        Assert(ovs_service_status == True, "OVS service is not working properly", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_ovs_bridges_are_working_correctly_when_instances_created(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        bridges_status= verify_ovs_dpdk_bridges(nodes_ips)
        Assert(bridges_status == True, "OVS service is not working properly", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_dpdk_instance_ceation(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_the_ovs_dpdk_works_fine_with_floating_ip(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
            ping_test= ping_test_between_instances(instance.get("floating_ip"), "8.8.8.8", settings)

        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test[0] == True, "floating ip is working fine", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def validate_ovs_virtual_nics_are_assigned_with_correct_ips_on_instance_reboot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #ping test instance
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
            #reboot instance
            reboot_server(endpoints.get("nova"), overcloud_token, instance.get("id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance.get("id")])
            ping_response2 = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_response2 == 0, "instance do not have correct ip after restart", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_the_communication_of_two_ovs_dpdk_instance_in_same_compute_node_with_only_one_instance_having_floating_ip(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if(instance1.get("floating_ip") is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
        if ping_response1==0 :
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 , "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True , "communication between instances failed when one instance has only floating ip", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_communication_of_two_dpdk_instance_on_same_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_communication_of_two_dpdk_instance_on_different_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute1)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") and instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional 
    def validates_the_ovs_dpdk_is_working_fine_with_the_memory_flavor_assigned_in_hugepages(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #put hugepage specs in flavor
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, False, "large")
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "yes")
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_validate_the_scenario_when_ovs_Service_is_restarted(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        #get compute node and ip
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #restart ovs service
        restart_service_on_node(compute0_ip, "ovs-vswitchd")
        #wait for dpdk ports to become online
        time.sleep(30)
        #Ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed after restarting OVS service", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.functional
    def test_verify_instance_creation_with_dpdk_flaor_when_all_vcpus_are_consumed(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)
        #create Instances
        for i in range (0, instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "Yes")
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status[:-1] , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.volume
    def test_verify_attach_volume_to_dpdk_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume successfully attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.volume
    def test_verify_detach_volume_from_dpdk_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.volume
    def test_verify_migration_of_dpdk_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("dpdk")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.volume
    def test_verify_create_snapshot_from_dpdk_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.dpdk
    @pytest.mark.volume
    def test_verify_create_dpdk_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("dpdk")
        #create flavor
        flavor_id= get_flavor_id("dpdk", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            instance2= search_and_create_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id,  environment.get("network1_id"), environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    '''
    MTU9000 Testcases
    '''
    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_compute_nodes_network_settings_for_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        interfaces_mtu_status= get_interfaces_mtu_size(nodes_ips)
        Assert(interfaces_mtu_status == True, "Mtu9000 is not enabled on all interfaces", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_controller_nodes_network_settings_for_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "controller")
        interfaces_mtu_status= get_interfaces_mtu_size(nodes_ips)
        Assert(interfaces_mtu_status == True, "Mtu9000 is not enabled on all interfaces", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_storage_nodes_network_settings_for_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "storage")
        interfaces_mtu_status= get_interfaces_mtu_size(nodes_ips)
        Assert(interfaces_mtu_status == True, "Mtu9000 is not enabled on all interfaces", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_by_pinging_one_storage_node_to_another_by_byte_size_of_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "storage")
        interfaces_mtu_status= ping_nodes_on_custom_mtu(nodes_ips, 8972)
        Assert(interfaces_mtu_status == True, "Nodes can not ping each other with MTU9000", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_by_pinging_one_controller_node_to_another_by_byte_size_of_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "controller")
        interfaces_mtu_status= ping_nodes_on_custom_mtu(nodes_ips, 8972)
        Assert(interfaces_mtu_status == True, "Nodes can not ping each other with MTU9000", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_by_pinging_one_compute_node_to_another_by_byte_size_of_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        interfaces_mtu_status= ping_nodes_on_custom_mtu(nodes_ips, 8972)
        Assert(interfaces_mtu_status == True, "Nodes can not ping each other with MTU9000", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_network_creation_on_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        network= get_network_detail(endpoints.get("neutron"), overcloud_token, environment.get("network1_id"))
        Assert(network["network"]["mtu"]==9000 , "network do not have MTU9000", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_route_creation_on_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        router_id= search_router(endpoints.get("neutron"), overcloud_token, settings["router_name"])
        Assert(router_id is not None , "router is not created", endpoints, overcloud_token, environment, settings)
   
    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_instance_creation_on_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_floating_ip_allocation_on_mtu_size_9000(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("floating_ip") is not None, "floating ip not assigned to instance", endpoints, overcloud_token, environment, settings)    
    
    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_communication_of_mtu9000_instance_on_same_compute_and_same_tenant_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            command="ping -c 3 -s 8972 -M do {}".format(instance2.get("floating_ip"))
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            print(ping_test1)
            command="ping -c 3 -s 8972 -M do {}".format(instance1.get("floating_ip"))
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings, command)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        #verify instance ping
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        #verify communication between instances
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_communication_of_mtu9000_instance_on_different_compute_and_same_tenant_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute1)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            command="ping -c 3 -s 8972 -M do {}".format(instance2.get("floating_ip"))
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            print(ping_test1)
            command="ping -c 3 -s 8972 -M do {}".format(instance1.get("floating_ip"))
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings, command)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        #verify instance ping
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        #verify communication between instances
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_communication_of_mtu9000_instance_on_same_compute_and_different_tenant_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute0)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            command="ping -c 3 -s 8972 -M do {}".format(instance2.get("floating_ip"))
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            print(ping_test1)
            command="ping -c 3 -s 8972 -M do {}".format(instance1.get("floating_ip"))
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings, command)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        #verify instance ping
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        #verify communication between instances
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_communication_of_mtu9000_instance_on_different_compute_and_different_tenant_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute1)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            command="ping -c 3 -s 8972 -M do {}".format(instance2.get("floating_ip"))
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            print(ping_test1)
            command="ping -c 3 -s 8972 -M do {}".format(instance1.get("floating_ip"))
            ping_test2= ping_test_between_instances(instance2.get("floating_ip"), instance1.get("floating_ip"), settings, command)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        #verify instance ping
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        #verify communication between instances
        Assert(ping_test1[0] == True and ping_test2[0]==True, "communication between instances failed", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_tnshat_itances_are_able_communicate_with_eachother_on_lower_mtu_sizes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("mtu9000", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #ping test instance
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            command="ping -c 3 -s 64 -M do {}".format(instance2.get("floating_ip"))
            ping_test_64= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            command="ping -c 3 -s 128 -M do {}".format(instance2.get("floating_ip"))
            ping_test_128= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            command="ping -c 3 -s 512 -M do {}".format(instance2.get("floating_ip"))
            ping_test_512= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            command="ping -c 3 -s 1500 -M do {}".format(instance2.get("floating_ip"))
            ping_test_1500= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            command="ping -c 3 -s 3000 -M do {}".format(instance2.get("floating_ip"))
            ping_test_3000= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)
            command="ping -c 3 -s 6000 -M do {}".format(instance2.get("floating_ip"))
            ping_test_6000= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings, command)

        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        #verify instance ping
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        #verify communication between instances
        Assert(ping_test_64[0] == True, "communication between instances failed on mtu size 64", endpoints, overcloud_token, environment, settings)
        Assert(ping_test_128[0] == True, "communication between instances failed on mtu size 128", endpoints, overcloud_token, environment, settings)
        Assert(ping_test_512[0] == True, "communication between instances failed on mtu size 512", endpoints, overcloud_token, environment, settings)
        Assert(ping_test_1500[0] == True, "communication between instances failed on mtu size 512", endpoints, overcloud_token, environment, settings)
        Assert(ping_test_3000[0] == True, "communication between instances failed on mtu size 512", endpoints, overcloud_token, environment, settings)
        Assert(ping_test_6000[0] == True, "communication between instances failed on mtu size 512", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_storage_nodes_are_able_communicate_with_eachother_on_lower_mtu_sizes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "storage")
        ping_64= ping_nodes_on_custom_mtu(nodes_ips, 64)
        ping_128= ping_nodes_on_custom_mtu(nodes_ips, 128)
        ping_512= ping_nodes_on_custom_mtu(nodes_ips, 512)
        ping_1500= ping_nodes_on_custom_mtu(nodes_ips, 1500)
        ping_3000= ping_nodes_on_custom_mtu(nodes_ips, 3000)
        ping_6000= ping_nodes_on_custom_mtu(nodes_ips, 6000)
        #validate ping responses
        Assert(ping_64 == True, "Nodes can not ping each other with mtu size 64", endpoints, overcloud_token, environment, settings)
        Assert(ping_128 == True, "Nodes can not ping each other with mtu size 128", endpoints, overcloud_token, environment, settings)
        Assert(ping_512 == True, "Nodes can not ping each other with mtu size 512", endpoints, overcloud_token, environment, settings)
        Assert(ping_1500 == True, "Nodes can not ping each other with mtu size 1500", endpoints, overcloud_token, environment, settings)
        Assert(ping_3000 == True, "Nodes can not ping each other with mtu size 3000", endpoints, overcloud_token, environment, settings)
        Assert(ping_6000 == True, "Nodes can not ping each other with mtu size 6000", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_controller_nodes_are_able_communicate_with_eachother_on_lower_mtu_sizes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "controller")
        ping_64= ping_nodes_on_custom_mtu(nodes_ips, 64)
        ping_128= ping_nodes_on_custom_mtu(nodes_ips, 128)
        ping_512= ping_nodes_on_custom_mtu(nodes_ips, 512)
        ping_1500= ping_nodes_on_custom_mtu(nodes_ips, 1500)
        ping_3000= ping_nodes_on_custom_mtu(nodes_ips, 3000)
        ping_6000= ping_nodes_on_custom_mtu(nodes_ips, 6000)
        #validate ping responses
        Assert(ping_64 == True, "Nodes can not ping each other with mtu size 64", endpoints, overcloud_token, environment, settings)
        Assert(ping_128 == True, "Nodes can not ping each other with mtu size 128", endpoints, overcloud_token, environment, settings)
        Assert(ping_512 == True, "Nodes can not ping each other with mtu size 512", endpoints, overcloud_token, environment, settings)
        Assert(ping_1500 == True, "Nodes can not ping each other with mtu size 1500", endpoints, overcloud_token, environment, settings)
        Assert(ping_3000 == True, "Nodes can not ping each other with mtu size 3000", endpoints, overcloud_token, environment, settings)
        Assert(ping_6000 == True, "Nodes can not ping each other with mtu size 6000", endpoints, overcloud_token, environment, settings)

    @pytest.mark.mtu9000
    @pytest.mark.functional
    def test_verify_compute_nodes_are_able_communicate_with_eachother_on_lower_mtu_sizes(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("mtu9000")
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        ping_64= ping_nodes_on_custom_mtu(nodes_ips, 64)
        ping_128= ping_nodes_on_custom_mtu(nodes_ips, 128)
        ping_512= ping_nodes_on_custom_mtu(nodes_ips, 512)
        ping_1500= ping_nodes_on_custom_mtu(nodes_ips, 1500)
        ping_3000= ping_nodes_on_custom_mtu(nodes_ips, 3000)
        ping_6000= ping_nodes_on_custom_mtu(nodes_ips, 6000)
        #validate ping responses
        Assert(ping_64 == True, "Nodes can not ping each other with mtu size 64", endpoints, overcloud_token, environment, settings)
        Assert(ping_128 == True, "Nodes can not ping each other with mtu size 128", endpoints, overcloud_token, environment, settings)
        Assert(ping_512 == True, "Nodes can not ping each other with mtu size 512", endpoints, overcloud_token, environment, settings)
        Assert(ping_1500 == True, "Nodes can not ping each other with mtu size 1500", endpoints, overcloud_token, environment, settings)
        Assert(ping_3000 == True, "Nodes can not ping each other with mtu size 3000", endpoints, overcloud_token, environment, settings)
        Assert(ping_6000 == True, "Nodes can not ping each other with mtu size 6000", endpoints, overcloud_token, environment, settings)

    '''
    Offloading
    '''
    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_vfs_are_created_and_in_up_state(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("offloading")
        #get ip of compute nodes
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        #check status of interfaces
        sriov_interfaces_status= get_sriov_enabled_interfaces(nodes_ips)
        #Validate interfaces
        Assert(sriov_interfaces_status == True, "SRIOV interface/s are not up", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_ovsoffload_status(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("offloading")
        #get ip of compute nodes
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        #check status of interfaces
        offload_status= get_ovsoffload_status(nodes_ips)
        #Validate interfaces
        Assert(offload_status == True, "Vflag is not enabled on all compute nodes", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_verify_the_mode_for_pci_device(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        skip_test_if_feature_not_enabled("offloading")
        #get ip of compute nodes
        nodes_ips= get_node_ip(baremetal_nodes, "compute")
        #get swtch dev mode
        pci_device_mode= get_mode_of_pci_devices(nodes_ips)
        #Validate switch mode
        Assert(pci_device_mode == True, "switch mode is not switchdev", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_ovs_offload_instance_creation(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        #ping test instance
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_creation_of_representor_port(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        last_representor_port= get_last_created_presenter_port(compute0_ip)
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "yes", "vflag", environment.get("subnet1_id"))
        #ping test instance
        if(instance.get("status") == "active"):   
            new_representor_port= get_last_created_presenter_port(compute0_ip)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(last_representor_port != new_representor_port, "representor port not created", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_two_ovs_offload_instance_on_same_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id")) 
        #wiat for some time to appear traffic on representor port as instances are already pinged during creation
        time.sleep(30)
        if instance1.get("status")=="active" and instance2.get("status")=="active":
            received_icmp=verify_offloading_on_representor_port(compute0_ip, instance1.get("floating_ip"), instance2.get("floating_ip"), settings)        
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp ==True, "offloading testing failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_two_ovs_offload_instance_on_different_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute1_ip=  get_node_ip(baremetal_nodes, "compute-1")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"), compute1, "No", "vflag", environment.get("subnet1_id"))
        #wiat for some time to appear traffic on representor port as instances are already pinged during creation
        time.sleep(30)
        if instance1.get("status")=="active" and instance2.get("status")=="active":
            received_icmp=verify_offloading_on_representor_port(compute1_ip, instance1.get("floating_ip"), instance2.get("floating_ip"), settings)        
         #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp ==True, "offloading testing failed", endpoints, overcloud_token, environment, settings)     
   
    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_two_ovs_offload_instance_on_same_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=  get_node_ip(baremetal_nodes, "compute-0")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute0, "No", "vflag", environment.get("subnet2_id"))
        #wiat for some time to appear traffic on representor port as instances are already pinged during creation
        time.sleep(30)
        if instance1.get("status")=="active" and instance2.get("status")=="active":
            received_icmp=verify_offloading_on_representor_port(compute0_ip, instance1.get("floating_ip"), instance2.get("floating_ip"), settings)        
         #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp ==True, "offloading testing failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_two_ovs_offload_instance_on_different_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute1_ip=  get_node_ip(baremetal_nodes, "compute-1")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"), compute1, "No", "vflag", environment.get("subnet2_id"))
        #wiat for some time to appear traffic on representor port as instances are already pinged during creation
        time.sleep(30)
        if instance1.get("status")=="active" and instance2.get("status")=="active":
            received_icmp=verify_offloading_on_representor_port(compute1_ip, instance1.get("floating_ip"), instance2.get("floating_ip"), settings)        
 
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(received_icmp ==True, "offloading testing failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_ovs_offload_and_simple_instance_on_same_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"),compute0)
        #ping test
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)

        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_ovs_offload_and_simple_instance_on_different_compute_and_same_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network1_name"], environment.get("network1_id"),compute1)
        ##ping test
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_ovs_offload_and_simple_instance_on_same_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"),compute0)
        #ping test
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_communication_of_ovs_offload_and_simple_instance_on_different_compute_and_different_network(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #Get compute nodes
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_2_name"], settings["network2_name"], environment.get("network2_id"),compute1)
        #ping test
        if((instance1.get("floating_ip") or instance2.get("floating_ip")) is not None):
            ping_response1 = os.system("ping -c 3 " + instance1.get("floating_ip"))
            ping_response2 = os.system("ping -c 3 " + instance2.get("floating_ip"))
        if ping_response1==0 and ping_response2==0:
            ping_test1= ping_test_between_instances(instance1.get("floating_ip"), instance2.get("floating_ip"), settings)
            #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance1.get("port_id"))
        delete_port(endpoints.get("neutron"), overcloud_token, instance2.get("port_id"))
        #check status of server is active or not
        Assert((instance1.get("status") or instance2.get("status"))   == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response1 == 0 and ping_response2==0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test1[0] == True, "communication between instances failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_ovs_offload_instance_cold_migration(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        if instance.get("status") =="active":
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #cold migrate instance
            response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
            #new host
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))

        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.offloading
    @pytest.mark.functional
    def test_verify_ovs_offload_instance_live_migration(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        if instance.get("status") =="active": 
            #get host of instance
            host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #live migrate instance
            response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
            #get host of instance
            new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
            #ping test
            if(instance.get("floating_ip") is not None):
                ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))

        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)        
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.functional
    def test_reboot_the_ovs_offload_instance_and_check_the_vf_connectivity(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        #ping test instance
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
            #reboot instance
            print("rebooting")
            reboot_server(endpoints.get("nova"), overcloud_token, instance.get("id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance.get("id")])
            ping_test= ping_test_between_instances(instance.get("floating_ip"), "8.8.8.8", settings)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(ping_response == 0, "instance ping failed", endpoints, overcloud_token, environment, settings)
        Assert(ping_test[0] == True, "instance failed to ping 8.8.8.8", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.volume
    def test_verify_attach_volume_to_ovs_offload_instance_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume not attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.volume
    def test_verify_detach_volume_from_ovs_offload_instance_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.volume
    def test_verify_migration_of_ovs_offload_instance_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("offloading")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0, "No", "vflag", environment.get("subnet1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"))
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.volume
    def test_verify_create_snapshot_from_ovs_offload_instance_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.offloading
    @pytest.mark.volume
    def test_verify_create_ovs_offload_instance_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("offloading")
        #create flavor
        flavor_id= get_flavor_id("offloading", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "No", "vflag", environment.get("subnet1_id"))
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            port2_id, port2_ip= create_port(endpoints.get("neutron"), overcloud_token, environment.get("network1_id"), environment.get("subnet1_id"), settings["sriov_port_name"], "vflag")
            instance2= search_and_create_sriov_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id, port2_id, "r178", environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token, instance.get("port_id"))
        #delete port
        delete_port(endpoints.get("neutron"), overcloud_token,port2_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
    
    '''
    Octavia
    '''
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_verify_the_creation_of_http_loadbalancer(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        #create load balancer
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))

        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
            
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_verify_the_working_of_loadbalancer_by_sending_http_traffic_to_loadbalancer(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
       
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance1, instance2, instance3])
            round_robin= roundrobin_traffic_test(loadbalancer.get("floating_ip"), "HTTPS")
        
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))

        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
         
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify http round robin traffic
        Assert(round_robin ==True, "traffic is not in round robin format", endpoints, overcloud_token, environment, settings)

    @pytest.mark.octavia
    @pytest.mark.functional
    def test_verify_the_creation_of_tcp_loadbalancer(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        #create load balancer
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "TCP", 23456, "ROUND_ROBIN")
        
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))

        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
          
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_verify_the_working_of_loadbalancer_by_sending_tcp_traffic_to_loadbalancer(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "TCP", 23456, "ROUND_ROBIN")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "TCP", [instance1, instance2, instance3])
            round_robin= roundrobin_traffic_test(loadbalancer.get("floating_ip"), "TCP")
        
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))

        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify http round robin traffic
        Assert(round_robin ==True, "traffic is not in round robin format", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_down_the_one_of_the_member_of_the_pool_and_verify_it_does_not_receive_the_http_request(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia") 

        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance1, instance2, instance3])
            round_robin= roundrobin_traffic_test(loadbalancer.get("floating_ip"), "HTTPS")
            #get a pool member
            member_id= get_pool_member(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"))
            #down the member
            down_pool_member(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), member_id)           
        #Send traffic
        curl_command= "curl {}".format(loadbalancer.get("floating_ip"))
        output=[]
        for i in range(0, 6):    
            result= os.popen(curl_command).read()
            #parse result
            result= result.strip()
            output.append(result)  
        total_members= len(set(output))  

        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))

        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify http round robin traffic
        Assert(round_robin ==True, "traffic is not in round robin format", endpoints, overcloud_token, environment, settings)
        #verify number of memebrs recived traffic
        Assert(total_members ==2, "Traffic is received on offline member", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_add_the_member_to_the_existing_pool_and_verify_that_it_receives_the_http_request(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance1, instance2])
            round_robin= roundrobin_traffic_test(loadbalancer.get("floating_ip"), "HTTPS")
            #add new member
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance3])
            round_robin= roundrobin_traffic_test(loadbalancer.get("floating_ip"), "HTTPS")
            #add new member
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        
        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
         
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify http round robin traffic
        Assert(round_robin ==True, "new member has not received traffic", endpoints, overcloud_token, environment, settings)

    @pytest.mark.octavia
    @pytest.mark.functional
    def test_create_another_listener_and_attach_it_to_previous_loadbalancer_and_create_pool_for_it(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        #create second listener
        listener2_state=""
        try: 
            listener2_id= search_and_create_listener(endpoints.get("loadbalancer"), overcloud_token, settings.get("listener2_name"), loadbalancer2.get("lb_id"), "HTTPS", 80)
            #wait for listener creation
            listener_build_wait(endpoints.get("loadbalancer"), overcloud_token, [listener2_id], settings.get("loadbalancer_listener_creation_retires"))
            #get listener state
            listener2_state= check_listener_status(endpoints.get("loadbalancer"), overcloud_token, listener2_id)
        except:
            listener2_state= "error"
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))

        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of second listener
        Assert(listener2_state == "error", "second listener creared on loadbalancer with existing listener", endpoints, overcloud_token, environment, settings)
   
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_create_two_loadbalancer_with_their_own_listeners_and_pool_member(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")
        
        loadbalancer1= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        #create second load balancer
        loadbalancer2_id= search_and_create_loadbalancer(endpoints.get("loadbalancer"), overcloud_token, settings.get("loadbalancer2_name"), environment.get("subnet1_id"))
        #wait for loadbalancer creation
        loadbalancer_build_wait(endpoints.get("loadbalancer"), overcloud_token, [loadbalancer2_id], settings.get("loadbalancer_build_retires"))
        #get state of loadbalancer
        loadbalancer2_state= check_loadbalancer_status(endpoints.get("loadbalancer"), overcloud_token, loadbalancer2_id)
        if loadbalancer2_state== "ACTIVE":
            listener2_id= search_and_create_listener(endpoints.get("loadbalancer"), overcloud_token, settings.get("listener2_name"), loadbalancer2_id, "HTTPS", 80)
            #wait for listener creation
            listener_build_wait(endpoints.get("loadbalancer"), overcloud_token, [listener2_id], settings.get("loadbalancer_listener_creation_retires"))
            #get listener state
            listener2_state= check_listener_status(endpoints.get("loadbalancer"), overcloud_token, listener2_id)
        if loadbalancer2_state== "ACTIVE" and listener2_state =="ACTIVE":
            #create pool
            pool2_id= search_and_create_pool(endpoints.get("loadbalancer"), overcloud_token, settings.get("pool2_name"), listener2_id, loadbalancer2_id, "HTTPS", "ROUND_ROBIN")
            #wait for pool creation
            pool_build_wait(endpoints.get("loadbalancer"), overcloud_token, [pool2_id], settings.get("loadbalancer_pool_creation_retires"))
            #get pool status
            pool2_state= check_pool_status(endpoints.get("loadbalancer"), overcloud_token, pool2_id)
        
        #delete pool
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer1.get("pool_id"), overcloud_token)
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), pool2_id, overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer1.get("listener_id"), overcloud_token)
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), listener2_id, overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer1.get("lb_id"), overcloud_token)
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer2_id, overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer1.get("floating_ip_id"))

        #verify state of loadbalancer
        Assert(loadbalancer1.get("lb_status") =="ACTIVE" and loadbalancer2_state =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer1.get("listener_status") =="ACTIVE" and listener2_state =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer1.get("pool_status") =="ACTIVE" and pool2_state =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)

    @pytest.mark.octavia
    @pytest.mark.functional
    def test_shutdown_the_loadbalancer_vm_and_check_status_of_loadbalancer(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")    
        #create loadbalancer
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        #disable loadbalancer
        disable_loadbalancer(endpoints.get("loadbalancer"), overcloud_token,  loadbalancer.get("lb_id"))
        operating_status_before_shutdown=check_loadbalancer_operating_status(endpoints.get("loadbalancer"), overcloud_token,  loadbalancer.get("lb_id"))
        #enable loadbalancer
        enable_loadbalancer(endpoints.get("loadbalancer"), overcloud_token,  loadbalancer.get("lb_id"))
        operating_status_after_shutdown=check_loadbalancer_operating_status(endpoints.get("loadbalancer"), overcloud_token,  loadbalancer.get("lb_id"))
        
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        Assert(operating_status_before_shutdown =="OFFLINE" and operating_status_after_shutdown =="ONLINE", "laodbalancer is not working propery when disabled", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_verify_creation_of_loadbalancer_L7policy(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")    
        #create loadbalancer
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        #create l7 policy for listener
        l7policy_id= create_l7policy(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("listener_id"))
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        Assert(l7policy_id != None , "l7 policy is not created", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_test_creation_rule_for_loadbalancer_L7policy(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")    
        #create loadbalancer
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN")
        #create l7 policy for listener
        l7policy_id= create_l7policy(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("listener_id"))
        #create rule for l7 policy
        l7_policy_rule= create_l7policy_rule(endpoints.get("loadbalancer"), overcloud_token, l7policy_id)
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        Assert(l7policy_id != None , "l7 policy is not created", endpoints, overcloud_token, environment, settings)
        Assert(l7_policy_rule != None , "rule for l7 policy is not created", endpoints, overcloud_token, environment, settings)

    @pytest.mark.octavia
    @pytest.mark.functional
    def test_cold_migration_of_pool_member(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia")    
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "TCP", 23456, "ROUND_ROBIN")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings.get("server_1_name"), settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            #install_http_packages_on_instance(instance.get("floating_ip"), "1", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "TCP", [instance])        
            #verify state of loadbalancer
            if instance.get("status") =="active":
                #get host of instance
                host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
                #cold migrate instance
                response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
                #new host
                new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
                #ping test
                if(instance.get("floating_ip") is not None):
                    ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
            #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
                
        #validate loadbalancer creation        
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        #validate instance creation
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)       
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.octavia
    @pytest.mark.functional
    def test_live_migration_of_pool_member(self, endpoints, overcloud_token, environment, settings, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("octavia")    
        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "TCP", 23456, "ROUND_ROBIN")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings.get("server_1_name"), settings["network1_name"], environment.get("network1_id"), compute0)
            #install packages on instances
            install_http_packages_on_instance(instance.get("floating_ip"), "1", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "TCP", [instance])        #verify state of loadbalancer
            if instance.get("status") =="active": 
                #get host of instance
                host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
                #live migrate instance
                response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
                #get host of instance
                new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
                #ping test
                if(instance.get("floating_ip") is not None):
                    ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
                #delete instance
                delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
                #delete flavor
                delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)                
                #validate loadbalancer creation        
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        
        #validate instance creation
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)        
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)
       
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_create_pool_with_the_source_ip_algorithm_and_verify_the_http_request_flow(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia") 

        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "SOURCE_IP")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance1, instance2, instance3])
            #Send traffic
            curl_command= "curl {}".format(loadbalancer.get("floating_ip"))
            output=[]
            for i in range(0, 6):    
                result= os.popen(curl_command).read()
                #parse result
                result= result.strip()
                output.append(result)  

        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        
        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 
        
        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify number of memebrs recived traffic
        Assert(len(output)>0 , "Traffic flow does not happen when algorithm is source ip", endpoints, overcloud_token, environment, settings)
        
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_create_pool_with_the_least_connections_algorithm_and_verify_the_http_request_flow(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia") 

        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "LEAST_CONNECTIONS")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance1, instance2, instance3])
            #Send traffic
            curl_command= "curl {}".format(loadbalancer.get("floating_ip"))
            output=[]
            for i in range(0, 6):    
                result= os.popen(curl_command).read()
                #parse result
                result= result.strip()
                output.append(result)  

        #delete loadbalancer
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))
        
        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 

        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify number of memebrs recived traffic
        Assert(len(output)>0 , "Traffic flow does not happen when algorithm is source ip", endpoints, overcloud_token, environment, settings)
       
    @pytest.mark.octavia
    @pytest.mark.functional
    def test_create_pool_with_the_session_persistence_algorithm_and_verify_the_http_request_flow(self, endpoints, overcloud_token, environment, settings):
        skip_test_if_feature_not_enabled("octavia") 

        loadbalancer= create_lb(endpoints.get("loadbalancer"), endpoints.get("neutron"), overcloud_token, settings, environment, "HTTPS", 80, "ROUND_ROBIN", "session_persistence")
        if (loadbalancer.get("pool_status")== "ACTIVE"):
            #create flavor
            flavor_id= get_flavor_id("octavia", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
            #create instaces
            instance1= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server1", settings["network1_name"], environment.get("network1_id"))
            instance2= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server2", settings["network1_name"], environment.get("network1_id"))
            instance3= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "testcase_server3", settings["network1_name"], environment.get("network1_id"))
            #install packages on instances
            install_http_packages_on_instance(instance1.get("floating_ip"), "1", settings)
            install_http_packages_on_instance(instance2.get("floating_ip"), "2", settings)
            install_http_packages_on_instance(instance3.get("floating_ip"), "3", settings)
            #add members to pool
            add_members_to_pool(endpoints.get("loadbalancer"), overcloud_token, loadbalancer.get("pool_id"), environment.get("subnet1_id"), 80, "HTTPS", [instance1, instance2, instance3])
            #Send traffic
            round_robin= roundrobin_traffic_test(loadbalancer.get("floating_ip"), "HTTPS")

        #delete pool
        delete_loadbalancer_pool(endpoints.get("loadbalancer"), loadbalancer.get("pool_id"), overcloud_token)
        #delete listener
        delete_loadbalancer_listener(endpoints.get("loadbalancer"), loadbalancer.get("listener_id"), overcloud_token)
        #delete loadbalancer
        delete_loadbalancer(endpoints.get("loadbalancer"), loadbalancer.get("lb_id"), overcloud_token)
        #delete floating_ip
        delete_floating_ip(endpoints.get("neutron"), overcloud_token, loadbalancer.get("floating_ip_id"))    
        if (loadbalancer.get("pool_status")== "ACTIVE"):
        #delete instance
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance1)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance2)
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance3)
            #delete flavor
            delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id) 

        #verify state of loadbalancer
        Assert(loadbalancer.get("lb_status") =="ACTIVE", "loadbalancer creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of listener
        Assert(loadbalancer.get("listener_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify state of pool
        Assert(loadbalancer.get("pool_status") =="ACTIVE", "listener creation failed", endpoints, overcloud_token, environment, settings)
        #verify traffic is in round robin format
        Assert(round_robin ==True, "new member has not received traffic", endpoints, overcloud_token, environment, settings)
    
    
    '''
    Power Flex
    '''
    @pytest.mark.powerflex
    @pytest.mark.storage 
    def test_verify_powerflex__service_status(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex service status
        powerflex_status= get_volume_service_list(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), "hostgroup@tripleo_dellemc_powerflex")
        print(powerflex_status)
        #validate powerflex service
        Assert(powerflex_status == "up", "powerflex service is not up", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.powerflex
    @pytest.mark.storage 
    def test_verify_powerflex_volume_type(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_type= get_volume_type_list(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), "powerflex_backend")
        #validate volume type
        Assert(volume_type != None, "powerflex backend not found", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_powerflex_volume_creation(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #validate volume creation
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_creation_of_snapshot_from_powerflex_volume(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id) 
        #create snapshot of volume
        snapshot_id= create_volume_snapshot(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id, settings.get("snapshot1_name"))
        #delete snapshot
        delete_snapshot(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), snapshot_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #validate snapshot creation
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(snapshot_id is not None, "snapshot not created successfully", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_creation_of_powerflex_volume_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id) 
        #create snapshot of volume
        snapshot_id= create_volume_snapshot(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id, settings.get("snapshot1_name"))
        #create volume from snapshot
        snapshot_volume= create_volume_from_snapshot(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume2_name"), snapshot_id)
        
        #delete volume created from snapshot
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), snapshot_volume)
        #delete snapshot
        delete_snapshot(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), snapshot_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #validate snapshot creation
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(snapshot_id is not None, "snapshot not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(snapshot_volume is not None, "volume is not created successfully from snapshot", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_delete_created_volume(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #search volume
        volume_id= search_volume(endpoints.get("cinder"), overcloud_token, settings.get("volume1_name"), environment.get("project_id"))        
        #validate volume deletion
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(not volume_id, "volume is not deleted successfully", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.error
    @pytest.mark.storage
    def test_upscale_detached_volume(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #create volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #upscale volume
        upscale_status= upscale_voume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id, "20")
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #search volume
        #validate volume size
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(upscale_status == True, "volume is not upscaled", endpoints, overcloud_token, environment, settings)
    
    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_image_creation_from_volume(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #create image from volume
        image_id=create_image_from_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id, settings.get("image2_name"))
        print(image_id)
        #delete volume
        #delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete image
        #delete_image(endpoints.get("image"), overcloud_token, image_id)
        #validate volume creation
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(image_id is not None, "image not created successfully from volume", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_create_volume_with_replication_property(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #get powerflex volume type
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #replicate volume
        replicated_volume_id= replicate_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), "testcase_replicated_volume", volume_id)
        if(replicated_volume_id is not None):
            replicated_volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), replicated_volume_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), replicated_volume_id)
        #validate volume deletion
        Assert(volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)
        Assert(replicated_volume_status == "available", "volume is not created successfully", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_attach_volume_to_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #create flavor
        flavor_id= get_flavor_id("powerflex", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume successfully attached to server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_detach_volume_from_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #create flavor
        flavor_id= get_flavor_id("powerflex", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #detach volume
        if volume_status_after_attachment =="in-use":
            detach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_deattachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_deattachment == "available", "volume is not detached from server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_cold_migration_of_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("powerflex")
        #create flavor
        flavor_id= get_flavor_id("powerflex", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "cold migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after cold migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_live_migration_of_instance_with_attached_volume(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test_if_feature_not_enabled("powerflex")
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= get_flavor_id("powerflex", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #cerate volume
        volume_id= search_and_create_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), settings.get("volume1_name"), settings.get("volume_size"), "powerflex_backend")
        #volume status
        volume_status= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        if instance.get("status") =="active" and volume_status== "available":
            attach_volume(endpoints.get("nova"), overcloud_token, environment.get("project_id"), instance.get("id"), volume_id)
        volume_status_after_attachment= check_volume_status(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #migrate instance
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        if(instance.get("floating_ip") is not None):
            ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete volume
        delete_volume(endpoints.get("cinder"), overcloud_token, environment.get("project_id"), volume_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(volume_status != "error", "volume creation failed", endpoints, overcloud_token, environment, settings)
        Assert(volume_status_after_attachment == "in-use", "volume failed to attach to server", endpoints, overcloud_token, environment, settings)
        Assert(response ==202, "live migration failed", endpoints, overcloud_token, environment, settings)
        Assert(host!=new_host, "instance is not migrated to other host", endpoints, overcloud_token, environment, settings)
        Assert(ping_response==0, "instance ping failed after live migration", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_create_snapshot_from_instance(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #create flavor
        flavor_id= get_flavor_id("powerflex", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)

    @pytest.mark.powerflex
    @pytest.mark.storage
    def test_verify_create_instance_from_snapshot(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("powerflex")
        #create flavor
        flavor_id= get_flavor_id("powerflex", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), None, "Yes")
        #create snapshot
        instance_snapshot_id=""
        instance2=""
        if instance.get("status") =="active":
            instance_snapshot_id= create_server_snapshot(endpoints.get("nova"), overcloud_token, instance.get("id"), settings.get("snapshot1_name"))
        if instance_snapshot_id != None:
            instance2= search_and_create_server(endpoints.get("nova"), overcloud_token, settings["server_2_name"], instance_snapshot_id, settings["key_name"], flavor_id,  environment.get("network1_id"), environment.get("security_group_id"))
            server_build_wait(endpoints.get("nova"), overcloud_token, [instance2])
            instance2_status= check_server_status(endpoints.get("nova"), overcloud_token, instance2)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        delete_server_with_id(endpoints.get("nova"), overcloud_token, instance2)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #delete snapshot
        delete_image(endpoints.get("image"), overcloud_token, instance_snapshot_id)
        #check status of server is active or not
        Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        Assert(instance_snapshot_id != None, "failed to create snapshot of server", endpoints, overcloud_token, environment, settings)
        Assert(instance2_status == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
    

def skip_test_if_feature_not_enabled(feature):
    logging.info("Starting testcase: {}".format(currentFuncName(1)))
    #update testcase counting with respect to feature
    testcases_detail[currentFuncName(1)]= [feature, "Unknown", ""]
    #skip test if feature not enabled
    if feature not in deployed_features:
        testcases_detail[currentFuncName(1)]= [testcases_detail.get(currentFuncName(1))[0],"Skipped", testcases_detail.get(currentFuncName(1))[2]]
        logging.info("Test case {}: Skipped".format(currentFuncName(1) ))
        pytest.skip("{} is disabled in ini file".format(feature))
    
def Assert(test, message, endpoints, overcloud_token, environment, settings):
    if not test:
        logging.error(message)
        logging.info("{} failed".format(currentFuncName(1)))
        testcases_detail[currentFuncName(1)]= [testcases_detail.get(currentFuncName(1))[0],"Failed",message]
        delete_environment(endpoints, overcloud_token, environment, settings)
        assert test,message
    else:
        testcases_detail[currentFuncName(1)]= [testcases_detail.get(currentFuncName(1))[0],"Passed", ""]
currentFuncName = lambda n=0: sys._getframe(n + 1).f_code.co_name
