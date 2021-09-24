from functions import *
from openstack_features.numa import *
from openstack_features.barbican import *
from openstack_features.hugepage import *
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
def print_features_list_and_results(ini_file, endpoints, settings, overcloud_token):
    #print features enabled ini file
    for key, value in ini_file.items():
        if(value== "true"):
            key=key.split("_")
            deployed_features.append(key[0])
            if(key[0]== "smart"):
                print("Hardware Offloading is Enabled")
            else:
                print("{} is Enabled".format(key[0].capitalize()))
    yield 
    '''
    This part of code wil execute after execution of all tests. 
    It will clean environment and print report
    '''
    #cleaning environment at end of testcases
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
@pytest.fixture(scope="session", name="overcloud_token")
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
            image_file= open(os.path.expanduser(ini_file.get("image_file_name")), 'rb')
            upload_file_to_image(endpoints.get("image"), overcloud_token, image_file, image_id)
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
    flavor1_id=(endpoints.get("nova"), overcloud_token, settings["flavor1_name"])
    if flavor1_id is not None:
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor1_id)
    flavor2_id=(endpoints.get("nova"), overcloud_token, settings["flavor2_name"])
    if flavor2_id is not None:
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor2_id)

#Numa testcases
class TestOpenStack():
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
        if(nstance.get("status") == "active"):
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
    def test_verify_numa_instance_resizing(self, settings, environment, endpoints, overcloud_token):
        skip_test_if_feature_not_enabled("error")
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 4)

        #create flavor to resize
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 2)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #resize server
        resize_status= resize_server(endpoints.get("nova"),overcloud_token, instance.get("id"), flavor_to_resize)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        print(resize_status)
    
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
        if instance1.get("status") =="active": 
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
    @pytest.mark.development
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
        skip_test_if_feature_not_enabled("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-0")
        #get possible instances on compute node
        #instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #print("possible instances are: {}".format(instances_possible))
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)

        #create Instances
        for i in range (0,2):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created  as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created  as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)

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
        #instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)
        #create Instances    
        for i in range (0,2):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
            #pause all servers
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "pause")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
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
        #instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)

        #create Instances    
        for i in range (0,2):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
            #pause all servers
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "suspend")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
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
        #instances_possible= get_possible_numa_instances(compute0_ip, 20)
        #create flavor
        flavor_id= get_flavor_id("numa", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, 20)
        #create Instances    
        for i in range (0,2):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
            #pause all servers
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "shutdown")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when vcpu are not consumed", endpoints, overcloud_token, environment, settings)
        Assert(instance.get("status") != "active", "instances are not created as expected when vcpu are consumed ", endpoints, overcloud_token, environment, settings)
    
    #Hugepage Testcases
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
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features)
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
            Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
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
            Assert(instance.get("status") == "active", "instance state is not active", endpoints, overcloud_token, environment, settings)
        else:
            Assert(instance.get("status") == "error", "instance state is not active", endpoints, overcloud_token, environment, settings)

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
        #create flavor
        flavor_id= get_flavor_id("hugepage", endpoints.get("nova"), overcloud_token, settings["flavor1_name"], settings, deployed_features, None, 20480)
        #create Instances
        for i in range (0,instances_possible):
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when hugaepages are not consumed", endpoints, overcloud_token, environment, settings)
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
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        #pause all instances
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "pause")
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when hugaepages are not consumed and all instances are paused", endpoints, overcloud_token, environment, settings)
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
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #suspend instances
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "suspend")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when hugaepages are not consumed and all instances are suspended", endpoints, overcloud_token, environment, settings)
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
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #shutdown all instances
        perform_action_on_instances(instances, endpoints.get("nova"), overcloud_token, "shutdown")
        #create extra instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected when hugaepages are not consumed and all instances are shutdown", endpoints, overcloud_token, environment, settings)
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
            instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, "test_server{}".format(i), settings["network1_name"], environment.get("network1_id"), compute0)
            instances_status.append(instance.get("status"))
            instances.append(instance)
        #delete instance
        for instance in instances:
            delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        Assert("error" not in instances_status , "instances are not created as expected with 22GB flavor", endpoints, overcloud_token, environment, settings)



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
