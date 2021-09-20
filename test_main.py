from functions import *
from openstack_features.numa import *
from openstack_features.barbican import *
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


print("Hellooooooooo")
if not os.path.exists('logs'):
    os.makedirs('logs')
total_testcases=0
#log_file= "logs/"+ time.strftime("%d-%m-%Y-%H-%M-%S")+".log"
#logging.basicConfig(level=logging.DEBUG,
#                    format='%(asctime)s %(message)s',
#                    handlers=[logging.FileHandler(log_file),
#                             logging.StreamHandler()])


# Fixtures provide a fixed baseline so that tests execute reliably and produce consistent, repeatable, results. 
# They have 4 scopes: classes, modules, packages or session

#read settings from settings.json
deployed_features=[]
feature_tests={}
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
@pytest.fixture(scope="class", name="environment", autouse=True)
def create_basic_openstack_environment(settings, endpoints, overcloud_token, ini_file):
    ids={}
    #list of features enabled
    print("Creating OpenStack Environment \n")
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
    ids["network1_id"]= network1_id
    ids["network2_id"]= network2_id
    
    #cereate subnets
    subnet1_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet1_name"], network1_id, settings["subnet1_cidr"]) 
    subnet2_id= search_and_create_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet2_name"], network2_id, settings["subnet2_cidr"]) 
    ids["subnet1_id"]= subnet1_id
    ids["subnet2_id"]= subnet2_id

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
        public_network_id= search_network(endpoints.get("neutron"), overcloud_token, "public")
        public_subnet_id= search_subnet(endpoints.get("neutron"), overcloud_token, settings["external_subnet"])
        router_id= create_router(endpoints.get("neutron"), overcloud_token, settings["router_name"], public_network_id,public_subnet_id )
        add_interface_to_router(endpoints.get("neutron"), overcloud_token, router_id, subnet2_id)
        add_interface_to_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)
    ids["router_id"]= router_id

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
    ids["image_id"]= image_id
    #create flavor    
    flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, settings["flavor1"], 4096, 2, 150)
    if(ini_file.get("ovs_dpdk_enabled")=="true"):
        logging.debug("putting ovsdpdk specs in flavor")
        put_ovs_dpdk_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
    elif(ini_file.get("numa_enable")=="true" or ini_file.get("sriov_enabled")=="true"):
        logging.debug("putting numa specs in flavor")
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
    ids["flavor_id"]= flavor_id

    yield ids
    
    #Clean Environment
    
    print("\n Cleaning Environment")
    
    logging.info("-----------------")
    logging.info("--Custom Report--")
    logging.info("-----------------")
    logging.info("Total Testcases {}".format(total_testcases))
    for feature in feature_tests:
        logging.info("Total {} testcases are: {}".format(feature, feature_tests.get(feature)))
    '''
    delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
    delete_image(endpoints.get("image"), overcloud_token, image_id)
    remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet2_id)
    remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)
    delete_network(endpoints.get("neutron"), overcloud_token, network1_id)
    delete_network(endpoints.get("neutron"), overcloud_token, network2_id)
    delete_router(endpoints.get("neutron"), overcloud_token, router_id)
    delete_kaypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    create_report()
   '''
def delete_environment():
    delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
    delete_image(endpoints.get("image"), overcloud_token, image_id)
    remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet2_id)
    remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)
    delete_network(endpoints.get("neutron"), overcloud_token, network1_id)
    delete_network(endpoints.get("neutron"), overcloud_token, network2_id)
    delete_router(endpoints.get("neutron"), overcloud_token, router_id)
    delete_kaypair(endpoints.get("nova"), overcloud_token, settings["key_name"])

#Numa testcases
class TestOpenStack():
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_with_numa_flavor(self, settings, environment, endpoints, overcloud_token):
        skip_test("numa")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 4, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        assert instance.get("status") == "active"

    @pytest.mark.numa
    @pytest.mark.functional
    def test_number_of_vcpus_pinned_are_same_as_the_vcpus_in_numa_flavour(self, settings, environment, endpoints, overcloud_token, baremetal_nodes):
        #verify vcpus of instance are 4 or not 
        skip_test("numa")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 4, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Get VCPUS
        vcpus= get_vcpus_of_instance(endpoints.get("nova"), overcloud_token, baremetal_nodes, instance)
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #Get VCPUS of instance 
        assert vcpus == "4"

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_resizing(self, settings, environment, endpoints, overcloud_token):
        skip_test("error")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 4, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
        #create flavor to resize
        flavor_to_resize= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor2", 4096, 2, 10)
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
        skip_test("numa")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 4, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #Ping test
        response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        assert response == 0
   
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_cold_migration(self, settings, environment, endpoints, overcloud_token):
        skip_test("numa")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 4, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #cold migrate instance
        response=  cold_migrate_instance(endpoints.get("nova"), overcloud_token, instance.get("id"), instance.get("floating_ip"), settings)
        #new host
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        assert response ==202 and (host!=new_host) and ping_response==0
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_numa_instance_live_migration(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test("numa")
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-0", ini_file.get("domain"))
        compute1= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 4, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"), compute0)
        #get host of instance
        host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #live migrate instance
        response= live_migrate_server(endpoints.get("nova"), overcloud_token, instance.get("id"), compute1)
        #get host of instance
        new_host= get_server_baremetal_host(endpoints.get("nova"), overcloud_token, instance.get("id"))
        #ping test
        ping_response = os.system("ping -c 3 " + instance.get("floating_ip"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        assert response ==202 and (host!=new_host) and ping_response==0

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-1")
        #get possible instances on compute node
        #instances_possible= get_possible_instances(compute0_ip, 20)
        #print("possible instances are: {}".format(instances_possible))
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 20, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
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
        assert "error" not in instances_status and (instance.get("status") != "active")

    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed_and_all_instances_are_paused(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-1")
        #get possible instances on compute node
        #instances_possible= get_possible_instances(compute0_ip, 20)
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 20, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
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
        assert "error" not in instances_status and (instance.get("status") != "active")
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed_and_all_instances_are_suspended(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-1")
        #get possible instances on compute node
        #instances_possible= get_possible_instances(compute0_ip, 20)
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 20, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
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
        assert "error" not in instances_status and (instance.get("status") != "active")
        
    @pytest.mark.numa
    @pytest.mark.functional
    def test_verify_instance_creation_when_all_vcpus_are_consumed_and_all_instances_are_shutdown(self, settings, environment, endpoints, overcloud_token, baremetal_nodes, ini_file):
        skip_test("numa")
        instances= []
        instances_status=[]
        #get compute nodes name
        compute0= get_compute_name(baremetal_nodes, "compute-1", ini_file.get("domain"))
        compute0_ip=get_node_ip(baremetal_nodes, "compute-1")
        #get possible instances on compute node
        #instances_possible= get_possible_instances(compute0_ip, 20)
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "numa_flavor1", 4096, 20, 10)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, True)
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
        assert "error" not in instances_status and (instance.get("status") != "active")
        
    #Hugepage Testcases
    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_with_hugepage_flavor(self, settings, environment, endpoints, overcloud_token):
        skip_test("hugepage")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "hugepage_flavor", 4096, 2, 40)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, False, 1048576)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        assert instance.get("status") == "active"
    
    @pytest.mark.hugepage
    @pytest.mark.functional
    def test_verify_instance_creation_with_hugepage_1GB_flavor_and_1GB_deployment(self, settings, environment, endpoints, overcloud_token):
        skip_test("hugepage")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "hugepage_flavor", 4096, 2, 40)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, False, 1048576)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        assert instance.get("status") == "active"
    
    @pytest.mark.hugepage
    @pytest.mark.functional
    @pytest.mark.development
    def test_verify_instance_creation_with_hugepage_2MB_flavor_and_1GB_deployment(self, settings, environment, endpoints, overcloud_token):
        skip_test("hugepage")
        #create flavor
        flavor_id= search_and_create_flavor(endpoints.get("nova"), overcloud_token, "hugepage_flavor", 4096, 2, 40)
        put_extra_specs_in_flavor(endpoints.get("nova"), overcloud_token, flavor_id, False, 2048)
        #create instance
        instance= create_instance(settings, environment, endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, flavor_id, settings["server_1_name"], settings["network1_name"], environment.get("network1_id"))
        #delete instance
        delete_server(endpoints.get("nova"), endpoints.get("neutron"), overcloud_token, instance)
        #delete flavor
        delete_flavor(endpoints.get("nova"), overcloud_token, flavor_id)
        #check status of server is active or not
        logAssert(instance.get("status") == "active", "instance should be in error state but it is active")
        #assert instance.get("status") == "active" and flavor_id != None
    

#Barbican Testases
    @pytest.mark.barbican
    def cdenvironment(self, settings, endpoints, overcloud_token, ini_file):
        
        skip_test("barbican")
        create_basic_openstack_environment(settings, endpoints, overcloud_token, ini_file)

    @pytest.mark.barbican
    @pytest.mark.functional
    def test_create_barbican_secret(self, endpoints, overcloud_token, environment):
        skip_test("barbican")
        assert create_barbican_secret(endpoints.get("barbican"), overcloud_token) != "" or None

#SRIOV Testases
    @pytest.mark.sriov
    def test_dummy_srio2(sriov):
        skip_test("sriov")
        environment()

    @pytest.mark.sriov
    def test_dummy_sriov(endpoints, overcloud_token, environment):
        skip_test("sriov")
        assert create_barbican_secret(endpoints.get("barbican"), overcloud_token) != "" or None

def skip_test(feature):
    #logging.debug("Starting testcase: {}".format())
    global total_testcases
    total_testcases=total_testcases+1
    feature_tests[feature]= 1
    if feature not in deployed_features:
        pytest.skip("{} is disabled in ini file".format(feature))

def logAssert(test, message):
    if not test:
        logging.error(message)
        assert test,message
