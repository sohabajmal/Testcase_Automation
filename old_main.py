import json
import os
import sys
import requests
from openstack_functions import *
from numa import *
from hugepages import *
import argparse
import logging
import subprocess
from ovsdpdk import*
import time
from sriov import *
from mtu9000 import *
from dvr import *
from octavia import *
from sriov_vflag import *
from volume import *
from hci import *
from barbican import *

#filename=time.strftime("%d-%m-%Y-%H-%M-%S")+".log"
#filsename= "logs.log", filemode="w", stream=sys.stdout
#logging.basicConfig(level=logging.INFO,  format='%(asctime)s %(levelname)s: %(message)s', stream=sys.stdout, filename= "logs/"+time.strftime("%d-%m-%Y-%H-%M-%S")+".log")

if not os.path.exists('logs'):
    os.makedirs('logs')


log_file= "logs/"+ time.strftime("%d-%m-%Y-%H-%M-%S")+".log"
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(message)s',
                    handlers=[logging.FileHandler(log_file),
                              logging.StreamHandler()])

def parse_arguments():
    # parse arguments
    logging.info("Parsing Arguments")
    parser = argparse.ArgumentParser(description='pass settings file, feature and deployment type for test cases')
    parser.add_argument('-s', '--settings',
                        help=' settings file',
                        default="settings.json")
    parser.add_argument('-f', '--feature', nargs='+',
                        help='features enabled in deployment',
                        required=True)
    parser.add_argument('-v', '--volume',
                        help='storage and volume testing',
                        required=False, action='store_true')
    parser.add_argument('-o', '--overcloudrc',
                        help='overrcloud rc file',
                        required=True)
    parser.add_argument('-u', '--undercloudrc',
                        help='undercloud rc file',
                        default="~/stackrc", 
                        required=False)
   
    return parser.parse_args()

def read_settings(settings_file):
    #read settings from json file
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r') as file:
                 data = file.read().replace('\n', '')
            settings= json.loads(data)
        except Exception as e:
            logging.exception("Failed to load settings file \n {}".format(e))
    else:
        logging.exception("File not found")
    return settings
def run_linux_command(command):
    command= subprocess.run([command], shell=True, stdout=subprocess.PIPE)
    output= command.stdout.decode('ascii')
    if not output:
        logging.error("IP NOT FOUND",  stack_info=True)
        raise ValueError("IP Not found")
    return output

def read_rc_file(rc_file):
    if os.path.exists(os.path.expanduser(rc_file)):
        logging.info("{} file found".format(rc_file))
        #Find and parse ip
        output= run_linux_command("grep OS_AUTH_URL {}".format(os.path.expanduser(rc_file)))
        output= output.split('=')
        ip= output[1][:-6]

        #Find and parse username
        output= run_linux_command("grep OS_USERNAME {}".format(os.path.expanduser(rc_file)))
        output= output.split('=')
        username= output[1].rstrip("\n")

        #Find and parse password
        output= run_linux_command("grep OS_PASSWORD {}".format(os.path.expanduser(rc_file)))
        output= output.split('=')
        password= output[1].rstrip("\n")
        return ip, username, password

    else:
        logging.error("File {} not found".format(rc_file), stack_info=True )
        raise FileNotFoundError ("File {} not found".format(rc_file))

def setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token):
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

        #Search and create network
        print(features[0])
        if(features[0]== "mtu9000"):
            network1_id = search_and_create_network(neutron_ep, token, settings["network1_name"], 9000, settings["network_provider_type"], False)  
            network2_id = search_and_create_network(neutron_ep, token, settings["network2_name"], 9000, settings["network_provider_type"], False)  
        else: 
            network1_id = search_and_create_network(neutron_ep, token, settings["network1_name"], 1500, settings["network_provider_type"], False)  
            network2_id = search_and_create_network(neutron_ep, token, settings["network2_name"], 1500, settings["network_provider_type"], False)  
        #Search and create subnet
        subnet1_id= search_and_create_subnet(neutron_ep, token, settings["subnet1_name"], network1_id, settings["subnet1_cidr"]) 
        subnet2_id= search_and_create_subnet(neutron_ep, token, settings["subnet2_name"], network2_id, settings["subnet2_cidr"]) 
        
        router_id= search_router(neutron_ep, token, settings["router_name"])
        if router_id is None:
            public_network_id= public_network_id= search_network(neutron_ep, token, "public")
            public_subnet_id= search_subnet(neutron_ep, token, settings["external_subnet"])
            router_id= create_router(neutron_ep, token, settings["router_name"], public_network_id,public_subnet_id )
            add_interface_to_router(neutron_ep, token, router_id, subnet2_id)
            add_interface_to_router(neutron_ep, token, router_id, subnet1_id)
        #Search and create security group
        #/v2.0/security-groups
        project_id= find_admin_project_id(keystone_ep, token)
        security_group_id= get_default_security_group_id(neutron_ep, token, project_id)
        #security_group_id= search_and_create_security_group(neutron_ep, token, settings["security_group_name"])
        try:
            add_icmp_rule_to_security_group(neutron_ep, token, security_group_id)
            add_ssh_rule_to_security_group(neutron_ep, token, security_group_id)
        except:
            pass
        if("barbican" not in features):
            image_id= search_and_create_image(image_ep, token, settings["image_name"], "bare", "qcow2", "public", os.path.expanduser(settings["image_file"]))
        else:
            image_id= search_image(nova_ep, token, settings["image_name"])
            if(image_id is None):
                key= create_ssl_certificate(settings)
                image_signature= sign_image(settings)
                barbican_key_id= add_key_to_store(barbican_ep, token, key)
                image_id= create_barbican_image(image_ep, token, settings["image_name"], "bare", "qcow2", "public", image_signature, barbican_key_id)
            status= get_image_status(image_ep, token, image_id)
            if status== "queued":
                image_file= open(os.path.expanduser(settings["image_file"]), 'rb')
                upload_file_to_image(image_ep, token, image_file, image_id)
        flavor_id= search_and_create_flavor(nova_ep, token, settings["flavor1"], 4096, 2, 150)
        if(features[0] == "ovsdpdk"):
            logging.info("putting ovsdpdk specs in flavor")
            put_ovs_dpdk_specs_in_flavor(nova_ep, token, flavor_id)
        elif("numa" in features or features[0]=="sriov" or features[0]=="sriov_vflag"):
            logging.info("putting numa specs in flavor")
            put_extra_specs_in_flavor(nova_ep, token, flavor_id, True)
        return network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key
    except Exception as e:
        logging.error("error occured during environment setup/ skipping testscases")
        logging.exception(e)
        return "error","error","error","error","error","error","error","error","error"

def delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings):
    try:
        server_id= search_server(nova_ep, token, settings["server_1_name"])
        if server_id is not None:
            logging.info("deleting server 1")
            delete_resource("{}/v2.1/servers/{}".format(nova_ep,server_id), token)
        server_id= search_server(nova_ep, token, settings["server_1_name"])
        if server_id is not None:
            logging.info("deleting server 1")
            delete_resource("{}/v2.1/servers/{}".format(nova_ep,server_id), token)
        
        logging.info("deleting flavor")
        delete_resource("{}/v2.1/flavors/{}".format(nova_ep,flavor_id), token)

        logging.info("deleting image")
        delete_resource("{}/v2/images/{}".format(image_ep, image_id), token)
        time.sleep(3)
        logging.info("removing router interfaces")
        remove_interface_to_router(neutron_ep, token, router_id, subnet2_id)
        time.sleep(10)
        remove_interface_to_router(neutron_ep, token, router_id, subnet1_id)
        time.sleep(10)

        logging.info("deleting router")
        delete_resource("{}/v2.0/routers/{}".format(neutron_ep,router_id), token)

        logging.info("deleting networks")
        delete_resource("{}/v2.0/networks/{}".format(neutron_ep,network1_id), token)
        time.sleep(5)
        delete_resource("{}/v2.0/networks/{}".format(neutron_ep,network2_id), token)
        time.sleep(3)
    except Exception as e:
        logging.error("error occured while cleaning resources")
        logging.exception(e)

def numa_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    #Temporary changing quota
    logging.info("temporary changing quota")
    project_id= find_admin_project_id(keystone_ep, token)
    try: 
        set_quota(nova_ep, token, project_id, 200, 25, 204800)
        time.sleep(10)
    except:
        pass

    passed=failed=0

    t3, message3= numa_test_case_3(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)  
    if t3 == True:
        t3= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t3="Failed"
    
    t5, message5, t6, message6,  t9, message9= numa_test_case_5_6_9(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t5 == True:
        t5= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t5="Failed"
    if t6 == True:
        t6= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t6="Failed"
    if t9 == True:
        t9= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t9="Failed"
    
    t7, message7= numa_test_case_7(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"
    
    t8, message8= numa_test_case_8(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"
    
    t10, message10= numa_test_case_10(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t10 == True:
        t10= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t10="Failed"    
    t11, message11= numa_test_case_11(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t11 == True:
        t11= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t11="Failed"
    
    t12, message12= numa_test_case_12(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t12 == True:
        t12= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t12="Failed"
    t13, message13= numa_test_case_13(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t13 == True:
        t13= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t13="Failed"
    if(volume== True):
        volume_passed, volume_message= numa_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, network1_id, security_group_id, image_id)

    #Changing qouta to default settings
    logging.info("setting default quota")
    try:
        set_quota(nova_ep, token, project_id, 20, 20, 51200)
    except:
        pass
    
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    
    logging.info("---------------------------")
    logging.info("------NUMA Test Cases------")
    logging.info("---------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))

    logging.info("NUMA test case 3 status: {} ".format(t3))
    logging.info("NUMA test case 5 status: {} ".format(t5))
    logging.info("NUMA test case 6 status: {} ".format(t6))
    logging.info("NUMA test case 7 status: {} ".format(t7))
    logging.info("NUMA test case 8 status: {} ".format(t8))
    logging.info("NUMA test case 9 status: {} ".format(t9))
    logging.info("NUMA test case 10 status: {} ".format(t10))
    logging.info("NUMA test case 11 status: {} ".format(t11))
    logging.info("NUMA test case 12 status: {} ".format(t12))
    logging.info("NUMA test case 13 status: {} ".format(t13))
 
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    logging.info("NUMA test case 3 status: {} ".format(t3))
    logging.info("NUMA message  {} \n".format(message3))
    logging.info("------------------------------")
    logging.info("NUMA test case 5 status: {} ".format(t5))
    logging.info("NUMA message  {} \n".format(message5))
    logging.info("------------------------------")
    logging.info("NUMA test case 6 status: {} ".format(t6))
    logging.info("NUMA message  {} \n".format(message6))
    logging.info("------------------------------")
    logging.info("NUMA test case 7 status: {} ".format(t7))
    logging.info("NUMA message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("NUMA test case 8 status: {} ".format(t8))
    logging.info("NUMA message  {} \n".format(message8))
    logging.info("------------------------------")
    logging.info("NUMA test case 9 status: {} ".format(t9))
    logging.info("NUMA message  {} \n".format(message9))
    logging.info("------------------------------")
    logging.info("NUMA test case 10 status: {} ".format(t10))
    logging.info("NUMA message  {} \n".format(message10))
    logging.info("------------------------------")
    logging.info("NUMA test case 11 status: {} ".format(t11))
    logging.info("NUMA message  {} \n".format(message11))
    logging.info("------------------------------")
    logging.info("NUMA test case 12 status: {} ".format(t12))
    logging.info("NUMA message  {} \n".format(message12))
    logging.info("------------------------------")
    logging.info("NUMA test case 13 status: {} ".format(t13))
    logging.info("NUMA message  {} \n".format(message13))
    logging.info("------------------------------")
    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------Numa Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("NUMA Volume Testcase Results")
        logging.info("{}".format(volume_message))
    
def hugepages_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    #Temporary changing quota
    logging.info("temporary changing quota")
    project_id= find_admin_project_id(keystone_ep, token)
    try: 
        set_quota(nova_ep, token, project_id, 200, 25, 204800)
        time.sleep(10)
    except:
        pass
    passed=failed=0  
    t1, message1= hugepages_test_case_1(baremetal_nodes_ips)
    if t1 == True:
        t1= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t1="Failed"

    t2, message2= hugepages_test_case_2(baremetal_nodes_ips)
    if t2 == True:
        t2= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t2="Failed"
    
    t3, message3= hugepages_test_case_3(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t3 == True:
        t3= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t3="Failed"
    t4, message4= hugepages_test_case_4(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t4 == True:
        t4= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t4="Failed"
   
    t7, message7,t8, message8= hugepages_test_case_7_and_8(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"
    
    t9, message9= hugepages_test_case_9(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)

    if t9 == True:
        t9= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t9="Failed"
    
    t10, message10= hugepages_test_case_10(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t10 == True:
        t10= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t10="Failed"
    
    t11, message11= hugepages_test_case_11(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t11 == True:
        t11= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t11="Failed"
    t12, message12= hugepages_test_case_12(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t12 == True:
        t12= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t12="Failed"
    t13, message13= hugepages_test_case_13(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t13 == True:
        t13= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t13="Failed"
    if(volume== True):
        volume_passed, volume_message= hugepages_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, network1_id, security_group_id, image_id)
    #Changing qouta to default settings
    logging.info("setting default quota")
    try:
        set_quota(nova_ep, token, project_id, 20, 20, 51200)
    except:
        pass
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    logging.info("--------------------------------")
    logging.info("------Hugepages Test Cases------")
    logging.info("------  ------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))

    logging.info("Hugepages test case 1 status: {} ".format(t1))
    logging.info("Hugepages test case 2 status: {} ".format(t2))
    logging.info("Hugepages test case 3 status: {} ".format(t3))
    logging.info("Hugepages test case 4 status: {} ".format(t4))
    logging.info("Hugepages test case 7 status: {} ".format(t7))
    logging.info("Hugepages test case 8 status: {} ".format(t8))
    logging.info("Hugepages test case 9 status: {} ".format(t9))
    logging.info("Hugepages test case 10 status: {} ".format(t10))
    logging.info("Hugepages test case 11 status: {} ".format(t11))
    logging.info("Hugepages test case 12 status: {} ".format(t12))
    logging.info("Hugepages test case 13 status: {} ".format(t13))
 
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    logging.info("Hugepages test case 1 status: {} ".format(t1))
    logging.info("Hugepages message  {} \n".format(message1))
    logging.info("------------------------------")
    logging.info("Hugepages test case 2 status: {} ".format(t2))
    logging.info("Hugepages message  {} \n".format(message2))
    logging.info("------------------------------")
    logging.info("Hugepages test case 3 status: {} ".format(t3))
    logging.info("Hugepages message  {} \n".format(message3))
    logging.info("------------------------------")
    logging.info("Hugepages test case 4 status: {} ".format(t4))
    logging.info("Hugepages message  {} \n".format(message4))
    logging.info("------------------------------")
    logging.info("Hugepages test case 7 status: {} ".format(t7))
    logging.info("Hugepages message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("Hugepages test case 8 status: {} ".format(t8))
    logging.info("Hugepages message  {} \n".format(message8))
    logging.info("------------------------------")
    logging.info("Hugepages test case 9 status: {} ".format(t9))
    logging.info("Hugepages message  {} \n".format(message9))
    logging.info("------------------------------")
    logging.info("Hugepages test case 10 status: {} ".format(t10))
    logging.info("Hugepages message  {} \n".format(message10))
    logging.info("------------------------------")
    logging.info("Hugepages test case 11 status: {} ".format(t11))
    logging.info("Hugepages message  {} \n".format(message11))
    logging.info("------------------------------")
    logging.info("Hugepages test case 12 status: {} ".format(t12))
    logging.info("Hugepages message  {} \n".format(message12))
    logging.info("------------------------------")
    logging.info("Hugepages test case 13 status: {} ".format(t13))
    logging.info("Hugepages message  {} \n".format(message13))
    logging.info("------------------------------ \n\n\n")

    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------Hugepages Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("Hugepage Volume Testcase Results")
        logging.info("{}".format(volume_message))
    
def sriov_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    #creating zones

    try:
        compute0 =  [key for key, val in baremetal_nodes_ips.items() if "compute-0" in key]
        compute0= compute0[0]
        compute1 =  [key for key, val in baremetal_nodes_ips.items() if "compute-1" in key]
        compute1= compute1[0]
        compute2 =  [key for key, val in baremetal_nodes_ips.items() if "compute-2" in key]
        compute2= compute2[0]
        default_zone_id= get_availability_zones(nova_ep, token)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute0)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute1)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute2)
        nova0_id= create_availability_zones(nova_ep, token, "nova0")
        nova1_id= create_availability_zones(nova_ep, token, "nova1")
        add_host_to_zone(nova_ep, token, nova0_id, compute0)
        add_host_to_zone(nova_ep, token, nova1_id, compute1)
        add_host_to_zone(nova_ep, token, nova1_id, compute2)
    except Exception as e:
        pass
    time.sleep(5)
    
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    passed=failed=0
    
    t3, message3= sriov_test_case_3(baremetal_nodes_ips)
    if t3 == True:
        t3= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t3="Failed"

    t7,message7, t8,message8= sriov_test_case_7_8(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"  
    
    t10,message10= sriov_test_case_10(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t10 == True:
        t10= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t10="Failed"
    
    t11,message11= sriov_test_case_11(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t11 == True:
        t11= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t11="Failed"
    
    t12,message12= sriov_test_case_12(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t12 == True:
        t12= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t12="Failed"
    
    t13,message13, t14, message14= sriov_test_case_13_14(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t13 == True:
        t13= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t13="Failed"
    if t14 == True:
        t14= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t14="Failed" 
    
    t15,message15= sriov_test_case_15(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t15 == True:
        t15= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t15="Failed"
    
    t16,message16= sriov_test_case_16(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t16 == True:
        t16= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t6="Failed"

    t17,message17= sriov_test_case_17(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t17 == True:
        t17= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t17="Failed"
    
    t18,message18= sriov_test_case_18(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t18 == True:
        t18= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t18="Failed"
    t19,message19= sriov_test_case_19(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t19 == True:
        t19= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t19="Failed"
    t20,message20= sriov_test_case_20(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t20 == True:
        t20= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t20="Failed"
    if(volume== True):
        volume_passed, volume_message= sriov_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, flavor_id, network1_id, security_group_id, image_id)
    #Changing qouta to default settings
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    #Deleting zones
    try:
        remove_host_from_zone(nova_ep, token, nova0_id, compute0)
        remove_host_from_zone(nova_ep, token, nova1_id, compute1)
        remove_host_from_zone(nova_ep, token, nova1_id, compute2)
        add_host_to_zone(nova_ep, token, default_zone_id, compute0)
        add_host_to_zone(nova_ep, token, default_zone_id, compute1)
        add_host_to_zone(nova_ep, token, default_zone_id, compute2)
        delete_resource("{}/v2.1/os-aggregates/{}".format(nova_ep, nova0_id), token)
        delete_resource("{}/v2.1/os-aggregates/{}".format(nova_ep, nova1_id), token)
    except Exception as e:
        logging.exception(e)
     
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    logging.info("---------------------------")
    logging.info("------SRIOV Test Cases------")
    logging.info("---------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))
    
    logging.info("SRIOV test case 3 status: {} ".format(t3))
    logging.info("SRIOV test case 7 status: {} ".format(t7))
    logging.info("SRIOV test case 8 status: {} ".format(t8))
    logging.info("SRIOV test case 10 status: {} ".format(t10))
    logging.info("SRIOV test case 11 status: {} ".format(t11))
    logging.info("SRIOV test case 12 status: {} ".format(t12))
    logging.info("SRIOV test case 13 status: {} ".format(t13))
    logging.info("SRIOV test case 14 status: {} ".format(t14))
    logging.info("SRIOV test case 15 status: {} ".format(t15))
    logging.info("SRIOV test case 16 status: {} ".format(t16))
    logging.info("SRIOV test case 17 status: {} ".format(t17))
    logging.info("SRIOV test case 18 status: {} ".format(t18))
    logging.info("SRIOV test case 19 status: {} ".format(t19))
    logging.info("SRIOV test case 20 status: {} ".format(t20))
    
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    
    logging.info("SRIOV test case 3 status: {} ".format(t3))
    logging.info("SRIOV message  {} \n".format(message3))
    logging.info("------------------------------")
    logging.info("SRIOV test case 7 status: {} ".format(t7))
    logging.info("SRIOV message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("SRIOV test case 8 status: {} ".format(t8))
    logging.info("SRIOV message  {} \n".format(message8))
    logging.info("------------------------------")
    logging.info("SRIOV test case 10 status: {} ".format(t10))
    logging.info("SRIOV message  {} \n".format(message10))
    logging.info("------------------------------")
    logging.info("SRIOV test case 11 status: {} ".format(t11))
    logging.info("SRIOV message  {} \n".format(message11))
    logging.info("------------------------------")
    logging.info("SRIOV test case 12 status: {} ".format(t12))
    logging.info("SRIOV message  {} \n".format(message12))
    logging.info("------------------------------")
    logging.info("SRIOV test case 13 status: {} ".format(t13))
    logging.info("SRIOV message  {} \n".format(message13))
    logging.info("------------------------------")
    logging.info("SRIOV test case 14 status: {} ".format(t14))
    logging.info("SRIOV message  {} \n".format(message14))
    logging.info("------------------------------")
    logging.info("SRIOV test case 15 status: {} ".format(t15))
    logging.info("SRIOV message  {} \n".format(message15))
    logging.info("------------------------------")
    logging.info("SRIOV test case 16 status: {} ".format(t16))
    logging.info("SRIOV message  {} \n".format(message16))
    logging.info("------------------------------")
    logging.info("SRIOV test case 17 status: {} ".format(t17))
    logging.info("SRIOV message  {} \n".format(message17))
    logging.info("------------------------------")
    logging.info("SRIOV test case 18 status: {} ".format(t18))
    logging.info("SRIOV message  {} \n".format(message18))
    logging.info("------------------------------")
    logging.info("SRIOV test case 19 status: {} ".format(t19))
    logging.info("SRIOV message  {} \n".format(message19))
    logging.info("------------------------------")
    logging.info("SRIOV test case 20 status: {} ".format(t20))
    logging.info("SRIOV message  {} \n".format(message20))
    logging.info("------------------------------")
    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------SRIOV Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("Hugepage Volume Testcase Results")
        logging.info("{}".format(volume_message))

def ovsdpdk_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    
    passed=failed=0    
    #Temporary changing quota
    logging.info("temporary changing quota")
    project_id= find_admin_project_id(keystone_ep, token)
    try: 
        set_quota(nova_ep, token, project_id, 200, 25, 204800)
        time.sleep(10)
    except:
        pass

    t9, message9= ovsdpdk_test_case_9(baremetal_nodes_ips, settings)
    if t9 == True:
        t9= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t9="Failed"
    t11, message11= ovsdpdk_test_case_11(baremetal_nodes_ips, settings)
    if t11 == True:
        t11= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t11="Failed"
    
    t15, message15= ovsdpdk_test_case_15(nova_ep, token, settings)
    if t15 == True:
        t15= "Passed"
        passed=passed+1
        t15="Failed"
    else:
        failed=failed+1
        t15="Failed"
    
    t16, message16= ovsdpdk_test_case_16()
    if t16 == True:
        t16= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t16="Failed"
    t17, message17= ovsdpdk_test_case_17(baremetal_nodes_ips, settings)
    if t17 == True:
        t17= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t17="Failed" 
    t18, message18= ovsdpdk_test_case_18(baremetal_nodes_ips)
    if t18 == True:
        t18= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t18="Failed"
    
    #t22= ovsdpdk_test_case_22(baremetal_nodes_ips)
    #if t22 == True:
    #    t22= "Passed"
    #    passed=passed+1
    #else:
    #    failed=failed+1
    #    t22="Failed"
    
    t28, message28= ovsdpdk_test_case_28(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t28 == True:
        t28= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t28="Failed"
    
    #t36, message36= ovsdpdk_test_case_36(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    #if t36 == True:
    #    t36= "Passed"
    #    passed=passed+1
    #else:
    #    failed=failed+1
    #    t36="Failed"
    
    t43, message43= ovsdpdk_test_case_43(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t43 == True:
        t43= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t43="Failed"
    
    t46, message46= ovsdpdk_test_case_46(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t46 == True:
        t46= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t46="Failed"
    
    t47, message47= ovsdpdk_test_case_47(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t47 == True:
        t47= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t47="Failed"
    
    t48, message48= ovsdpdk_test_case_48(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t48 == True:
        t48= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t48="Failed"
    
    t49, message49= ovsdpdk_test_case_49(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t49 == True:
        t49= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t49="Failed"
    t50, message50= ovsdpdk_test_case_50(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t50 == True:
        t50= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t50="Failed"
    #Changing qouta to default settings
    logging.info("setting default quota")
    try:
        set_quota(nova_ep, token, project_id, 20, 20, 51200)
    except:
        pass

    if(volume== True):
        volume_passed, volume_message= ovsdpdk_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, flavor_id,  network1_id, security_group_id, image_id)
    
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)
 
    logging.info("------------------------------")
    logging.info("------OVSDPDK Test Cases------")
    logging.info("------------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))
    
    logging.info("OVSDPDK test case 9 status: {} ".format(t9))
    logging.info("OVSDPDK test case 11 status: {} ".format(t11))
    logging.info("OVSDPDK test case 15 status: {} ".format(t15))
    logging.info("OVSDPDK test case 16 status: {} ".format(t16))
    logging.info("OVSDPDK test case 17 status: {} ".format(t17))
    logging.info("OVSDPDK test case 18 status: {} ".format(t18))
    #logging.info("OVSDPDK test case 22 status: {} ".format(t22))
    logging.info("OVSDPDK test case 28 status: {} ".format(t28))
    #logging.info("OVSDPDK test case 36 status: {} ".format(t36))
    logging.info("OVSDPDK test case 43 status: {} ".format(t43))
    logging.info("OVSDPDK test case 46 status: {} ".format(t46))
    logging.info("OVSDPDK test case 47 status: {} ".format(t47))
    logging.info("OVSDPDK test case 48 status: {} ".format(t48))
    logging.info("OVSDPDK test case 49 status: {} ".format(t49))
    logging.info("OVSDPDK test case 50 status: {} ".format(t50))
    
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 9 status: {} ".format(t9))
    logging.info("OVSDPDK message  {} \n".format(message9))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 11 status: {} ".format(t11))
    logging.info("OVSDPDK message  {} \n".format(message11))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 15 status: {} ".format(t15))
    logging.info("OVSDPDK message  {} \n".format(message15))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 16 status: {} ".format(t16))
    logging.info("OVSDPDK message  {} \n".format(message16))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 17 status: {} ".format(t17))
    logging.info("OVSDPDK message  {} \n".format(message17))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 18 status: {} ".format(t18))
    logging.info("OVSDPDK message  {} \n".format(message18))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 18 status: {} ".format(t18))
    logging.info("OVSDPDK message  {} \n".format(message18))
    logging.info("------------------------------")
    #logging.info("OVSDPDK test case 22 status: {} ".format(t22))
    #logging.info("Mtu message  {} \n".format(message22))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 28 status: {} ".format(t28))
    logging.info("OVSDPDK message  {} \n".format(message28))
    logging.info("------------------------------")
    #logging.info("OVSDPDK test case 36 status: {} ".format(t36))
    #logging.info("OVSDPDK message  {} \n".format(message36))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 43 status: {} ".format(t43))
    logging.info("OVSDPDK message  {} \n".format(message43))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 46 status: {} ".format(t46))
    logging.info("OVSDPDK message  {} \n".format(message46))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 47 status: {} ".format(t47))
    logging.info("OVSDPDK message  {} \n".format(message47))
    logging.info("------------------------------")    
    logging.info("OVSDPDK test case 48 status: {} ".format(t48))
    logging.info("OVSDPDK message  {} \n".format(message48))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 49 status: {} ".format(t49))
    logging.info("OVSDPDK message  {} \n".format(message49))
    logging.info("------------------------------")
    logging.info("OVSDPDK test case 50 status: {} ".format(t50))
    logging.info("OVSDPDK message  {} \n".format(message50))
    logging.info("------------------------------")
    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------OVSDPDK Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("OVSDPDK Volume Testcase Results")
        logging.info("{}".format(volume_message))
     
def mtu9000_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep,  token, settings, baremetal_nodes_ips, features, volume):
    
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    passed=failed=0
    
    t3, message3= mtu9000_test_case_3(baremetal_nodes_ips)
    if t3 is True:
        passed=passed+1
        t3= "Passed"
    else: 
        failed= failed+1
        t3= "Failed"
    
    t4, message4= mtu9000_test_case_4(baremetal_nodes_ips)
    if t4 is True:
        passed=passed+1
        t4= "Passed"
    else: 
        failed= failed+1
        t4= "Failed"
    t5, message5= mtu9000_test_case_5(baremetal_nodes_ips)
    if t5 is True:
        passed=passed+1
        t5= "Passed"
    else: 
        failed= failed+1
        t5= "Failed"
    t6, message6= mtu9000_test_case_6(baremetal_nodes_ips)
    if t6 is True:
        passed=passed+1
        t6= "Passed"
    else: 
        failed= failed+1
        t6= "Failed"
    
    t7, message7= mtu9000_test_case_7(baremetal_nodes_ips)
    if t7 is True:
        passed=passed+1
        t7= "Passed"
    else: 
        failed= failed+1
        t7= "Failed"

    t8, message8= mtu9000_test_case_8(baremetal_nodes_ips)
    if t8 is True:
        passed=passed+1
        t8= "Passed"
    else: 
        failed= failed+1
        t8= "Failed"
    
    t9, message9= mtu9000_test_case_9(neutron_ep, token, network1_id)
    if t9 is True:
        passed=passed+1
        t9= "Passed"
    else: 
        failed= failed+1
        t9= "Failed"
    
    t10,message10= mtu9000_test_case_10(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t10 is True:
        passed=passed+1
        t10= "Passed"
    else: 
        failed= failed+1
        t10= "Failed"
    
    t11,message11= mtu9000_test_case_11(neutron_ep, token, router_id, settings)
    if t11 is True:
        passed=passed+1
        t11= "Passed"
    else: 
        failed= failed+1
        t11= "Failed"
    
    t12,message12= mtu9000_test_case_12(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t12 is True:
        passed=passed+1
        t12= "Passed"
    else: 
        failed= failed+1
        t12= "Failed"
    
    
    t13,message13= mtu9000_test_case_13(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t13 is True:
        passed=passed+1
        t13= "Passed"
    else: 
        failed= failed+1
        t13= "Failed"
    
    t14,message14= mtu9000_test_case_14(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t14 is True:
        passed=passed+1
        t14= "Passed"
    else: 
        failed= failed+1
        t14= "Failed"
    
    
    t15,message15= mtu9000_test_case_15(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t15 is True:
        passed=passed+1
        t15= "Passed"
    else: 
        failed= failed+1
        t15= "Failed"
    
    t16,message16= mtu9000_test_case_16(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t16 is True:
        passed=passed+1
        t16= "Passed"
    else: 
        failed= failed+1
        t16= "Failed"
        
    if(volume== True):
        volume_passed, volume_message= mtu9000_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, flavor_id,  network1_id, security_group_id, image_id)

    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    
    logging.info("------------------------------")
    logging.info("------MTU9000 Test Cases------")
    logging.info("------------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))
    logging.info("MTU test case 3 status: {} ".format(t3))
    logging.info("MTU test case 4 status: {} ".format(t4))
    logging.info("MTU test case 5 status: {} ".format(t5))
    logging.info("MTU test case 6 status: {} ".format(t6))
    logging.info("MTU test case 7 status: {} ".format(t7))
    logging.info("MTU test case 8 status: {} ".format(t8))
    
    logging.info("MTU test case 9 status: {} ".format(t9))
    logging.info("MTU test case 10 status: {} ".format(t10))
    logging.info("MTU test case 11 status: {} ".format(t11))
    logging.info("MTU test case 12 status: {} ".format(t12))
    logging.info("MTU test case 13 status: {} ".format(t13))
    
    logging.info("MTU test case 14 status: {} ".format(t14))
    logging.info("MTU test case 15 status: {} ".format(t15))
    logging.info("MTU test case 16 status: {} ".format(t16))
    
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    
    logging.info("MTU test case 3 status: {} ".format(t3))
    logging.info("Mtu message  {} \n".format(message3))
    logging.info("------------------------------")
    logging.info("MTU test case 4 status: {} ".format(t4))
    logging.info("Mtu message  {} \n".format(message4))
    logging.info("------------------------------")
    logging.info("MTU test case 5 status: {} ".format(t5))
    logging.info("Mtu message  {} \n".format(message5))
    logging.info("------------------------------")
    logging.info("MTU test case 6 status: {} ".format(t6))
    logging.info("Mtu message  {} \n".format(message6))
    logging.info("------------------------------")
    
    logging.info("MTU test case 7 status: {} ".format(t7))
    logging.info("Mtu message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("MTU test case 8 status: {} ".format(t8))
    logging.info("Mtu message  {} \n".format(message8))
    logging.info("------------------------------")
    
    logging.info("MTU test case 9 status: {} ".format(t9))
    logging.info("Mtu message  {} \n".format(message9))
    logging.info("------------------------------")
    logging.info("MTU test case 10 status: {} ".format(t10))
    logging.info("Mtu message  {} \n".format(message10))
    logging.info("------------------------------")
    logging.info("MTU test case 11 status: {} ".format(t11))
    logging.info("Mtu message  {} \n".format(message11))
    logging.info("------------------------------")
    logging.info("MTU test case 12 status: {} ".format(t12))
    logging.info("Mtu message  {} \n".format(message12))
    logging.info("------------------------------")
    logging.info("MTU test case 13 status: {} ".format(t13))
    logging.info("Mtu message  {} \n".format(message13))
    logging.info("------------------------------")
    
    logging.info("MTU test case 14 status: {} ".format(t14))
    logging.info("Mtu message  {} \n".format(message14))
    logging.info("------------------------------")
    
    logging.info("MTU test case 15 status: {} ".format(t15))
    logging.info("Mtu message  {} \n".format(message15))
    logging.info("------------------------------")
    logging.info("MTU test case 16 status: {} ".format(t16))
    logging.info("Mtu message  {} \n".format(message16))
    logging.info("------------------------------")
   
    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------MTU9000 Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("MTU9000 Volume Testcase Results")
        logging.info("{}".format(volume_message))
    
def dvr_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    passed=failed=0
    t7, message7= dvr_test_case_7(baremetal_nodes_ips)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"

    t8, message8= dvr_test_case_8(baremetal_nodes_ips)
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"
    
    t10, message10= dvr_test_case_10(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, router_id, security_group_id, image_id, flavor_id)
    if t10 == True:
        t10= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t10="Failed"
    
    t11, message11= dvr_test_case_11(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id, flavor_id)
    if t11 == True:
        t11= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t11="Failed"
    
    t12, message12= dvr_test_case_12(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id, flavor_id)
    if t12 == True:
        t12= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t12="Failed"
    
     
    t13, message13= dvr_test_case_13(baremetal_nodes_ips)
    if t13 == True:
        t13= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t13="Failed"
    
    t14, message14, t15, message15, t23, message23= dvr_test_case_14_15_23(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id, flavor_id)
    if t14 == True:
        t14= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t14="Failed"
    
    if t15 == True:
        t15= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t15="Failed"
   
    if t23 == True:
        t23= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t23="Failed"
   
    
    t16, message16= dvr_test_case_16(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id, flavor_id)
    if t16 == True:
        t16= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t16="Failed"
   
    t19, message19= dvr_test_case_19(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, router_id, security_group_id, image_id, flavor_id)
    if t19 == True:
        t19= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t19="Failed"
    
    t17, message17= dvr_test_case_17(neutron_ep, token)
    if t17 == True:
        t17= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t17="Failed"
    
    t31, message31= dvr_test_case_31(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t31 == True:
        t31= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t31="Failed"
    
    t32, message32= dvr_test_case_32(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t32 == True:
        t32= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t32="Failed"
   
    if(volume== True):
        volume_passed, volume_message= dvr_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, flavor_id,  network1_id, security_group_id, image_id)
    
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    logging.info("------------------------------")
    logging.info("---------DVR Test Cases-------")
    logging.info("------------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))
    
    logging.info("DVR test case 7 status: {} ".format(t7))
    logging.info("DVR test case 8 status: {} ".format(t8))
    logging.info("DVR test case 10 status: {} ".format(t10))
    logging.info("DVR test case 11 status: {} ".format(t11))
    logging.info("DVR test case 12 status: {} ".format(t12))
    logging.info("DVR test case 13 status: {} ".format(t13))
    logging.info("DVR test case 14 status: {} ".format(t14))
    logging.info("DVR test case 15 status: {} ".format(t15))
    logging.info("DVR test case 16 status: {} ".format(t16))
    logging.info("DVR test case 17 status: {} ".format(t17))
    logging.info("DVR test case 19 status: {} ".format(t19))
    logging.info("DVR test case 23 status: {} ".format(t23))
    logging.info("DVR test case 31 status: {} ".format(t31))
    logging.info("DVR test case 32 status: {} ".format(t32))
   
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    logging.info("DVR test case 7 status: {} ".format(t7))
    logging.info("DVR message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("DVR test case 8 status: {} ".format(t8))
    logging.info("DVR message  {} \n".format(message8))
    logging.info("------------------------------")
    logging.info("DVR test case 10 status: {} ".format(t10))
    logging.info("DVR message  {} \n".format(message10))
    logging.info("------------------------------")
    logging.info("DVR test case 11 status: {} ".format(t11))
    logging.info("DVR message  {} \n".format(message11))
    logging.info("------------------------------")
    logging.info("DVR test case 12 status: {} ".format(t12))
    logging.info("DVR message  {} \n".format(message12))
    logging.info("------------------------------")
    logging.info("DVR test case 13 status: {} ".format(t12))
    logging.info("DVR message  {} \n".format(message13))
    logging.info("------------------------------")
    logging.info("DVR test case 14 status: {} ".format(t14))
    logging.info("DVR message  {} \n".format(message14))
    logging.info("------------------------------")
    logging.info("DVR test case 15 status: {} ".format(t15))
    logging.info("DVR message  {} \n".format(message15))
    logging.info("------------------------------")
    logging.info("DVR test case 16 status: {} ".format(t16))
    logging.info("DVR message  {} \n".format(message16))
    logging.info("------------------------------")
    logging.info("DVR test case 17 status: {} ".format(t17))
    logging.info("DVR message  {} \n".format(message17))
    logging.info("------------------------------")
    logging.info("DVR test case 19 status: {} ".format(t19))
    logging.info("DVR message  {} \n".format(message19))
    logging.info("------------------------------")
    logging.info("DVR test case 23 status: {} ".format(t23))
    logging.info("DVR message  {} \n".format(message23))
    logging.info("------------------------------")
    logging.info("DVR test case 31 status: {} ".format(t31))
    logging.info("DVR message  {} \n".format(message31))
    logging.info("------------------------------")    
    logging.info("DVR test case 32 status: {} ".format(t32))
    logging.info("DVR message  {} \n".format(message32))
    logging.info("------------------------------")
    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------DVR Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("DVR Volume Testcase Results")
        logging.info("{}".format(volume_message))
    

def octavia_test_cases(nova_ep, neutron_ep, image_ep, loadbal_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    passed=failed=0
    '''
    t5,message5, t6,message6= octavia_test_case_5_6(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t5 == True:
        t5= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t5="Failed"
    print(t5)
    print(message5)

    if t6 == True:
        t6= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t6="Failed"
    print(t6)
    print(message6)

    '''
    
    t3, message3, t4,message4, t7,message7, t8,message8, t9,message9, t10,message10= octavia_test_case_3_4_7_8_9_10(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t3 == True:
        t3= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t3="Failed"
    print(t3)
    print(message3)
    if t4 == True:
        t4= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t4="Failed"
    print(t4)
    print(message4)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"
    print(t7)
    print(message7)
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"
    print(t8)
    print(message8)
    if t9 == True:
        t9= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t9="Failed"
    print(t9)
    print(message9)

    if t10 == True:
        t10= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t10="Failed"
    print(t10)
    print(message10)
    '''
    t12, message12= octavia_test_case_12(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t12 == True:
        t12= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t12="Failed"
    print(t12)
    print(message12)

    t25, message25= octavia_test_case_25(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t25 == True:
        t25= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t25="Failed"
    print(t25)
    print(message25)
    
    t26, message26= octavia_test_case_26(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t26 == True:
        t26= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t26="Failed"
    print(t26)
    print(message26)
    
    t27, message27= octavia_test_case_27(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t27 == True:
        t27= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t27="Failed"
    print(t27)
    print(message27)
    
    t28, message28= octavia_test_case_28(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t28 == True:
        t28= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t28="Failed"
    print(t28)
    print(message28)
    
    t29, message29= octavia_test_case_29(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t29 == True:
        t29= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t29="Failed"
    print(t29)
    print(message29)
    
    t30, message30= octavia_test_case_30(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t30 == True:
        t30= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t30="Failed"
    print(t30)
    print(message30)
    
    t31, message31= octavia_test_case_31(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t31 == True:
        t31= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t31="Failed"
    print(t31)
    print(message31)
    
    t32, message32= octavia_test_case_32(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t32 == True:
        t32= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t32="Failed"
    print(t32)
    print(message32)
    
    t33, message33= octavia_test_case_33(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t33 == True:
        t33= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t33="Failed"
    print(t33)
    print(message33)
    
    t34, message34= octavia_test_case_34(nova_ep, neutron_ep, image_ep, loadbal_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, router_id, security_group_id, image_id)
    if t34 == True:
        t34= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t34="Failed"
    print(t34)
    print(message34)
       
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    '''
def sriov_vflag_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep,  token, settings, baremetal_nodes_ips, features, volume):
    #creating zones
    
    try:
        compute0 =  [key for key, val in baremetal_nodes_ips.items() if "compute-0" in key]
        compute0= compute0[0]
        compute1 =  [key for key, val in baremetal_nodes_ips.items() if "compute-1" in key]
        compute1= compute1[0]
        default_zone_id= get_availability_zones(nova_ep, token)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute0)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute1)
        nova0_id= create_availability_zones(nova_ep, token, "nova0")
        nova1_id= create_availability_zones(nova_ep, token, "nova1")
        add_host_to_zone(nova_ep, token, nova0_id, compute0)
        add_host_to_zone(nova_ep, token, nova1_id, compute1)
    except Exception as e:
        pass
    time.sleep(20)
    
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    passed=failed=0

    sriov_vflag_test_case_3(baremetal_nodes_ips)
    sriov_vflag_test_case_6(baremetal_nodes_ips)
    t7,message7, t9,message9= sriov_vflag_test_case_7_9(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    print(t7)
    print(message7)
    print(t9)
    print(message9)
    t10,message10= sriov_vflag_test_case_10(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    print(t10)
    print(message10)
    t11,message11= sriov_vflag_test_case_11(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id)
    print(t11)
    print(message11)
    t12,message12= sriov_vflag_test_case_12(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id)
    print(t12)
    print(message12)
    t13,message13= sriov_vflag_test_case_13(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    print(t13)
    print(message13)
    
    t14,message14= sriov_vflag_test_case_14(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id)
    print(t14)
    print(message14)
    
    t15,message15= sriov_vflag_test_case_15(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id)
    print(t15)
    print(message15)

    t16,message16= sriov_vflag_test_case_16(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    print(t16)
    print(message16)
    t17,message17= sriov_vflag_test_case_17(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    print(t17)
    print(message17)
    
    '''
    t7,message7, t8,message8= (nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"    
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)
  
    '''
def hci_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, features, volume):
    #creating zones
    try:
        compute0 =  [key for key, val in baremetal_nodes_ips.items() if "hci-0" in key]
        compute0= compute0[0]
        compute1 =  [key for key, val in baremetal_nodes_ips.items() if "hci-1" in key]
        compute1= compute1[0]
        compute2 =  [key for key, val in baremetal_nodes_ips.items() if "hci-2" in key]
        compute2= compute2[0]
        default_zone_id= get_availability_zones(nova_ep, token)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute0)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute1)
        remove_host_from_zone(nova_ep, token, default_zone_id, compute2)
        nova0_id= create_availability_zones(nova_ep, token, "nova0")
        nova1_id= create_availability_zones(nova_ep, token, "nova1")
        #nova2_id= create_availability_zones(nova_ep, token, "nova2")
        add_host_to_zone(nova_ep, token, nova0_id, compute0)
        add_host_to_zone(nova_ep, token, nova1_id, compute1)
        add_host_to_zone(nova_ep, token, nova1_id, compute2)
        time.sleep(20)
    except Exception as e:
        logging.exception(e)
    
    
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    
    passed=failed=0
    t3,message3= hci_test_case_3(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)    
    if t3 == True:
        t3= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t3="Failed"
    
    t4,message4= hci_test_case_4(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t4 == True:
        t4= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t4="Failed"
    
    t5,message5= hci_test_case_5(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t5 == True:
        t5= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t5="Failed"
    t6,message6= hci_test_case_6(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, network2_id, subnet2_id, security_group_id, image_id, flavor_id)
    if t5 == True:
        t6= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t6="Failed"
    
    t7,message7= hci_test_case_7(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"

    t8,message8= hci_test_case_8(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"

    t9,message9= hci_test_case_9(nova_ep, neutron_ep, image_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t9 == True:
        t9= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t9="Failed"

    #Deleting zones
    try:
        remove_host_from_zone(nova_ep, token, nova0_id, compute0)
        remove_host_from_zone(nova_ep, token, nova1_id, compute1)
        remove_host_from_zone(nova_ep, token, nova1_id, compute2)
        add_host_to_zone(nova_ep, token, default_zone_id, compute0)
        add_host_to_zone(nova_ep, token, default_zone_id, compute1)
        add_host_to_zone(nova_ep, token, default_zone_id, compute2)
        delete_resource("{}/v2.1/os-aggregates/{}".format(nova_ep, nova0_id), token)
        delete_resource("{}/v2.1/os-aggregates/{}".format(nova_ep, nova1_id), token)
    except Exception as e:
        logging.exception(e)
        pass

    t10,message10= hci_test_case_10(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, image_id, flavor_id)
    if t10 == True:
        t10= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t10="Failed"
    
    if(volume== True):
        volume_passed, volume_message= hci_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, flavor_id,  network1_id, security_group_id, image_id)
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)

    logging.info("---------------------------")
    logging.info("-------HCI Test Cases-------")
    logging.info("---------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))
    logging.info("HCI test case 3 status: {} ".format(t3))
    logging.info("HCI test case 4 status: {} ".format(t4))
    logging.info("HCI test case 5 status: {} ".format(t5))
    logging.info("HCI test case 6 status: {} ".format(t6))
    logging.info("HCI test case 7 status: {} ".format(t7))
    logging.info("HCI test case 8 status: {} ".format(t8))
    logging.info("HCI test case 9 status: {} ".format(t9))
    logging.info("HCI test case 10 status: {} ".format(t10))
 
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    logging.info("HCI test case 3 status: {} ".format(t3))
    logging.info("HCI message  {} \n".format(message3))
    logging.info("------------------------------")
    logging.info("HCI test case 4 status: {} ".format(t4))
    logging.info("HCI message  {} \n".format(message4))
    logging.info("------------------------------")
    logging.info("HCI test case 5 status: {} ".format(t5))
    logging.info("HCI message  {} \n".format(message5))
    logging.info("------------------------------")
    logging.info("HCI test case 6 status: {} ".format(t6))
    logging.info("HCI message  {} \n".format(message6))
    logging.info("------------------------------")
    logging.info("HCI test case 7 status: {} ".format(t7))
    logging.info("HCI message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("HCI test case 8 status: {} ".format(t8))
    logging.info("HCI message  {} \n".format(message8))
    logging.info("------------------------------")
    logging.info("HCI test case 8 status: {} ".format(t9))
    logging.info("HCI message  {} \n".format(message9))
    logging.info("------------------------------")
    logging.info("HCI test case 10 status: {} ".format(t10))
    logging.info("HCI message  {} \n".format(message10))
    logging.info("------------------------------")

    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------HCI Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("HCI Volume Testcase Results")
        logging.info("{}".format(volume_message))

def barbican_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, barbican_ep, keystone_ep, token, settings, baremetal_nodes_ips, features, volume):
    network1_id, network2_id, subnet1_id, subnet2_id, router_id, security_group_id, image_id, flavor_id, keypair_public_key= setup_testcases(features, settings, neutron_ep, nova_ep, image_ep, barbican_ep, keystone_ep, token)
    if(network1_id == "error" and network2_id =="error"):
        logging.error("error occured during environment setup/ skipping testscases")
        return None
    passed=failed=0
   # ---- can use dictionaries for 
   # mock test library, separate file, name detailed function name 
    t1,message1, t2,message2, t3,message3, t4,message4 = barbican_test_case_1_2_3_4(barbican_ep, token) 
    if t1 == True:
        t1= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t1="Failed"
    if t2 == True:
        t2= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t2="Failed"
    if t3 == True:
        t3= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t3="Failed"
    if t4 == True:
        t4= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t4="Failed"
    
    t5,message5= barbican_test_case_5(barbican_ep, token)
    if t5 == True:
        t5= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t5="Failed"
    
    t6,message6,t7,message7, t8, message8, t9, message9 = barbican_test_case_6_7_8_9(keystone_ep, cinder_ep, nova_ep, neutron_ep, image_ep, barbican_ep, token, settings, baremetal_nodes_ips, keypair_public_key, network1_id, subnet1_id, security_group_id, flavor_id)
    if t6 == True:
        t6= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t6="Failed"
    if t7 == True:
        t7= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t7="Failed"
    if t8 == True:
        t8= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t8="Failed"
    if t9 == True:
        t9= "Passed"
        passed=passed+1
    else:
        failed=failed+1
        t9="Failed"
    if(volume== True):
        volume_passed, volume_message= barbican_volume_test_case(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, token, settings, baremetal_nodes_ips, flavor_id,  network1_id, security_group_id, image_id)
    
    logging.info("cleaning resources")
    delete_setup( token, nova_ep, image_ep, neutron_ep, network1_id, network2_id, subnet1_id, subnet2_id, router_id, image_id, flavor_id, settings)
# --------   pass value to value if true one scenario, else second,
# ------- only one function to finalize results 
#------ pep8
    logging.info("------------------------------")
    logging.info("---------Barbican Test Cases-------")
    logging.info("------------------------------")
    logging.info("Total Testcases {}".format(failed+passed))
    logging.info("Testcases Passed {}".format(passed))
    logging.info("Testcases Failed {}".format(failed))
    
    logging.info("Barbican test case 1 status: {} ".format(t1))
    logging.info("Barbican test case 2 status: {} ".format(t2))
    logging.info("Barbican test case 3 status: {} ".format(t3))
    logging.info("Barbican test case 4 status: {} ".format(t4))
    logging.info("Barbican test case 5 status: {} ".format(t5))
    logging.info("Barbican test case 6 status: {} ".format(t6))
    logging.info("Barbican test case 7 status: {} ".format(t7))
    logging.info("Barbican test case 8 status: {} ".format(t8))
    logging.info("Barbican test case 9 status: {} ".format(t9))
   
    logging.info("------------------------------")
    logging.info("----------Description--------")
    logging.info("------------------------------")
    logging.info("Barbican test case 1 status: {} ".format(t1))
    logging.info("Barbican message  {} \n".format(message1))
    logging.info("------------------------------")
    logging.info("Barbican test case 2 status: {} ".format(t2))
    logging.info("Barbican message  {} \n".format(message2))
    logging.info("------------------------------")
    logging.info("Barbican test case 3 status: {} ".format(t3))
    logging.info("Barbican message  {} \n".format(message3))
    logging.info("------------------------------")
    logging.info("Barbican test case 4 status: {} ".format(t4))
    logging.info("Barbican message  {} \n".format(message4))
    logging.info("------------------------------")
    logging.info("Barbican test case 5 status: {} ".format(t5))
    logging.info("Barbican message  {} \n".format(message5))
    logging.info("------------------------------")
    logging.info("Barbican test case 6 status: {} ".format(t6))
    logging.info("Barbican message  {} \n".format(message6))
    logging.info("------------------------------")
    logging.info("Barbican test case 7 status: {} ".format(t7))
    logging.info("Barbican message  {} \n".format(message7))
    logging.info("------------------------------")
    logging.info("Barbican test case 8 status: {} ".format(t8))
    logging.info("Barbican message  {} \n".format(message8))
    logging.info("------------------------------")
    logging.info("Barbican test case 9 status: {} ".format(t9))
    logging.info("Barbican message  {} \n".format(message9))
    logging.info("------------------------------")
    if(volume== True):
        logging.info("--------------------------------")
        logging.info("------Barbican Volume Test Cases------")
        logging.info("------  ------------------------")
        logging.info("Total Testcases 12")
        logging.info("Testcases Passed {}".format(volume_passed))
        logging.info("Testcases Skipped/Failed {}".format((12-volume_passed)))
        logging.info("Barbican Volume Testcase Results")
        logging.info("{}".format(volume_message))



def main():
   
    #Parse Arguments
    try:
        arguments= parse_arguments()
    except Exception as e:
        logging.exception("error parsing arguments {}".format(e))
        #  exit error ---------------

    #Validate Arguments
    logging.info("validating arguments")
    if not(arguments.feature[0] == "numa" or  arguments.feature[0] == "hugepages" or arguments.feature[0] == "ovsdpdk" or arguments.feature[0] == "sriov" or arguments.feature[0]=="mtu9000" or arguments.feature[0]=="dvr" or arguments.feature[0]=="octavia" or arguments.feature[0]=="sriov_vflag", arguments.feature[0]=="hci", arguments.feature[0]=="barbican"):
        logging.critical("Invalid Argument {}".format(arguments.feature))
        raise ValueError("Invalid Argument {}".format(arguments.feature))

    #Read Settings File
    logging.info("reading settings from file")
    settings= read_settings(arguments.settings)

    #encrypting of rsa key file
    #filename= os.path.expanduser(".ssh/id_rsa")
    command= "ssh-keygen -f ~/.ssh/id_rsa -p -m PEM -f ~/.ssh/id_rsa -N ''"
    os.system(command)
    


    #Read rc files
    logging.info("reading undercloud stackrc file")
    #undercloud_url, undercloud_username, undercloud_password= read_rc_file(arguments.undercloudrc)
    undercloud_ip, undercloud_username, undercloud_password= read_rc_file(arguments.undercloudrc)
    overcloud_ip, overcloud_username, overcloud_password= read_rc_file(arguments.overcloudrc)


    #Create Endpoints
    keystone_ep= "{}:5000".format(overcloud_ip)
    neutron_ep= "{}:9696".format(overcloud_ip)
    cinder_ep= "{}:8776".format(overcloud_ip)
    nova_ep= "{}:8774".format(overcloud_ip)
    image_ep= "{}:9292".format(overcloud_ip) 
    loadbal_ep= "{}:9876".format(overcloud_ip) 
    barbican_ep="{}:9311".format(overcloud_ip) 
    undercloud_keystone_ep= "{}:5000".format(undercloud_ip)
    undercloud_nova_ep= "{}:8774".format(undercloud_ip)

    #Get undercloud authentication Token
    undercloud_token= get_authentication_token(undercloud_keystone_ep, undercloud_username, undercloud_password)
    logging.info("Successfully authenticated with undercloud") if undercloud_token is not None else logging.error("Authentication with undercloud failed")
    
    #Get overcloud authentication token
    logging.info("auhenticating user")
    token= get_authentication_token(keystone_ep, overcloud_username,overcloud_password)

    #Get Ips of baremetal nodes
    baremetal_nodes_ips= get_baremeta_nodes_ip(undercloud_nova_ep, undercloud_token)
    logging.info("Successfully received baremetal nodes ip addresses")
    compoute0_dic = [value for key, val in baremetal_nodes_ips.items() if "compute1" in key]
    #get hist list
    hosts_list= get_compute_host_list(nova_ep, token)
    

    #compute nodes name when when hci is deployed 
    if arguments.feature=="hci":
        compute_node_search_pattern= "hci-"
    else:
        compute_node_search_pattern= "compute-"
    #update compute nodes names in baremetal nodes ip
    logging.info("updating compute nodes name in baremetal nodes ips")
    compute0= [i for i in hosts_list if (compute_node_search_pattern+"0") in i]
    compute0_key = [key for key, val in baremetal_nodes_ips.items() if  (compute_node_search_pattern+"0") in key]
    baremetal_nodes_ips[compute0[0]] = baremetal_nodes_ips.pop(compute0_key[0])
    if(settings["compute_nodes"]== 2 or settings["compute_nodes"]== 3):
        compute1= [i for i in hosts_list if  (compute_node_search_pattern+"1") in i]
        compute1_key = [key for key, val in baremetal_nodes_ips.items() if (compute_node_search_pattern+"1") in key]
        baremetal_nodes_ips[compute1[0]] = baremetal_nodes_ips.pop(compute1_key[0])
    if(settings["compute_nodes"]== 3):
        compute2= [i for i in hosts_list if  (compute_node_search_pattern+"2") in i]
        compute2_key = [key for key, val in baremetal_nodes_ips.items() if (compute_node_search_pattern+"2") in key]
        baremetal_nodes_ips[compute2[0]] = baremetal_nodes_ips.pop(compute2_key[0])
    #Set empty names if less compute nodes to avoid testcase failure
    if(settings["compute_nodes"]== 1):
        baremetal_nodes_ips["compute-1"]= ""
        baremetal_nodes_ips["compute-2"]=""
    if(settings["compute_nodes"]== 2):
        baremetal_nodes_ips["compute-2"]=""
    # ----------- discover nodes logs
    #Run Test Cases
    if arguments.feature[0] == "numa":
        numa_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature,  arguments.volume) 
    if arguments.feature[0] == "hugepages":
        hugepages_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep,keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "ovsdpdk":
        ovsdpdk_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep,keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "sriov":
        sriov_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep,keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "mtu9000":
        mtu9000_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "dvr":
        dvr_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume)
    if arguments.feature[0] == "octavia":
        octavia_test_cases(nova_ep, neutron_ep, image_ep, loadbal_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "sriov_vflag":
        sriov_vflag_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "hci":
        hci_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep,keystone_ep, barbican_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
    if arguments.feature[0] == "barbican":
        barbican_test_cases(nova_ep, neutron_ep, image_ep, cinder_ep, barbican_ep, keystone_ep, token, settings, baremetal_nodes_ips, arguments.feature, arguments.volume) 
   
if __name__ == "__main__":
    main()
