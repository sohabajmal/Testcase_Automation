import os
import json
import logging
import subprocess
import paramiko
import wget
from xml.dom import minidom
from openstack_api_functions.nova import *
from openstack_api_functions.neutron import *
from openstack_api_functions.keystone import *
from beautifultable import BeautifulTable


def read_settings(settings_file):
    #read settings from json file
    if os.path.exists(settings_file):
        try:
            #open setting.json file
            with open(settings_file, 'r') as file:
                 data = file.read().replace('\n', '')
            settings= json.loads(data)
        except Exception as e:
            logging.error("Failed to load settings file \n {}".format(e))
    else:
        logging.error("File not found")
        raise FileNotFoundError ("File {} not found".format(settings_file))
    return settings

def  read_rc_file(rc_file):
    if os.path.exists(os.path.expanduser(rc_file)):
        
        logging.debug("{} file found".format(rc_file))
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
        parameters={"ip": ip, "username": username, "password": password}
        return parameters
    else:
        logging.error("File {} not found".format(rc_file), stack_info=True )
        raise FileNotFoundError ("File {} not found".format(rc_file))

def run_linux_command(command):
    #run command
    command= subprocess.run([command], shell=True, stdout=subprocess.PIPE)
    #parse output
    output= command.stdout.decode('ascii')
    if not output:
        logging.error("Error in executing command {}".format(command),  stack_info=True)
        raise ValueError("Error in executing command {}".format(command))
    return output
def create_services_endpoints(undercloud_ip, overcloud_ip):
    #create openstack endpoints
    endpoints={}
    endpoints["keystone"]= "{}:5000".format(overcloud_ip)
    endpoints["neutron"]= "{}:9696".format(overcloud_ip)
    endpoints["cinder"]= "{}:8776".format(overcloud_ip)
    endpoints["nova"]= "{}:8774".format(overcloud_ip)
    endpoints["image"]= "{}:9292".format(overcloud_ip) 
    endpoints["loadbalancer"]= "{}:9876".format(overcloud_ip) 
    endpoints["barbican"]="{}:9311".format(overcloud_ip) 
    endpoints["undercloud_keystone"]= "{}:5000".format(undercloud_ip)
    endpoints["undercloud_nova"]= "{}:8774".format(undercloud_ip)
    return endpoints
def read_ini_settings(sah_ip, ini_file):
    settings_dic={}
    command= "grep -e mtu_size_global_default= -e nic_env_file= -e hpg_enable= -e hpg_size= -e numa_enable= -e ovs_dpdk_enable= -e sriov_enable= -e smart_nic= -e dvr_enable= -e barbican_enable= -e octavia_enable= -e overcloud_name= -e sanity_image_url= -e domain= -e floating_ip_network_vlan= -e floating_ip_network= -e floating_ip_network_gateway= -e floating_ip_network_start_ip= -e floating_ip_network_end_ip= -e enable_powerflex_backend {}".format(ini_file)
    settings= ssh_into_node(sah_ip, command, "root")
    #Parse string for new line
    settings= settings[0].split("\n")
    #parse mtu size
    mtu_size=settings[0].split("=")
    settings_dic['mtu_size']=mtu_size[1]
    #DPDK Ports
    deployment=settings[1].split("=")
    deployment=str(deployment[1]).split("/")
    if("9" in deployment[0] or "8" in deployment[0]):
        if("sriov" in deployment[0]):
            ports= 2
        else:
            ports=4
    else:
        ports= 2
    settings_dic['dpdk_ports']=ports
    #hugepage_enabled
    hpg_enable=settings[2].split("=")
    settings_dic['hugepage_enabled']=hpg_enable[1]
    #hugepage_size
    hpg_size=settings[3].split("=")
    settings_dic['hugepage_size']=hpg_size[1]
    #numa_enabled
    numa_enable=settings[4].split("=")
    settings_dic['numa_enabled']=numa_enable[1]
    #ovs_dpdk_enable
    ovs_dpdk_enable=settings[5].split("=")
    settings_dic['ovs_dpdk_enabled']=ovs_dpdk_enable[1]
    #sriov_enable
    sriov_enable=settings[6].split("=")
    settings_dic['sriov_enabled']=sriov_enable[1]
    #smart_nic
    smart_nic=settings[7].split("=")
    settings_dic['smart_nic']=smart_nic[1]
    #dvr_enable
    dvr_enable=settings[8].split("=")
    settings_dic['dvr_enabled']=dvr_enable[1]
    #barbican_enable
    barbican_enable=settings[9].split("=")
    settings_dic['barbican_enabled']=barbican_enable[1]
    #octavia_enable
    octavia_enable=settings[10].split("=")
    settings_dic['octavia_enabled']=octavia_enable[1]
    #overcloud name
    overcloud_name=settings[11].split("=")
    settings_dic['overcloud_name']=overcloud_name[1]
    #sanity image name
    domain=settings[12].split("=")
    settings_dic['domain']= domain[1]
    #powerflex_enable
    powerflex=settings[13].split("=")
    settings_dic['powerflex_enable']= powerflex[1]

    #Get flloating ip details
    #get floating network cidr
    floating_ip_network_cidr=settings[14].split("=")
    settings_dic['floating_ip_network_cidr']=floating_ip_network_cidr[1]
    #get floating ip start range
    floating_ip_network_start_ip=settings[15].split("=")
    settings_dic['floating_ip_network_start_ip']=floating_ip_network_start_ip[1]
    #get floating ip end range
    floating_ip_network_end_ip=settings[16].split("=")
    settings_dic['floating_ip_network_end_ip']=floating_ip_network_end_ip[1]
    #get floating network gateway
    floating_ip_network_gateway=settings[17].split("=")
    settings_dic['floating_ip_network_gateway']=floating_ip_network_gateway[1]
    #get floating network vlan
    floating_ip_network_vlan=settings[18].split("=")
    settings_dic['floating_ip_network_vlan']=floating_ip_network_vlan[1]
    #sanity image url
    sanity_image_url=settings[19].split("=")
    settings_dic['sanity_image_url']=sanity_image_url[1]
    #sanity image name
    sanity_image_url=sanity_image_url[1].split("/")
    settings_dic['image_file_name']= "~/{}".format(sanity_image_url[-1])
    return settings_dic

def download_qcow_image(url):
    logging.info("Downloading centos qcow image")
    wget.download(url, os.path.expanduser("~/"))

def ssh_into_node(host_ip, command, user_name="heat-admin"):
    try:
        logging.debug("Trying to connect with node {}".format(host_ip))
        # ins_id = conn.get_server(server_name).id
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        #if username is root
        if (user_name == "root"):
            ssh_session = ssh_client.connect(host_ip, 22, user_name, "Dell0SS!")
        else:
            #if public key saved in id_rsa
            ssh_session = ssh_client.connect(host_ip, username=user_name, key_filename=os.path.expanduser("~/.ssh/id_rsa")) 
        logging.debug("Running command in a compute node")
        #run command
        stdin, stdout, stderr = ssh_client.exec_command(command)
        logging.debug("command {} successfully executed on node {}".format(command, host_ip))
        #decode output
        output= stdout.read().decode('ascii')
        error= stderr.read().decode('ascii')
        
        return output, error
    except Exception as e:
        logging.exception(e)
        logging.error("error ocurred when making ssh connection and running command on remote server") 
    finally:
        ssh_client.close()
        logging.debug("connection from client has been closed") 

def create_instance(settings, environment, nova_ep, neutron_ep, token, flavor_id, server_name, network_name, network_id, compute=None, skip_floaating_ip_assignment="No", feature=None, subnet_id=None):
    server={}
    if feature == "sriov" or feature == "vflag":
        if feature == "vflag":
            port_id, port_ip= create_port(neutron_ep, token, network_id, subnet_id, settings["sriov_port_name"], "vflag")
        else:
            port_id, port_ip= create_port(neutron_ep, token, network_id, subnet_id, settings["sriov_port_name"])
        server_id= search_and_create_sriov_server(nova_ep, token, server_name, environment.get("image_id"), settings["key_name"], flavor_id,  port_id, environment.get("security_group_id"), compute)
        server["port_id"]=port_id
    else:
        server_id= search_and_create_server(nova_ep, token, server_name, environment.get("image_id"), settings["key_name"], flavor_id,  network_id, environment.get("security_group_id"), compute)
    server["id"]=server_id
    server_build_wait(nova_ep, token, [server_id])
    status= check_server_status(nova_ep, token, server_id)
    server["status"]=status
    if(status=="active" and skip_floaating_ip_assignment=="No"):
        if feature !="sriov":
            server_ip= get_server_ip(nova_ep, token, server_id, network_name)
            server["ip"]=server_ip
        else:
            server_ip= port_ip
            server["ip"]=port_ip
        floating_ip= get_server_floating_ip(nova_ep, token, server_id, network_name)
        floating_ip_id= get_floating_ip_id(neutron_ep, token, floating_ip)
        server["floating_ip_id"]=floating_ip_id
        if floating_ip is None:         
            server_port= get_ports(neutron_ep, token, network_id, server_ip)
            public_network_id= search_network(neutron_ep, token, settings["external_network_name"])
            public_subnet_id= search_subnet(neutron_ep, token, settings["external_subnet"])
            floating_ip, floating_ip_id= create_floating_ip(neutron_ep, token, public_network_id, public_subnet_id, server_ip, server_port)
            #Wait for instance to complete boot
            wait_instance_boot(floating_ip, settings["instance_boot_wait_retires"])
        server["floating_ip"]=floating_ip
        server["floating_ip_id"]=floating_ip_id 
    return server

def cold_migrate_instance(nova_ep, token, instance_id, instance_floating_ip, settings):
    response=  perform_action_on_server(nova_ep,token, instance_id, "migrate")
    logging.info("Waiting for migration")
    time.sleep(30)
    if response==202:
        logging.info("confirming migration")
        perform_action_on_server(nova_ep,token, instance_id, "confirmResize")
        time.sleep(30)
        wait_instance_boot(instance_floating_ip, settings["instance_boot_wait_retires"])
    return response

def get_compute_name(baremetal_nodes, compute, domain):
    compute= [key for key, val in baremetal_nodes.items() if compute in key]
    #compute= "{}.localdomain".format(compute[0])
    compute= "{}.{}".format(compute[0],domain)
    return compute
def get_node_ip(baremetal_nodes, node_name):
    ip= [val for key, val in baremetal_nodes.items() if node_name in key]
    if len(ip)==1:
        return ip[0]
    else:
        return ip

def perform_action_on_instances(instances, nova_ep, token, action):
    for instance in instances:   
        perform_action_on_server(nova_ep,token, instance.get("id"), action)
    time.sleep(10)

def get_testcases_summary(testcases_detail, deployed_features):
    passed=failed=skipped=0
    for key in testcases_detail.items():
        print(key)
    for test in testcases_detail:
        if(testcases_detail[test][1]=="Passed"):
            passed+=1
            print("Passed: {}".format(test))
        if(testcases_detail[test][1]=="Failed" or testcases_detail[test][1]== "Unknown"):
            failed+=1
            print("Failed: {}".format(test))
            print(testcases_detail[test][1])
        if(testcases_detail[test][1]=="Skipped"):
            skipped+=1
            print("Skipped: {}".format(test))
    total_testcases= passed+ failed+ skipped
    table = BeautifulTable()
    header=["", "Total", "Passed", "Failed", "Skipped"]
    row=["Total",total_testcases, passed, failed, skipped]
    
    table.columns.header= header
    table.rows.append(row)
    for feature in deployed_features:
        row=[feature.capitalize()]
        total=passed=failed=skipped=0
        for testcase in testcases_detail:
            if(testcases_detail[testcase][0]==feature):
                #print("{}: {} ".format(testcase, testcases_detail[testcase][1]))
                if(testcases_detail[testcase][1]=="Failed" or testcases_detail[testcase][1]== "Unknown"):
                    failed+=1
                    total+=1
                if(testcases_detail[testcase][1]=="Passed"):
                    passed+=1
                    total+=1
                if(testcases_detail[testcase][1]=="Skipped"):
                    skipped+=1
                    total+=1
            if(testcases_detail[testcase][0] not in deployed_features):
                deployed_features.append(testcases_detail[testcase][0])
        row.extend([total,passed,failed,skipped])
        table.rows.append(row)

    return table

def clean_all_environment(ini_file, endpoints, settings, overcloud_token):
    logging.info("\nCleaning environment")
    
    image_id=search_image(endpoints.get("nova"), overcloud_token, settings["image_name"])
    if image_id is not None:
        delete_image(endpoints.get("image"), overcloud_token, image_id)
    
    router_id= search_router(endpoints.get("neutron"), overcloud_token, settings["router_name"])
    if router_id is not None:
        subnet1_id= search_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet1_name"])
        if subnet1_id is not None:
            try:
                remove_interface_from_router(endpoints.get("neutron"), overcloud_token, router_id, subnet1_id)
            except Exception as e:
                logging.debug("can not remove port from router")
        subnet2_id= search_subnet(endpoints.get("neutron"), overcloud_token, settings["subnet2_name"])
        if subnet2_id is not None:
            try:
                remove_interface_from_router(endpoints.get("neutron"), overcloud_token,router_id, subnet2_id)
            except Exception as e:
                logging.debug("can not remove port from router")
        delete_router(endpoints.get("neutron"), overcloud_token, router_id)
    network1_id= search_network(endpoints.get("neutron"), overcloud_token, settings["network1_name"])
    if network1_id is not None:
        delete_network(endpoints.get("neutron"), overcloud_token, network1_id)
    network2_id= search_network(endpoints.get("neutron"), overcloud_token, settings["network2_name"])
    if network2_id is not None:
        delete_network(endpoints.get("neutron"), overcloud_token, network2_id)

    keypair=search_keypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
    if keypair is not None:
        delete_kaypair(endpoints.get("nova"), overcloud_token, settings["key_name"])
        #delete keypair file
        keyfile_name= os.path.expanduser(settings["key_file"])
        try:
            logging.debug("deleting old private file")
            os.system("sudo rm "+keyfile_name)
        except OSError:
            pass
    #Changing qouta to default settings
    logging.info("setting default quota")
    project_id= find_admin_project_id(endpoints.get("keystone"), overcloud_token)
    try:
        set_quota(endpoints.get("nova"), overcloud_token, project_id, 20, 20, 51200)
    except:
        pass

def get_flavor_id(feature, nova_ep, token, flavor_name, settings, deployed_features, vcpus=None, ram=None, disks=None, mem_page_size="large" ):
    if vcpus is None:
        vcpus= settings["flavor_vcpus"]
    if ram is None:
        ram= settings["flavor_ram"]
    if disks is None:
        disks= settings["flavor_disks"]

    flavor_id= search_and_create_flavor(nova_ep, token, flavor_name, ram, vcpus, disks)
    if (feature=="numa"):
        put_extra_specs_in_flavor(nova_ep, token, flavor_id, True)
    
    if (feature=="hugepage"):
        put_extra_specs_in_flavor(nova_ep, token, flavor_id, False, mem_page_size)

    if (feature=="dpdk"):
        put_ovs_dpdk_specs_in_flavor(nova_ep, token, flavor_id)
    if (feature=="sriov" or feature=="barbican" or feature=="dvr" or feature=="mtu9000" or feature=="dpdk" or feature=="offloading" or feature=="octavia" or feature=="powerflex"):
        if("numa" in deployed_features):
            put_extra_specs_in_flavor(nova_ep, token, flavor_id, True)
    return flavor_id

def instance_ssh_test(ip, settings):
    """

    """
    try:
        remove_key= "ssh-keygen -R {}".format(ip)
        os.system(remove_key)
    except:
        pass
    retries=0
    ssh=False
    while(1):
        try:
            client= paramiko.SSHClient()
            paramiko.AutoAddPolicy()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username="centos", key_filename=os.path.expanduser(settings["key_file"]))
            ssh= True
            break
        except Exception as e:
            logging.exception(e)
            logging.debug("Waiting for server to ssh")
            time.sleep(30)
        retries=retries+1
        if(retries==settings["instance_ssh_wait_retires"]):
            break
    return ssh

def ping_test_between_instances(ip, ping_ip, settings, command=None):
    if command is None:
        command="ping  -c 3 {}".format(ping_ip)
    try:
        remove_key= "ssh-keygen -R {}".format(ip)
        os.system(remove_key)
    except:
        pass
    retries=0
    while(1):
        try:
            client= paramiko.SSHClient()
            paramiko.AutoAddPolicy()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username="centos", key_filename=os.path.expanduser(settings["key_file"]))
            logging.debug("SSH Session is established")
            logging.debug("Running command in a compute node")
            stdin, stdout, stderr = client.exec_command(command)
            logging.info("command {} successfully executed on instance")
            output= stdout.read().decode('ascii')
            error= stderr.read().decode('ascii')
            logging.info("command {} successfully executed on instance".format(command))

            if error =="" and "icmp_seq=3 Destination Host Unreachable" not in output and "ttl=" in output:
                return True, output, error
            else:
                return False, output, error
            client.close()
        except Exception as e:
            logging.exception(e)
            logging.error("error ocurred when making ssh connection and running command on remote server") 
            time.sleep(30)
        retries=retries+1
        if(retries==settings["instance_ssh_wait_retires"]):
            break

def restart_baremetal_node(baremetal_node, settings):
    #reboot node
    ssh_output= ssh_into_node(baremetal_node, "sudo reboot")    
    #wait for system to shutdown
    time.sleep(30)
    #wait for node to restart
    retries=0
    while(1):
        response = os.system("ping -c 3 " + baremetal_node)
        if response == 0:
            logging.debug ("Ping successfull!") 
            return True
        logging.debug("Waiting for server to boot")
        time.sleep(30)
        retries=retries+1
        if(retries == settings.get("bare_metal_node_wait_retires")):
            return False

def stop_service_on_node(node, service):
    command= "sudo systemctl stop {}".format(service)
    ssh_into_node(node, command)
    time.sleep(3)

def start_service_on_node(node, service):
    command= "sudo systemctl start {}".format(service)
    ssh_into_node(node, command)
    time.sleep(3)

def restart_service_on_node(node, service):
    command= "sudo systemctl restart {}".format(service)
    ssh_into_node(node, command)
    time.sleep(3)







