import os
import json
import logging
import subprocess
import paramiko

def read_settings(settings_file):
    #read settings from json file
    if os.path.exists(settings_file):
        try:
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
        parameters={"ip": ip, "username": username, "password": password}
        return parameters
        

    else:
        logging.error("File {} not found".format(rc_file), stack_info=True )
        raise FileNotFoundError ("File {} not found".format(rc_file))

def run_linux_command(command):
    command= subprocess.run([command], shell=True, stdout=subprocess.PIPE)
    output= command.stdout.decode('ascii')
    if not output:
        logging.error("Error in executing command {}".format(command),  stack_info=True)
        raise ValueError("Error in executing command {}".format(command))
    return output
def create_services_endpoints(undercloud_ip, overcloud_ip):
    endpoints={}
    endpoints["keystone"]= "{}:5000".format(overcloud_ip)
    endpoints["neutron"]= "{}:9696".format(overcloud_ip)
    endpoints["cinder"]= "{}:8776".format(overcloud_ip)
    endpoints["nova"]= "{}:8774".format(overcloud_ip)
    endpoints["image"]= "{}:9292".format(overcloud_ip) 
    endpoints["loadbal"]= "{}:9876".format(overcloud_ip) 
    endpoints["barbican"]="{}:9311".format(overcloud_ip) 
    endpoints["undercloud_keystone"]= "{}:5000".format(undercloud_ip)
    endpoints["undercloud_nova"]= "{}:8774".format(undercloud_ip)
    return endpoints
#def create_ssh_pem_file():
def read_ini_settings(sah_ip, ini_file):
    settings_dic={}
    command= "grep -e mtu_size_global_default= -e nic_env_file= -e hpg_enable= -e hpg_size= -e numa_enable= -e ovs_dpdk_enable= -e sriov_enable= -e smart_nic= -e dvr_enable= -e barbican_enable= -e octavia_enable= -e overcloud_name= {}".format(ini_file)

    settings= ssh_into_node(sah_ip, command, "root")
    
    #Parse string for new line
    settings= settings[0].split("\n")
    #parse mtu size
    mtu_size=settings[0].split("=")
    settings_dic['mtu_size']=mtu_size[1]
    #NFV Ports
    total_nfv_ports=settings[1].split("=")
    ports= [int(s) for s in total_nfv_ports[1].split() if s.isdigit()]

    settings_dic['total_nfv_ports']=s

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
    #smart_nic
    dvr_enable=settings[8].split("=")
    settings_dic['dvr_enabled']=dvr_enable[1]
    #smart_nic
    barbican_enable=settings[9].split("=")
    settings_dic['barbican_enabled']=barbican_enable[1]
    #smart_nic
    octavia_enable=settings[10].split("=")
    settings_dic['octavia_enabled']=octavia_enable[1]
    #overcloud name
    overcloud_name=settings[11].split("=")
    settings_dic['overcloud_name']=overcloud_name[1]
    print(settings_dic)
    return settings_dic


    

def ssh_into_node(host_ip, command, user_name="heat-admin"):
    try:
        logging.info("Trying to connect with node {}".format(host_ip))
        # ins_id = conn.get_server(server_name).id
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if (user_name == "root"):
            ssh_session = ssh_client.connect(host_ip, 22, "root", "Dell0SS!")
        else:
            ssh_session = ssh_client.connect(host_ip, username=user_name, key_filename=os.path.expanduser("~/.ssh/id_rsa")) 
        logging.info("SSH Session is established")
        logging.info("Running command in a compute node")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        logging.info("command {} successfully executed on node {}".format(command, host_ip))
        output= stdout.read().decode('ascii')
        error= stderr.read().decode('ascii')
        return output, error
    except Exception as e:
        logging.exception(e)
        logging.error("error ocurred when making ssh connection and running command on remote server") 
    finally:
        ssh_client.close()
        logging.info("Connection from client has been closed") 
    


