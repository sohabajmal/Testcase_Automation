from common_utils import *
import paramiko
import logging
import os


def get_ovs_dpdk_ports(baremetal_nodes, expected_ports):
    command= "sudo cat /var/lib/os-net-config/dpdk_mapping.yaml"
    print(expected_ports)
    try:
        for node in baremetal_nodes:
            ports= ssh_into_node(node, command)
            ports=ports[0]
            total_ports= ports.count("driver:")
            if total_ports != expected_ports:
                logging.debug("Total DPDK ports are: {}".format(total_ports))
                return False
        else: 
            return True
    except Exception as e:
        logging.exception(e)
        return False

def verify_status_of_dpdk_ports(baremetal_nodes, expected_ports):
    command= "sudo ovs-ofctl show br-tenant"           
    try:
        for node in baremetal_nodes:
            ports= ssh_into_node(node, command)
            ports=ports[0]
            total_ports= ports.count("dpdk")
            if total_ports != expected_ports:
                logging.debug("Total DPDK ports are: {}".format(total_ports))
                return False
        else: 
            return True
    except Exception as e:
        logging.exception(e)
        return False
def verify_status_of_ovs_dpdk_service(baremetal_nodes):
    command= "timeout 2 systemctl status ovs-vswitchd.service"           
    try:
        for node in baremetal_nodes:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_session = ssh_client.connect(node, username="heat-admin", key_filename=os.path.expanduser("~/.ssh/id_rsa"))
            logging.debug("Running command in a compute node")
            #run command
            stdin, stdout, stderr = ssh_client.exec_command(command)
            logging.debug("command {} successfully executed on node {}".format(command, node))
            #decode output
            status= stdout.read().decode('utf-8')
            error= stderr.read().decode('utf-8')
            print(status)
            if "Active: active (running)" not in status:
                logging.debug("OVS-DPDK Service Status is: {}".format(status))
                return False
        else: 
            return True
    except Exception as e:
        logging.exception(e)
        return False
    

def verify_status_of_ovs_service(baremetal_nodes):
    command= "service ovs-vswitchd status |grep 'active (running)'"           
    try:
        for node in baremetal_nodes:
            ovs_service_status= ssh_into_node(node, command)
            ovs_service_status=ovs_service_status[0]            
            if "active (running)" not in ovs_service_status:
                logging.debug("OVS service status is: {}".format(ovs_service_status))
                return False
        else: 
            return True
    except Exception as e:
        logging.exception(e)
        return False

def verify_ovs_dpdk_bridges(baremetal_nodes):
    command1= "sudo ovs-vsctl show | grep Bridge"
    command2= "sudo ovs-vsctl show |grep 'is_connected: true'" 
    try:
        for node in baremetal_nodes:
            tota_bridges= ssh_into_node(node, command1)
            tota_bridges= tota_bridges[0]
            tota_bridges= tota_bridges.split("\n")
            total_bridges= len(tota_bridges)           

            bridges_up= ssh_into_node(node, command2)
            bridges_up= bridges_up[0]
            bridges_up= bridges_up.split("\n")
            bridges_up= len(bridges_up)  
            if(bridges_up <total_bridges):
                return False
        else:
            return True
    except Exception as e:
        logging.exception(e)
        return False