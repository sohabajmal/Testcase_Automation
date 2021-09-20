from openstack_api_functions.nova import *
from functions import *
import logging
import math
import subprocess
import pytest



def get_vcpus_of_instance(nova_ep, token, baremetal_nodes, instance):
    host= get_server_baremetal_host(nova_ep, token, instance.get("id"))
    instance_xml_name= get_server_instance_name(nova_ep, token, instance.get("id"))
    host=host.split(".")
    compoute_node_ip = [val for key, val in baremetal_nodes.items() if host[0] in key]
    command= "sudo cat /etc/libvirt/qemu/{}.xml | grep vcpus".format(instance_xml_name)
    output= ssh_into_node(compoute_node_ip[0], command)
    output=output[0]
    vcpus=output.split('>')
    return vcpus[1][0]
def get_possible_instances(compute_ip, vcpus):
    cpu_cores= ssh_into_node(compute_ip, "lscpu | grep  'CPU(s):' ")
    cpu_cores= cpu_cores[0]
    cpu_cores= cpu_cores.split("\n")
    cpu_cores= cpu_cores[0].split(":")
    cpu_cores= cpu_cores[1].strip()
    instance_possible=  math.floor(int(cpu_cores)/vcpus)
    return instance_possible









