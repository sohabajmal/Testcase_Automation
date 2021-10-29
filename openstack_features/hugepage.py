from openstack_api_functions.nova import *
from common_utils import *
import logging
import math
import subprocess
import pytest

def get_possible_hugepage_instances(compute_ip, flavor_ram):
    output= ssh_into_node(compute_ip, " grep Huge /proc/meminfo")
    output=output[0]
    hugepg_free= parse_hugepage_size(output, "HugePages_Free:")
    instance_possible= math.floor(int(hugepg_free)/flavor_ram)
    return instance_possible

def parse_hugepage_size(huge_page_info, parameter):
    huge_page_info= huge_page_info.split('\n')
    for property in huge_page_info:
        line= property.split()
        if line[0] == parameter:
           return line[1]
           
def get_available_ram_of_node(compute_ip):        
    ssh_output= ssh_into_node(compute_ip, "grep MemTotal: /proc/meminfo")
    ssh_output=ssh_output[0]
    ssh_output=ssh_output.split("       ")
    ssh_output=ssh_output[1].split(" ")
    available_ram= int(ssh_output[0])/(1024*1024)
    return available_ram