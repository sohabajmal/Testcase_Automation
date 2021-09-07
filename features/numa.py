from openstack_api_functions.nova import *
from functions import *
import logging
import math
import subprocess


def create_numa_instance(settings, environment, nova_ep, token, flavor_id):
    put_extra_specs_in_flavor(nova_ep, token, flavor_id, True)
    server_id= search_and_create_server(nova_ep, token, settings["server_1_name"], environment[6], settings["key_name"], flavor_id,  environment[0], environment[5], None)
    server_build_wait(nova_ep, token, [server_id])
    return server_id

def get_vcpus_of_instance(settings, environment, nova_ep, token):
    flavor_id= search_and_create_flavor(nova_ep, token, "numa_flavor", 4096, 4, 10)
    server_id= create_numa_instance(settings, environment, nova_ep, token, flavor_id)
    host= get_server_baremetal_host(nova_ep, token, server_id)
    instance_name= get_server_instance_name(nova_ep, token, server_id)
    ip="192.168.120.59"
    command= "sudo cat /etc/libvirt/qemu/{}.xml | grep vcpus".format(instance_name)
    output= ssh_into_node(ip, command)
    output=output[0]
    vcpus=output.split('>')
    delete_server(nova_ep, token, server_id)
    delete_flavor(nova_ep, token, flavor_id)
    return vcpus[1][0]

   
