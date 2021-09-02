import os
import json
import logging
import subprocess

def read_settings(settings_file):
    #read settings from json file
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r') as file:
                 data = file.read().replace('\n', '')
            settings= json.loads(data)
        except Exception as e:
            print("Failed to load settings file \n {}".format(e))
    else:
        print("File not found")
        print(e)
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




