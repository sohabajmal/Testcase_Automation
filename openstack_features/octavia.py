from openstack_api_functions.loadbalancer import *
from openstack_api_functions.neutron import *

def loadbalancer_build_wait(loadbal_ep, token, laodbalancer_ids, maximum_retries):
    retries=0
    while True:
        for laodbalancer in laodbalancer_ids:
            status= check_loadbalancer_status(loadbal_ep, token, laodbalancer)
            logging.debug("loadbalancer status is: {}".format(status))
            if not (status == "ACTIVE" or status=="ERROR"):
                logging.debug("Waiting for loadbalancer/s to build")
                time.sleep(30)
        retries=retries+1
        if retries==maximum_retries:
            break
            
def listener_build_wait(loadbal_ep, token, listener_ids,maximum_retries):
    retries=0
    while True:
        for listener in listener_ids:
            status= check_listener_status(loadbal_ep, token, listener)
            logging.debug("listener status is: {}".format(status))
            if not (status == "ACTIVE" or status=="ERROR"):
                logging.debug("Waiting for listener/s to build")
                time.sleep(30)
        retries=retries+1
        if retries==maximum_retries:
            break
def pool_build_wait(loadbal_ep, token, pool_ids, maximum_retries):
    retries=0
    while True:
        for pool in pool_ids:
            status= check_pool_status(loadbal_ep, token, pool)
            logging.debug("pool status is: {}".format(status))
            if not (status == "ACTIVE" or status=="ERROR"):
                logging.debug("Waiting for pool/s to build")
                time.sleep(30)
        retries=retries+1
        if retries==maximum_retries:
            break
    
def install_http_packages_on_instance(instance, message, settings):
    try:
        logging.info("Installing packages on instance")
        client= paramiko.SSHClient()
        paramiko.AutoAddPolicy()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(instance, port=22, username="centos", key_filename=os.path.expanduser(settings["key_file"]))
        channel = client.get_transport().open_session()
        logging.debug("SSH Session is established")
        logging.debug("Running command in a instance node")
        channel.invoke_shell()
        channel.send("sudo -i \n")
        time.sleep(2)
        channel.send("rm /etc/resolv.conf\n")
        time.sleep(2)
        channel.send("touch /etc/resolv.conf\n")
        time.sleep(2)
        channel.send("printf  'nameserver 10.8.8.8' > /etc/resolv.conf\n")
        time.sleep(2)
        stdin, stdout, stderr = client.exec_command("sudo yum install -y epel-release")
        time.sleep(30)
        logging.debug("command {} successfully executed on instance {}".format("sudo yum install -y epel-release", instance))
        logging.debug("stderr is: {}".format(stderr.read().decode('ascii')))
        stdin, stdout, stderr = client.exec_command("sudo yum install -y nginx")
        time.sleep(30)
        logging.debug("command {} successfully executed on instance {}".format("sudo yum install -y nginx", instance))
        logging.debug("stderr is: {}".format(stderr.read().decode('ascii')))
        stdin, stdout, stderr = client.exec_command("sudo systemctl start nginx")
        time.sleep(30)
        logging.debug("command {} successfully executed on instance {}".format("sudo systemctl start nginx", instance))
        logging.debug("stderr is: {}".format(stderr.read().decode('ascii')))
        channel.send("cd /usr/share/nginx/html/\n")
        channel.send("rm index.html\n")
        time.sleep(2)
        channel.send("touch index.html\n")
        time.sleep(2)
        channel.send("printf  '{}'> index.html\n".format(message))
        time.sleep(2)
        logging.debug("command {} successfully executed on instance {}".format("sudo yum install nc.x86_64", instance))
        logging.debug("stderr is: {}".format(stderr.read().decode('ascii')))
        time.sleep(30)
        logging.debug("command {} successfully executed on instance {}".format("nc -lp 23456", instance))
        logging.debug("stderr is: {}".format(stderr.read().decode('ascii')))
        time.sleep(30)
 
    except Exception as e:
        logging.exception(e)
        logging.error("error ocurred when making ssh connection and running command on remote server") 
    finally:
        client.close()
        logging.debug("Connection from client has been closed") 

def roundrobin_traffic_test(loadbalancer_floating_ip, traffic_type):
    if traffic_type== "HTTPS":
        curl_command= "curl {}".format(loadbalancer_floating_ip)
    if traffic_type== "TCP":
        curl_command= "curl {}:{}".format(loadbalancer_floating_ip, 23456)
    output=[]
    for i in range(0, 6):    
        result= os.popen(curl_command).read()
        result= result.strip()
        output.append(result)    
    logging.debug("output is:")
    logging.debug(output) 
    print(output)
    if(output[0]!= output[1] and output[2]!= output[3] and output[4]!= output[5] and output[0]== output[3] and output[1]==output[4] and output[2]==output[5]):
        return True
    else:
         return False

def create_lb(loadbalancer_ep, neutron_ep, overcloud_token, settings, environment, traffic_type, port, algorithm, session=None):
    loadbalancer={}
    #create load balancer
    loadbalancer_id= search_and_create_loadbalancer(loadbalancer_ep, overcloud_token, settings.get("loadbalancer1_name"), environment.get("subnet1_id"))
    loadbalancer["lb_id"]=loadbalancer_id
    #wait for loadbalancer creation
    loadbalancer_build_wait(loadbalancer_ep, overcloud_token, [loadbalancer_id], settings.get("loadbalancer_build_retires"))
    #get state of loadbalancer
    loadbalancer_state= check_loadbalancer_status(loadbalancer_ep, overcloud_token, loadbalancer_id)
    loadbalancer["lb_status"]=loadbalancer_state
    if loadbalancer_state== "ACTIVE":
        #create listener
        listener_id= search_and_create_listener(loadbalancer_ep, overcloud_token, settings.get("listener1_name"), loadbalancer_id, traffic_type, port)
        loadbalancer["listener_id"]=listener_id
        #wait for listener creation
        listener_build_wait(loadbalancer_ep, overcloud_token, [listener_id], settings.get("loadbalancer_listener_creation_retires"))
        #get listener  state
        listener_state= check_listener_status(loadbalancer_ep, overcloud_token, listener_id)
        loadbalancer["listener_status"]=listener_state
    if loadbalancer_state== "ACTIVE" and listener_state =="ACTIVE":
        #create pool
        pool_id= search_and_create_pool(loadbalancer_ep, overcloud_token, settings.get("pool1_name"), listener_id, loadbalancer_id, traffic_type, algorithm, session)
        loadbalancer["pool_id"]=pool_id
        #wait for pool creation
        pool_build_wait(loadbalancer_ep, overcloud_token, [pool_id], settings.get("loadbalancer_pool_creation_retires"))
        #get pool status
        pool_state= check_pool_status(loadbalancer_ep, overcloud_token, pool_id)
        loadbalancer["pool_status"]=pool_state
    
    if loadbalancer_state== "ACTIVE":
        #Assign floating ip to loadbalancer
        lb_vipport= check_loadbalancer_vipport(loadbalancer_ep, overcloud_token, loadbalancer_id)
        #logging.info("vip port: {}".format(lb_vipport))
        public_network_id= search_network(neutron_ep, overcloud_token, settings["external_network_name"])
        lb_ip_id, lb_ip= create_loadbalancer_floatingip(neutron_ep, overcloud_token, public_network_id )
        #logging.info("load balancer ip is: {}".format(lb_ip))
        assign_lb_floatingip(neutron_ep, overcloud_token, lb_vipport, lb_ip_id )
        loadbalancer["floating_ip"]=lb_ip
        loadbalancer["floating_ip_id"]=lb_ip_id
    return loadbalancer

def add_members_to_pool(loadbalancer_ep, overcloud_token, pool_id, subnet_id, port, traffic_type, instances):
    for instance in instances:
        add_instance_to_pool(loadbalancer_ep, overcloud_token, pool_id, instance.get("ip"), subnet_id, port)
    #create health monitor
    #create_health_monitor_pool(loadbalancer_ep, overcloud_token, pool_id, traffic_type)




