from common_utils import *
from openstack_api_functions.volume import *
import logging
import os

def attach_volume(nova_ep, token, project_id, server1_id, volume_id):
    try:
        attach_volume_to_server( nova_ep, token, project_id, server1_id, volume_id, "/dev/vdd")
        time.sleep(30)
    except Exception as e:
        logging.exception(e)

def detach_volume(nova_ep, token, project_id, server1_id, volume_id):
    try:
        detath_volume_from_server( nova_ep, token, project_id, server1_id, volume_id, "/dev/vdd")
        time.sleep(30)
    except Exception as e:
        logging.exception(e)