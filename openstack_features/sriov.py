import subprocess
import os

def get_sriov_enabled_interfaces():
    command= "cat ~/pilot/templates/neutron-sriov.yaml |grep physint:"
    result= os.popen(command).read()
    result= result.split('\n')
    result=result[:-1]
    i=0
    for interface in result:
        result[i]= interface.strip('      - physint:')
        i=i+1
    return result
