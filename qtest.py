import requests
import json
import os
import time
import logging



token= "Bearer b5294742-4428-4ba1-bc0f-011c255ad759"
project_id= "119906"
def send_post_request(api_url, payload, token):
    #send post request
    try:
        #'OpenStack-API-Version': 'compute 2.74',
        if token== None:
            return requests.post(api_url, headers= {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic cXRlc3QtYXBpOg=='}, data=payload)
        else:
            return requests.post(api_url, headers= {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'Authorization': token}, data=payload)
    except Exception as e:
       print("request processing failure")
       print(e)
def send_get_request(api_url, payload, token):
    #send post request
    try:
        if token== None:
            return requests.post(api_url, headers= {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic cXRlc3QtYXBpOg=='}, data=payload)
        else:
            return requests.get(api_url, headers= {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'Authorization': token}, data=payload)
    except Exception as e:
       print("request processing failure")
       print(e)


#Authenticate with qtest
'''	   
payload= {
            "grant_type": "password",
            "username": "sohaib.ajmal@xflowresearch.com",
            "password": "Pak12345",
        }
		
print("payload is")
print(payload)
		
print("Qtest authenticating user")
response= send_post_request("https://sohaibajmal.qtestnet.com/oauth/token", payload)
print("successfully authenticated") if response.ok else response.raise_for_status()
print(response.text)
'''

#Get project details
'''
 curl -X GET "https://sohaibajmal.qtestnet.com/api/v3/projects" -H "accept: application/json" -H "content-type: application/x-www-form-urlencoded" -H "Authorization: Bearer b5294742-4428-4ba1-bc0f-011c255ad759" -d "expand=userprofile&assigned=true"
'''
'''
payload= {
            "expand": "userprofile",
            "assigned": "true",
            "page": "1",
            "pageSize": "100"
        }
print("Qtest Getting Projects")
response= send_get_request("https://sohaibajmal.qtestnet.com/api/v3/projects", payload, token)
#print("successfully get project list") if response.ok else response.raise_for_status()
print(response.text)

response= response.json()
#search for key
for resource in (response):
    if(resource["name"]=="qConnect - Sample Project"):
        print("!!!!!!!!!!!!!!!!")
        print(resource["id"])
        print("****************")
'''
#Get Testcases
'''
payload= {
            "projectId ": project_id,
            "page": "1",
            "size": "2",
            "expandSteps": "false"   
        }
print("Qtest Getting Testcases")
response= send_get_request("https://sohaibajmal.qtestnet.com/api/v3/projects/{}/test-cases".format(project_id), payload, token)
#print("successfully get project list") if response.ok else response.raise_for_status()
print(response.text)
response= response.json()
#search for key
count=0
for resource in (response):
    count=count+1
    print(resource["id"])
    print("-----")
print(count)
'''

#Get Single Testcases
payload= {
            "projectId ": project_id,
            "testCaseIdOrPid": "50095683",
        }
print("Qtest Getting Testcase")
response= send_get_request("https://sohaibajmal.qtestnet.com/api/v3/projects/{}/test-cases/50095683".format(project_id), payload, token)
#print("successfully get project list") if response.ok else response.raise_for_status()
print(response.text)
response= response.json()
#search for key

#Get Release
'''
 curl -X GET "https://sohaibajmal.qtestnet.com/api/v3/projects/119906/releases" -H "accept: application/json" -H "content-type: application/x-www-form-urlencoded" -H "Authorization: Bearer b5294742-4428-4ba1-bc0f-011c255ad759" -d "projectId=119906"

'''
release3_id= 565984
