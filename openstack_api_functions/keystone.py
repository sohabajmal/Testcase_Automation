def get_authentication_token(keystone_ep, username, password):
    #authenticate user with keystone
    payload= {"auth": {"identity": {"methods": ["password"],"password":
                      {"user": {"name": username, "domain": {"name": "Default"},"password": password} }},
                "scope": {"project": {"domain": {"id": "default"},"name": "admin"}}}}
    logging.debug("authenticating user")
    response= send_post_request("{}/v3/auth/tokens".format(keystone_ep), None, payload)
    logging.info("successfully authenticated") if response.ok else response.raise_for_status()
    return response.headers.get('X-Subject-Token')

def find_admin_project_id(keystone_ep, token):
    response= send_get_request("{}/v3/projects".format(keystone_ep), token)
    logging.info("successfully received project details") if response.ok else response.raise_for_status()
    return parse_json_to_search_resource(response, "projects", "name", "admin", "id")
