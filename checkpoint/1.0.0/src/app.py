import socket
import asyncio
import time
import random
import json
import requests
from walkoff_app_sdk.app_base import AppBase
from urllib3.exceptions import InsecureRequestWarning
import ast
import logging

# Configure logger once at the top of your module
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Some of the endpoints are not available for checkpoint version < R80.40 like show-policy-settings, add-objects-batch

class CheckPoint(AppBase):
    __version__ = "1.0.0"
    app_name = "Checkpoint"  # this needs to match "name" in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)

    def login(self, ip_addr:str, user:str, password:str)->str:
        """Returns session ID. to be used for authenticating requests"""

        url = f'https://{ip_addr}/web_api/login'

        request_headers = {
            'Content-Type' : 'application/json'
            }
        json_payload = {
            'user':user, 'password' : password
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=False)

        if not response.raise_for_status():
            return response.json()['sid']

        return f'Login failed, status_code->{response.status_code}'

    def logout(self, ip_addr:str, session_id:str)->str:
        """logs out user"""

        url = f'https://{ip_addr}/web_api/logout'

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        response = requests.post(url, headers=request_headers, data=json.dumps({}), verify=False)
        print(f"logout -> {response.json()['message']}")

    def publish(self, ip_addr:str, session_id:str)->"json":
        url = f'https://{ip_addr}/web_api/publish'

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        # if session_uid:
        #     json_payload = {
        #         'uid': session_uid
        #         }

        response = requests.post(url,data=json.dumps({}), headers=request_headers, verify=False)
        return response.json()

    def list_packages(self, ip_addr:str, user:str, password:str, ssl_verify)->"json":
        url = f'https://{ip_addr}/web_api/show-packages'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        response = requests.post(url, data=json.dumps({}), headers=request_headers, verify=ssl_verify)
        self.logout(ip_addr, session_id)
        return response.json()

    def install_policy(self, ip_addr:str, user:str, password:str, policy_package:str, targets:str, ssl_verify)->"json":
        #allow user to input list elments seperated by ,
        # this action has lots of optional parameters, add those when building for shuffle https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/install-policy~v1.8%20

        targets = [i.strip() for i in targets.split(',')]
        url = f'https://{ip_addr}/web_api/install-policy'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'policy-package': policy_package,
            'targets' : targets
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
        # Do we really need to publish changes after installing the policy??
        #self.publish(ip_addr,session_id)
        self.logout(ip_addr, session_id)
        return response.json()

    def add_host(self, ip_addr: str, user: str, password: str, host_list: list, ssl_verify) -> "json":
        """Create host"""
        logger.info(f"Received host_list: {host_list} (type: {type(host_list)})")

        final_response = {
            "success": [],
            "failed": []
        }

        # Convert string to list if needed
        if isinstance(host_list, str):
            try:
                host_list = ast.literal_eval(host_list)
                logger.debug("Converted host_list string to list")
            except Exception as e:
                logger.error(f"Failed to parse host_list: {e}")
                return {"success": [], "failed": [f"Invalid host_list: {host_list}"]}

        url = f'https://{ip_addr}/web_api/add-host'
        session_id = self.login(ip_addr, user, password)
        logger.info(f"Logged into {ip_addr} with session ID: {session_id}")

        ssl_verify = ssl_verify.lower() == 'true'
        logger.debug(f"SSL verification set to: {ssl_verify}")

        request_headers = {
            'Content-Type': 'application/json',
            'X-chkp-sid': session_id
        }

        for host in host_list:
            json_payload = {
                'name': host,
                'ip-address': host
            }
            logger.info(f"Sending request to add host: {host}")

            try:
                response = requests.post(
                    url,
                    data=json.dumps(json_payload),
                    headers=request_headers,
                    verify=ssl_verify
                )
                response_json = response.json()

                if response_json.get('errors') is None and response_json.get('warnings') is None:
                    logger.info(f"Host {host} added successfully")
                    final_response["success"].append(response_json)
                else:
                    logger.warning(f"Host {host} added with warnings/errors: {response_json}")
                    final_response['failed'].append(response_json)

            except Exception as e:
                logger.error(f"Request failed for host {host}: {e}")
                final_response['failed'].append({"host": host, "error": str(e)})

        self.publish(ip_addr, session_id)
        logger.debug("Published session")

        self.logout(ip_addr, session_id)
        logger.info(f"Logged out from {ip_addr}")

        return final_response

    def add_hosts_from_file(self, file_id:str, ip_addr:str, user:str, password:str, ssl_verify)->"json":
        ''' this function will read ips from text file (comma seperated)
            and make host in checkpoint for all of them '''
        # https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/add-objects-batch~v1.8%20

        # add-objects-batch requires R80.40+ ---  https://community.checkpoint.com/t5/API-CLI-Discussion/How-to-add-multiple-network-objects-easily-for-a-beginner/m-p/119214/highlight/true#M5870
        # gonna loop through all ips and make api call for each one of them.

        file_data = self.get_file(file_id)
        hosts_data = file_data['data'].decode() # reading file data and loading them into list
        host_list =[str(i).strip() for i in hosts_data.split(',')]

        url = f'https://{ip_addr}/web_api/add-host'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        for host in host_list:
            json_payload = {
                'name': host,
                'ip-address' : host
                }
            response = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
            if response.raise_for_status():
                return {"status":"failed","message":response.text}

        self.publish(ip_addr,session_id)
        self.logout(ip_addr, session_id)
        return {"message": "hosts added", "host_list": host_list }

    def show_hosts(self, ip_addr:str, user:str, password:str, ssl_verify)->"json":
        """create host"""

        url = f'https://{ip_addr}/web_api/show-hosts'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        response = requests.post(url, headers=request_headers,data=json.dumps({}), verify=ssl_verify)
        if not response.raise_for_status():
            return response.json()

        return {"status_code" :response.status_code, "message": response.text}

    def delete_host(self, ip_addr:str, user:str, password:str, host_name:str, ssl_verify:str)->"json":
        """create host"""

        url = f'https://{ip_addr}/web_api/show-hosts'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'name': host_name
            }

        response = requests.post(url, headers=request_headers,data=json.dumps(), verify=ssl_verify)
        if not response.raise_for_status():
            self.logout(ip_addr, session_id)
            return response.json()

        return {"status_code" :response.status_code, "message": response.text}

    def show_access_rule(self, ip_addr:str, user:str, password:str, name:str, layer:str, ssl_verify)->"json":
        #https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/show-access-rule~v1.8%20
        url = f'https://{ip_addr}/web_api/show-access-rule'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'name': name,
            'layer': layer
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, ssl_verify=verify)
        if not response.raise_for_status():
            self.logout(ip_addr, session_id)
            return response.json()

        return {"status_code" :response.status_code, "message": response.text()}

    def add_access_rule(self, ip_addr:str, user:str, password:str, name:str, layer:str, position:str, ssl_verify)->"json":
        """create host"""

        url = f'https://{ip_addr}/web_api/add-access-rule'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'name':name,
            'layer': host_name,
            'position' : host_ip
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
        self.logout(ip_addr, session_id)
        return response.json()

    def show_groups(self, ip_addr:str, user:str, password:str, ssl_verify:str)->"json":
        """create host"""

        url = f'https://{ip_addr}/web_api/show-groups'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        response = requests.post(url,data=json.dumps({}), headers=request_headers, verify=ssl_verify)
        self.logout(ip_addr, session_id)
        return response.json()

    def create_group(self, ip_addr:str, user:str, password:str, name:str, members:list ,ssl_verify:str)->"json":
        """create a network group"""

        url = f'https://{ip_addr}/web_api/add-groups'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        if members:
            json_payload = {
                'name': name,
                'members': members
                }
        else:
            json_payload = {
                'name': name
                }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
        self.publish(ip_addr,session_id)
        self.logout(ip_addr, session_id)
        return response.json()

    # def add_hosts_to_group(self, ip_addr:str, user:str, password:str, name:str, members:list ,ssl_verify:str)->"json":
    #     """Adds host to network group"""

    #     url = f'https://{ip_addr}/web_api/set-group'
    #     session_id = self.login(ip_addr, user, password)
    #     if isinstance(members, str):
    #         members = ast.literal_eval(members)

    #     if ssl_verify.lower() == 'true':
    #         ssl_verify = True
    #     else:
    #         ssl_verify = False

    #     request_headers = {
    #         'Content-Type' : 'application/json',
    #         'X-chkp-sid': session_id
    #         }
    #     json_payload = {
    #         'name': name,
    #         'members': members
    #         }

    #     response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
    #     self.publish(ip_addr,session_id)
    #     self.logout(ip_addr, session_id)
    #     return response.json()



    def add_hosts_to_group(self, ip_addr: str, user: str, password: str, name: str, members: list, ssl_verify: str) -> "json":
        """Adds only new hosts to a Check Point group, keeping existing ones intact."""

        logger.info("[add_hosts_to_group] Received inputs - IP: %s, User: %s, Group Name: %s, SSL Verify: %s",
                    ip_addr, user, name, ssl_verify)
        logger.info("[add_hosts_to_group] Members: %s", members)

        if isinstance(members, str):
            logger.info("[add_hosts_to_group] Converting members from string to list...")
            try:
                members = ast.literal_eval(members)
            except Exception as e:
                logger.error("[add_hosts_to_group] Failed to parse members list: %s", e)
                return {"error": "Invalid members format"}

        ssl_verify = ssl_verify.lower() == 'true'
        logger.info("[add_hosts_to_group] SSL verification set to: %s", ssl_verify)

        # Login to get session ID
        logger.info("[add_hosts_to_group] Logging in to Check Point API...")
        session_id = self.login(ip_addr, user, password)
        logger.info("[add_hosts_to_group] Session ID obtained: %s", session_id)

        request_headers = {
            'Content-Type': 'application/json',
            'X-chkp-sid': session_id
        }

        # Step 1: Get existing group members
        show_url = f'https://{ip_addr}/web_api/show-group'
        show_payload = {'name': name}
        logger.info("[add_hosts_to_group] Fetching existing members from group: %s", name)

        show_response = requests.post(show_url, data=json.dumps(show_payload), headers=request_headers, verify=ssl_verify)

        if show_response.status_code != 200:
            logger.error("[add_hosts_to_group] Failed to fetch group members: %s", show_response.text)
            self.logout(ip_addr, session_id)
            return {"error": "Failed to fetch existing members", "response": show_response.text}

        group_data = show_response.json()
        existing_members = [member.get("name") for member in group_data.get("members", [])]
        logger.info("[add_hosts_to_group] Existing members: %s", existing_members)

        # Step 2: Combine unique members
        combined_members = list(set(existing_members + members))
        logger.info("[add_hosts_to_group] Combined members to be updated: %s", combined_members)

        # Step 3: Update the group
        set_url = f'https://{ip_addr}/web_api/set-group'
        set_payload = {'name': name, 'members': combined_members}
        logger.info("[add_hosts_to_group] Sending updated members to Check Point API...")

        set_response = requests.post(set_url, data=json.dumps(set_payload), headers=request_headers, verify=ssl_verify)
        logger.info("[add_hosts_to_group] Set group response: %s", set_response.text)

        # Step 4: Publish changes and logout
        logger.info("[add_hosts_to_group] Publishing changes...")
        self.publish(ip_addr, session_id)
        logger.info("[add_hosts_to_group] Logging out...")
        self.logout(ip_addr, session_id)

        return set_response.json()




    def show_access_rulebase(self, ip_addr:str, user:str, password:str, name:str, ssl_verify:str)->"json":
        """Show access rulebase"""

        url = f'https://{ip_addr}/web_api/show-access-rulebase'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'name': name
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
        self.publish(ip_addr,session_id)
        self.logout(ip_addr, session_id)
        return response.json()

    def set_access_rule(self, ip_addr:str, user:str, password:str, name:str, layer:str, action:str, destination:str,ssl_verify:str)->"json":
        """Update existing access rule"""

        url = f'https://{ip_addr}/web_api/set-access-rule'
        session_id = self.login(ip_addr, user, password)

        layer = layer.capitalize()

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'name': name,
            'layer':layer,
            'action':action,
            'destination':destination
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
        self.publish(ip_addr,session_id)
        self.logout(ip_addr, session_id)
        return response.json()

    def list_all_tasks(self, ip_addr:str, user:str, password:str, ssl_verify)->"json":
        url = f'https://{ip_addr}/web_api/show-tasks'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }

        response = requests.post(url,data=json.dumps({}), headers=request_headers, verify=ssl_verify)
        self.logout(ip_addr, session_id)
        return response.json()

    def get_task(self, ip_addr:str, user:str, password:str, task_id:str, ssl_verify)->"json":
        url = f'https://{ip_addr}/web_api/show-task'
        session_id = self.login(ip_addr, user, password)

        if ssl_verify.lower() == 'true':
            ssl_verify = True
        else:
            ssl_verify = False

        request_headers = {
            'Content-Type' : 'application/json',
            'X-chkp-sid': session_id
            }
        json_payload = {
            'task-id': task_id
            }

        response = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=ssl_verify)
        self.logout(ip_addr, session_id)
        return response.json()


if __name__ == "__main__":
    CheckPoint.run()
