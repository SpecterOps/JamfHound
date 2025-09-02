import json
import os
from lib.edges import compute_edges
from lib.models import (
    Node, 
    Edge
)

# Checks a supplied Azure JSON file for user nodes that match jamf_Account nodes by email or displayname
def checkAzureUsers(azureJSON, jamfJSON="JAMFcollection.json"):
    checkProcessor = Preprocessor("placeholder.com")
    checkProcessor.nodes.pop()
    with open(azureJSON, 'r') as accts_source:
        azureData = json.load(accts_source)
        accts_source.close()
    with open(jamfJSON, 'r') as accts_source:
        jamfData = json.load(accts_source)
        accts_source.close() 
    for x in azureData.get("data"):
        if x.get('kind') == "AZUser":
            if x.get("data").get("mail"): # Check emails first
                for y in jamfData.get("graph").get("nodes"):
                    if "jamf_Account" in y.get("kinds") or "jamf_DisabledAccount" in y.get("kinds") or "jamf_ComputerUser" in y.get("kinds"):
                        if y.get("properties").get("email") == x.get("data").get("mail"):
                            matchEdge = Edge("AZMatchedEmail")
                            matchEdge.start["value"] = y.get("id")
                            matchEdge.end["value"] = x.get("data").get("id")
                            matchEdge.properties["description"] = "The Jamf principal email attribute matched the Azure account email."
                            checkProcessor.edges.append(matchEdge)
           #TODO: Create elif for displayname
    print(checkProcessor.write_out_collection(None, "AzureMerge.json"))

# Primary class for preparing data for ingest
class Preprocessor():
    def __init__(self, jtenant):
        self.admins = []
        self.computers = []
        self.computerusers = []
        self.accounts = []
        self.apiclients = []
        self.sites = []
        self.scripts = []
        self.policies = {}
        self.groups = []
        self.tenant = jtenant
        self.tenantID = ""
        self.rolesData = ""
        self.edges = []
        self.nodes = []
        self.graph = {}
        self.json_template_string = '''
{
  "graph": {
    "nodes": [],    
    "edges": []    
  },     
  "metadata": {
    "ingest_version": "v1",
    "collector": {
      "name": "Custom Collector",
      "version": "beta",
      "properties": {   
        "collection_methods": [
          "Custom Method"
        ],
        "windows_server_version": "n/a"
      }
    }  
  }    
}
'''
        self.prepare_graph() 

    # Converts a supplied accounts JSON file to a dictionary object
    def file_JSON_load(self, accounts_file):
        # Validate accounts file
        if not os.path.exists(accounts_file) or not os.path.isfile(accounts_file):
            raise Exception(f"X - {accounts_file} is not valid - X")
        # Import JSON
        with open(accounts_file, 'r') as accts_source:
            accts_data = json.load(accts_source)
            accts_source.close()
        return accts_data

    def prepare_graph(self):
        self.graph = json.loads(self.json_template_string)
        tenant = Node("Tenant")
        # tenant.id = "T-1"
        https_string = "https://"
        http_string = "http://"
        if self.tenant.startswith(https_string):
             tenant.properties["name"] = self.tenant[8:]
        elif self.tenant.startswith(http_string):
             tenant.properties["name"] = self.tenant[7:]
        else:
             tenant.properties["name"] = self.tenant

        if ":8443" in self.tenant:
            tenant.properties["type"] = "on-premesis"
            temp_name = str(tenant.properties.get("name"))
            new_name = temp_name.split(':')
            tenant.properties["name"] = new_name[0]
        else:
            tenant.properties["type"] = "cloud-hosted"
        tenant.id = str(tenant.properties.get("name"))
        tenant.properties["objectid"] = tenant.properties.get("name")
        tenant.properties["displayname"] = tenant.properties.get("name")
        self.tenantID = tenant.id
        self.nodes.append(tenant)    

    # Convert nodes to JSON
    def convert_nodes(self, write_only):
        for z in self.nodes:
            if write_only == False:
                z.kind = "jamf_" + z.kind
            if z.id != self.tenantID and write_only == False:
                z.id = f"{self.tenantID}-{z.id}" # Prepend tenant ID to make child nodes unique
                z.properties["objectid"] = z.id # Make sure objectid matches so ingest can complete
            new_node = {
            "id": z.id,
            "kinds": [z.kind],
            "properties": z.properties  
            }
            self.graph["graph"]["nodes"].append(new_node)

    # Convert edges to JSON
    def convert_edges(self, write_only):
        for r in self.edges:
            if write_only == False:
                r.kind = "jamf_" + r.kind
            new_edge = {
            "kind" : r.kind,
            "start": r.start,
            "end": r.end,
            "properties": r.properties
            }
            self.graph["graph"]["edges"].append(new_edge)

    # Write Out JSON
    def write_out_collection(self, jservice, outfile="JAMFcollection.json", write_only = False):
        self.convert_nodes(write_only)
        #self.compute_edges()
        if jservice is not None: # Our use case for edge processing, otherwise just node processing
            compute_edges(self, jservice)
        self.convert_edges(write_only)
        with open (outfile, "w") as f:
            json.dump(self.graph, f, indent=2)
        return f"+ - JSON data for ingest written to {outfile} - +"

    # Node Actions
    def process_nodes(self):
        self.process_account_nodes("accounts.json")
        self.process_group_nodes("groups.json")
        self.process_computer_nodes("computers.json")
        self.process_site_nodes("sites.json")
        self.process_api_client_nodes("apiclients.json", "apiroles.json")
        try:
            self.policies = (self.file_JSON_load("policies.json")).get("data")
        except:
            pass # TODO: Error handling, if policies.json doesn't exist we just won't have update edges for now
        try:
            self.scripts = (self.file_JSON_load("scripts.json")).get("scripts")
        except:
            pass # TODO: Error Handle

    #Add Account Nodes TODO: WILL NEED TO EVENTUALLY ACCOUNT FOR ACCOUNTS ASSIGNED TO MULTIPLE SITES
    def process_account_nodes(self, accounts_file):
        try:
            accts_data = self.file_JSON_load(accounts_file)
        except Exception as e:
            print(f"Failed to process accounts: {e}")
            return
        #Stub for accessing individual account data properties
        for x in accts_data["data"]:
            newaccount = Node("Account")
            newaccount.id = f"A{x["Properties"]["id"]}"
            newaccount.properties["displayname"] = x["Properties"]["full_name"]
            newaccount.properties["privilegeSet"] = x["Properties"]["privilege_set"]
            newaccount.properties["objectid"] = newaccount.id
            newaccount.properties["name"] = x["Properties"]["name"]
            newaccount.properties["email"] = x["Properties"]["email"]
            try:
                newaccount.properties["siteID"] = x["Properties"]["site"]["id"]
            except:
                newaccount.properties["siteID"] = -1
            newaccount.properties["accessLevel"] = x["Properties"]["access_level"]
            newaccount.properties["enabled"] = x["Properties"]["enabled"]
            # Check if we have an Administrator/Tier-Zero Account
            if newaccount.properties.get("accessLevel") == "Full Access" and newaccount.properties.get("privilegeSet") == "Administrator":
                newaccount.properties["Tier"] = 0 # This could be Tier-Zero or another node property
            newaccount.properties["localAccount"] = x["Properties"]["directory_user"] == False
            if newaccount.properties.get("accessLevel") == "Group Access":
                #ACCOUNT GROUPS ARE UNRELIABLE, ONLY RETURNS MOST RECENT GROUP ACCOUNT WAS ASSIGNED TO
                newaccount.properties["privilegesJSSObjects"] = "Group Assigned"
                newaccount.properties["privilegesJSSActions"] = "Group Assigned"
                newaccount.properties["privilegesJSSOSettings"] = "Group Assigned"
            else:
                try:
                    newaccount.properties["privilegesJSSObjects"] = x["Properties"]["privileges"]["jss_objects"]
                except:
                    pass # TODO: Log Errors
                try:
                    newaccount.properties["privilegesJSSActions"] = x["Properties"]["privileges"]["jss_actions"]
                except Exception as e:
                    pass #TODO: Log Errors
                try:
                    newaccount.properties["privilegesJSSSettings"] = x["Properties"]["privileges"]["jss_settings"]
                except Exception as f:
                    pass #TODO: Log Errors
                newaccount.properties["Groups"] = -5
            if newaccount.properties.get("enabled") == "Disabled":
                newaccount.kind = "DisabledAccount"
            self.accounts.append(newaccount)
            self.nodes.append(newaccount) 

    #Add API Client Nodes 
    def process_api_client_nodes(self, accounts_file, roles_file):
        try:
            accts_data = self.file_JSON_load(accounts_file)
            self.rolesData = self.file_JSON_load(roles_file)
        except Exception as e:
            print(f"Failed to process API Clients and Roles: {e}")
            return
        for v in accts_data["results"]:
            newclient = Node("ApiClient")
            newclient.id = f"AC{v["id"]}"
            newclient.properties = v
            newclient.properties.pop("id")
            newclient.properties["privileges"] = []
            newclient.properties["Tier"] = 1
            for m in newclient.properties.get("authorizationScopes"):
                for n in self.rolesData.get("results"):
                    if str(m) == n.get("displayName"):
                        for o in n.get("privileges"):
                            #Check if the preceding privilege string ended with a ,
                             newclient.properties["privileges"].append(o)
            newclient.properties["name"] = newclient.properties.get("displayName")
            if not newclient.properties.get("enabled"):
                newclient.kind = "DisabledApiClient"
            self.apiclients.append(newclient)
            self.nodes.append(newclient)
           

    #Add Group Nodes TODO: WILL NEED TO EVENTUALLY ACCOUNT FOR GROUPS ASSIGNED TO MULTIPLE SITES
    def process_group_nodes(self, accounts_file):
        try:
            accts_data = self.file_JSON_load(accounts_file)
        except Exception as e:
            print(f"Failed to process groups: {e}")
            return
        #Stub for accessing individual account data properties
        for x in accts_data["Groups"]:
            newaccount = Node("Group")
            newaccount.id = f"G{x["group"]["id"]}"
            newaccount.properties["displayname"] = x["group"]["name"]
            newaccount.properties["privilegeSet"] = x["group"]["privilege_set"]
            newaccount.properties["objectid"] = newaccount.id
            newaccount.properties["name"] = x["group"]["name"]
            try:
                newaccount.properties["siteID"] = x["group"]["site"]["id"]
            except:
                newaccount.properties["siteID"] = -1
            newaccount.properties["accessLevel"] = x["group"]["access_level"]
            # Check if we have an Administrator/Tier-Zero Group
            if newaccount.properties.get("accessLevel") == "Full Access" and newaccount.properties.get("privilegeSet") == "Administrator":
                newaccount.properties["Tier"] = 0 # This could be Tier-Zero or another node property
            try:
                newaccount.properties["privilegesJSSObjects"] = x["group"]["privileges"]["jss_objects"]
            except:
                pass # TODO: Log Errors
            try:
                newaccount.properties["privilegesJSSActions"] = x["group"]["privileges"]["jss_actions"]
            except Exception as e:
                pass #TODO: Log Errors
            try:
                newaccount.properties["privilegesJSSSettings"] = x["group"]["privileges"]["jss_settings"]
            except Exception as f:
                pass #TODO: Log Errors
            newaccount.properties["members"] = str(x["group"]["members"])
            self.groups.append(newaccount)
            self.nodes.append(newaccount)

    #Add Assigned User Nodes
    #TODO: This could probably eventually expand to use local user account info if assigned info is empty
    def process_assigned_user_nodes(self, computer_node):
        if len(computer_node.properties.get("username")) > 1 or len(computer_node.properties.get("email_address")) > 1:
            newuser = Node("ComputerUser")
            if len(computer_node.properties.get("email_address")) > 1:           
                newuser.id = f"U{computer_node.properties.get("email_address")}"
                if len(computer_node.properties.get("username")) > 1:
                    newuser.properties["displayname"] = computer_node.properties.get("username")
                else:
                    newuser.properties["displayname"] = computer_node.properties.get("email_address")
                newuser.properties["name"] = computer_node.properties.get("email_address")
                newuser.properties["email"] = computer_node.properties.get("email_address")
            else: #TODO: Might need to error handle this.
                newuser.id = f"U{computer_node.properties.get("username")}"
                newuser.properties["displayname"] = computer_node.properties.get("username")
                newuser.properties["name"] = computer_node.properties.get("username")
                newuser.properties["email"] = ""
            newuser.properties["objectid"] = newuser.id
            newuser.properties["computer"] = computer_node.id
            self.nodes.append(newuser)
            self.computerusers.append(newuser)
    
    #Add Computer Nodes
    def process_computer_nodes(self, computers_file):
        try:
            cmpts_data = self.file_JSON_load(computers_file)
        except Exception as e:
            print(f"Failed to process computers: {e}")
            return
        for c in cmpts_data["data"]:
            newcomputer = Node("Computer")
            newcomputer.id = f"C{c["Properties"]["id"]}"
            newcomputer.properties["displayname"] = c["Properties"]["name"]
            newcomputer.properties["name"] = c["Properties"]["name"]
            newcomputer.properties["objectid"] = newcomputer.id
            #Replace sub dictionaries
            newcomputer.properties["managed"] = c["Properties"]["remote_management"]["managed"]
            newcomputer.properties["make"] = c["Properties"]["make"]
            newcomputer.properties["mdm_capable"] = c["Properties"]["mdm_capable"]
            newcomputer.properties["model"] = c["Properties"]["model"]
            try:
                newcomputer.properties["enrolled_via_dep"] = c["Properties"]["management_status"]["enrolled_via_dep"]
            except:
                newcomputer.properties["enrolled_via_dep"] = ""
            try:
                newcomputer.properties["user_approved_enrollment"] = c["Properties"]["management_status"]["user_approved_enrollment"]
            except:
                newcomputer.properties["user_approved_enrollment"] = ""
            try:
                newcomputer.properties["user_approved_mdm"] = c["Properties"]["management_status"]["user_approved_mdm"]
            except:
                newcomputer.properties["user_approved_mdm"] = ""
            try:
                newcomputer.properties["device_aad_infos"] = str(c["Properties"]["device_aad_infos"])
            except Exception as err:
                newcomputer.properties["device_aad_infos"] = ""
            newcomputer.properties["siteID"] = c["Properties"]["site"]["id"]
            newcomputer.properties["sitename"] = c["Properties"]["site"]["name"]
            #Cast arrays to strings
            newcomputer.properties["username"] = c["Properties"]["username"]
            newcomputer.properties["email_address"] = c["Properties"]["email_address"]
            newcomputer.properties["phone_number"] = c["Properties"]["phone_number"]
            newcomputer.properties["position"] = c["Properties"]["position"]
            newcomputer.properties["realname"] = c["Properties"]["realname"]
            newcomputer.properties["real_name"] = c["Properties"]["real_name"]
            newcomputer.properties["os_name"] = c["Properties"]["os_name"]
            newcomputer.properties["os_version"] = c["Properties"]["os_version"]
            newcomputer.properties["os_build"] = c["Properties"]["os_build"]
            newcomputer.properties["processor_type"] = c["Properties"]["processor_type"]
            newcomputer.properties["recovery_lock_enabled"] = c["Properties"]["recovery_lock_enabled"]
            newcomputer.properties["institutional_recovery_key"] = c["Properties"]["institutional_recovery_key"]
            newcomputer.properties["serial_number"] = c["Properties"]["serial_number"]
            newcomputer.properties["udid"] = c["Properties"]["udid"]
            newcomputer.properties["uuid"] = c["Properties"]["uuid"]
            newcomputer.properties["supervised"] = c["Properties"]["supervised"]
            newcomputer.properties["sip_status"] = c["Properties"]["sip_status"]
            newcomputer.properties["xprotect_version"] = c["Properties"]["xprotect_version"]
            newcomputer.properties["active_directory_status"] = str(c["Properties"]["active_directory_status"])
            newcomputer.properties["computer_group_memberships"] = c["Properties"]["computer_group_memberships"]
            newcomputer.properties["firewall_enabled"] = c["Properties"]["firewall_enabled"]
            newcomputer.properties["gatekeeper_status"] = c["Properties"]["gatekeeper_status"]
            newcomputer.properties["initial_entry_date_utc"] = c["Properties"]["initial_entry_date_utc"]
            newcomputer.properties["ip_address"] = c["Properties"]["ip_address"]
            newcomputer.properties["last_reported_ip_v4"] = c["Properties"]["last_reported_ip_v4"]
            newcomputer.properties["last_reported_ip_v6"] = c["Properties"]["last_reported_ip_v6"]
            newcomputer.properties["is_apple_silicon"] = c["Properties"]["is_apple_silicon"]
            newcomputer.properties["last_contact_time_utc"] = c["Properties"]["last_contact_time_utc"]
            newcomputer.properties["jamf_version"] = c["Properties"]["jamf_version"]
            newcomputer.properties["filevault2_users"] = str(c["Properties"]["filevault2_users"])
            newcomputer.properties["local_accounts"] = str(c["Properties"]["local_accounts"])
            newcomputer.properties["user_inventories"] = str(c["Properties"]["user_inventories"])
            newcomputer.properties["mdm_capable_users"] = str(c["Properties"]["mdm_capable_users"])
            self.computers.append(newcomputer)
            self.nodes.append(newcomputer)
            self.process_assigned_user_nodes(newcomputer)

    #Add Sites Nodes
    #{'sites': [{'id': 1, 'name': 'Site1'}]}
    def process_site_nodes(self, sites_file):
        try:
            sites_data = self.file_JSON_load(sites_file)
        except Exception as e:
            print(f"Failed to process sites: {e}")
            return
        for s in sites_data["sites"]:
            newsite = Node("Site")
            newsite.id = f"S{s['id']}"
            newsite.properties["name"] = s['name']
            newsite.properties["objectid"] = newsite.id
            newsite.properties["displayname"] = newsite.properties.get("name")
            newsite.properties["siteID"] = s['id']
            self.sites.append(newsite)
            self.nodes.append(newsite)

    # Method to ensure edges from nodes are set traversable so long as accounts are enabled
    def check_traversable(self, edge, node):
# TODO: Check if the account is a member of a group but not using group permissions, this would make this edge non-traversable. Unlikely to happen
#        if node.kind != "jamf_DisabledAccount" and node.kind != "jamf_DisabledApiClient":
        edge.properties["traversable"] = True
        return edge
    
    def is_Jamf_Account_Or_Group(self, node):
        if node.kind == "jamf_Account" or node.kind == "jamf_DisabledAccount" or node.kind == "jamf_Group":
            return True
        else:
            return False
        
    def is_Jamf_API_Client(self, node):
        if node.kind == "jamf_ApiClient" or node.kind == "jamf_DisabledApiClient":
            return True
        else:
            return False