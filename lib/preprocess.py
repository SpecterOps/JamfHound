import json
import os

# Minimum required attributes for nodes in BH Generic Ingest
class Node():
    def __init__(self, nkind):
        self.id = ""
        self.kind = nkind
        self.properties = {}
# Minimum required attributes for edges in BH Generic Ingest
class Edge():
    def __init__(self, nkind):
        self.kind = nkind
        self.start = {"value": "", "match_by": "id"}
        self.end = {"value": "", "match_by": "id"}
        self.properties = {"description":""}

# Checks a supplied Azure JSON file for user nodes that match jamfAccount nodes by email or displayname
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
                    if "jamfAccount" in y.get("kinds") or "jamfDisabledAccount" in y.get("kinds") or "jamfComputerUser" in y.get("kinds"):
                        if y.get("properties").get("email") == x.get("data").get("mail"):
                            matchEdge = Edge("AZMatchedEmail")
                            matchEdge.start["value"] = y.get("id")
                            matchEdge.end["value"] = x.get("data").get("id")
                            matchEdge.properties["description"] = "The JAMF principal email attribute matched the Azure account email."
                            checkProcessor.edges.append(matchEdge)
           #TODO: Create elif for displayname
    print(checkProcessor.write_out_collection("AzureMerge.json"))

# Primary class for preparing data for ingest
class Preprocessor():
    def __init__(self, jtenant):
        self.admins = []
        self.computers = []
        self.computerusers = []
        self.accounts = []
        self.apiclients = []
        self.sites = {}
        self.tenant = jtenant
        self.tenantID = ""
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
            temp_name = tenant.properties.get("name")
            new_name = temp_name.split(':')
            tenant.properties["name"] = new_name[0]
        else:
            tenant.properties["type"] = "cloud-hosted"
        tenant.id = tenant.properties.get("name")
        tenant.properties["objectid"] = tenant.properties.get("name")
        tenant.properties["displayname"] = tenant.properties.get("name")
        self.tenantID = tenant.id
        self.nodes.append(tenant)    

    # Convert nodes to JSON
    def convert_nodes(self):
        for z in self.nodes:
            z.kind = "jamf" + z.kind
            if z.id != self.tenantID:
                z.id = f"{self.tenantID}-{z.id}" # Prepend tenant ID to make child nodes unique
                z.properties["objectid"] = z.id # Make sure objectid matches so ingest can complete
            new_node = {
            "id": z.id,
            "kinds": [z.kind],
            "properties": z.properties  
            }
            self.graph["graph"]["nodes"].append(new_node)

    # Convert edges to JSON
    def convert_edges(self):
        for r in self.edges:
            r.kind = "jamf" + r.kind
            new_edge = {
            "kind" : r.kind,
            "start": r.start,
            "end": r.end,
            "properties": r.properties
            }
            self.graph["graph"]["edges"].append(new_edge)
      #  print(json.dumps(self.graph, indent=2))

    # Write Out JSON
    def write_out_collection(self, outfile="JAMFcollection.json"):
        self.convert_nodes()
        self.compute_edges()
        self.convert_edges()
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
        #TODO: Review node properties and replace any x.properties["name"] = {} with x.properties["name"] = "{}"

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
            self.accounts.append(newaccount)
            self.nodes.append(newaccount) 

    #Add API Client Nodes 
    def process_api_client_nodes(self, accounts_file, roles_file):
        try:
            accts_data = self.file_JSON_load(accounts_file)
            roles_data = self.file_JSON_load(roles_file)
        except Exception as e:
            print(f"Failed to process API Clients and Roles: {e}")
            return
        for v in accts_data["results"]:
            newclient = Node("ApiClient")
            newclient.id = f"AC{v["id"]}"
            newclient.properties = v
            newclient.properties.pop("id")
            newclient.properties["privileges"] = []
            for m in newclient.properties.get("authorizationScopes"):
                for n in roles_data.get("results"):
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
#            self.computerUser_Edge(computer_node, newuser)
    
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
            self.nodes.append(newsite)

    #Generic function to call new edge computes as they are added
    def compute_edges(self):
        self.contains_Tenant_Edges()
        self.adminTo_Tenant_Edge()
        self.adminTo_Site_Edge()
        self.update_account_Edges()
        self.create_account_Edges()
        self.policies_and_scripts_Edges()
        self.memberOf_Edges()
        self.computerExtension_Edges()
        self.createApiIntegrations_Edges()
        self.updateApiIntegrations_Edges()
        self.matchingEmails_Edge()
        self.computerUser_Edge()

    #Compute AdminTo Edges for Tenant by checking enabled accounts with Full Access and Administrator
    def adminTo_Tenant_Edge(self):
        for y in self.nodes:
            if y.properties.get("accessLevel") == "Full Access" and y.properties.get("enabled") == "Enabled" and y.properties.get("privilegeSet") == "Administrator":
                if y.kind == "jamfAccount" and y.properties.get("enabled"):
                    # Enabled tenant admin account
                    adminEdge = Edge("AdminTo")
                    adminEdge.start["value"] = y.id
                    adminEdge.end["value"] = self.tenantID #"T-1"Hardcoded base tenant value
                    adminEdge.properties["description"] = "The source has full administrative control over the target and all resources controlled by the target."
                    self.admins.append(y)
                    self.edges.append(adminEdge)
                else:
                    adminEdge = Edge("AdminTo")
                    adminEdge.start["value"] = y.id
                    adminEdge.end["value"] = self.tenantID # "T-1" Hardcoded base tenant value
                    adminEdge.properties["description"] = "The source has full administrative control over the target and all resources controlled by the target."
                    self.admins.append(y)
                    self.edges.append(adminEdge)
    
    #Compute AdminTo Edges for Sites by checking enabled accounts with Site Access and Administrator    
    def adminTo_Site_Edge(self):
        for b in self.nodes:
            if b.kind == "jamfAccount" or b.kind == "jamfGroup":
                if b.properties.get("accessLevel") == "Site Access" and b.properties.get("enabled") == "Enabled" and b.properties.get("privilegeSet") == "Administrator":
                    adminSiteEdge = Edge("AdminToSite")
                    adminSiteEdge.start["value"] = b.id
                    adminSiteEdge.end["value"] = f"{self.tenantID}-S{b.properties['siteID']}" #TODO: Hardcoded site static value, better to convert to finding site UID in future probably
                    adminSiteEdge.properties["description"] = "The source has administrative control over the site and all resources controlled by the site. This includes creating policies and scripts that impact resources of the site, send or clear MDM commands, remotely administer site devices and computers,  create computer objects for the site."
                    self.admins.append(b) #TODO: Review this to ensure it is proper to exclude site admins from other edges
                    self.edges.append(adminSiteEdge) 

    #Compute contains Edges for Tenant resources #accounts, #computers, #sites, #groups, etc...
    def contains_Tenant_Edges(self):
        for s in self.nodes:
            if not s.id == self.tenantID and s.kind != "jamfComputerUser":
                if self.contains_site_Edges(s):
                    tcontainsEdge = Edge("Contains")
                    tcontainsEdge.start["value"] = self.tenantID # "T-1" Hardcoded base tenant value
                    tcontainsEdge.end["value"] = s.id
                    tcontainsEdge.properties["description"] = "The source contains the target resource."
                    self.edges.append(tcontainsEdge)

    #Compute if a site contains an object
    def contains_site_Edges(self, v):
        if not v.id == self.tenantID and v.kind != "jamfSite" and v.kind != "jamfAccount" and v.kind != "jamfApiClient" and v.kind != "jamfDisabledApiClient": # Do not create additional contains edges to tenant itself or sites. These are only contained by the tenant.
            if v.properties["siteID"] != "-1":
                siteObject = ""
                for r in self.nodes:
                    if r.kind == "jamfSite" and r.id == f"{self.tenantID}-S{v.properties["siteID"]}": #Compare the supplied node siteID with jamfSites in Node list
                        vcontainsEdge = Edge("Contains")
                        vcontainsEdge.start["value"] = r.id
                        vcontainsEdge.end["value"] = v.id
                        vcontainsEdge.properties["description"] = "The source contains the target resource."
                        self.edges.append(vcontainsEdge)
                        return False
        return True


    #Compute Update Account Edge
    def update_account_Edges(self):
        for x in self.nodes:
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Update Accounts" in x.properties["privilegesJSSObjects"]:
                        for z in self.accounts:
                            updateAccountsEdge = Edge("UpdateAccounts")
                            updateAccountsEdge.start["value"] = x.id
                            updateAccountsEdge.end["value"] = z.id
                            updateAccountsEdge.properties["description"] = "The source possesses the 'Update Accounts' JSS Object permission which allows altering the permissions of accounts to include resetting passwords or making themself or others administrators."
                            self.edges.append(updateAccountsEdge)
            if x.kind == "jamfApiClient":
                if "Update Accounts" in x.properties["privileges"]:
                    for z in self.accounts:
                        updateAccountsEdge = Edge("UpdateAccounts")
                        updateAccountsEdge.start["value"] = x.id
                        updateAccountsEdge.end["value"] = z.id
                        updateAccountsEdge.properties["description"] = "The source possesses the 'Update Accounts' JSS Object permission which allows altering the permissions of accounts to include resetting passwords or making themselves or others admins."
                        self.edges.append(updateAccountsEdge)

    #Compute Create Account Edge
    def create_account_Edges(self):
        for x in self.nodes:
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Create Accounts" in x.properties["privilegesJSSObjects"]:
                        updateAccountsEdge = Edge("CreateAccounts")
                        updateAccountsEdge.start["value"] = x.id
                        updateAccountsEdge.end["value"] = self.tenantID # "T-1"
                        updateAccountsEdge.properties["description"] = "The account possesses the 'Create Accounts' JSS Object permission which allows creating new accounts including administrators."
                        self.edges.append(updateAccountsEdge)
            if x.kind == "jamfApiClient":
                if "Create Accounts" in x.properties["privileges"]:
                    updateAccountsEdge = Edge("CreateAccounts")
                    updateAccountsEdge.start["value"] = x.id
                    updateAccountsEdge.end["value"] = self.tenantID # "T-1"
                    updateAccountsEdge.properties["description"] = "The account possesses the 'Create Accounts' JSS Object permission which allows creating new accounts including administrators."
                    self.edges.append(updateAccountsEdge)

    # Compute Push Scripts and Policies Edge #TODO : This may need to be updated to handle multiple sites assigned to an account
    def policies_and_scripts_Edges(self):
        for x in self.nodes:
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Create Policies" in x.properties["privilegesJSSObjects"] or "Update Policies" in x.properties["privilegesJSSObjects"]:
                        self.policies_Edges(x)
                        if "Create Scripts" in x.properties["privilegesJSSObjects"] or "Update Scripts" in x.properties["privilegesJSSObjects"]:
                            # Check for site limitations #TODO : This may need to be updated in the future to handle accounts assigned to multiple sites
                            if x.properties.get("accessLevel") == "Site Access":
                                for k in self.computers:
                                    if k.properties.get("siteID") == x.properties.get("siteID"):
                                        scriptsPoliciesEdge = Edge("Scripts")
                                        scriptsPoliciesEdge.start["value"] = x.id
                                        scriptsPoliciesEdge.end["value"] = k.id
                                        scriptsPoliciesEdge.properties["description"] = "The source can create or update scripts to be executed with policies on the target."
                                        self.edges.append(scriptsPoliciesEdge)
                            else:
                                # Iterate through computers
                                for l in self.computers:
                                    scriptsPoliciesEdge = Edge("Scripts")
                                    scriptsPoliciesEdge.start["value"] = x.id
                                    scriptsPoliciesEdge.end["value"] = l.id
                                    scriptsPoliciesEdge.properties["description"] = "The source can create or update scripts to be executed with policies on the target."
                                    self.edges.append(scriptsPoliciesEdge)
            if x.kind == "jamfApiClient":
                if "Create Policies" in x.properties.get("privileges") or "Update Policies" in x.properties.get("privileges"):
                    self.policies_Edges(x)
                    if "Create Scripts" in x.properties["privileges"] or "Update Scripts" in x.properties["privileges"]:
                        # Iterate through computers
                        for l in self.computers:
                            scriptsPoliciesEdge = Edge("Scripts")
                            scriptsPoliciesEdge.start["value"] = x.id
                            scriptsPoliciesEdge.end["value"] = l.id
                            scriptsPoliciesEdge.properties["description"] = "The source can create or update scripts to be executed with policies on the target."
                            self.edges.append(scriptsPoliciesEdge)

    # Compute Policies Edge
    def policies_Edges(self, account_node):
        # Check for site limitations #TODO : This may need to be updated in the future to handle accounts assigned to multiple sites
        if account_node.properties.get("accessLevel") == "Site Access":
            for k in self.computers:
                if k.properties.get("siteID") == account_node.properties.get("siteID"):
                    policiesEdge = Edge("Policies")
                    policiesEdge.start["value"] = account_node.id
                    policiesEdge.end["value"] = k.id
                    policiesEdge.properties["description"] = "The source can create or update policies to execute commands on the target."
                    self.edges.append(policiesEdge)
        else:
            # Iterate through computers
            for l in self.computers:
                policiesEdge = Edge("Policies")
                policiesEdge.start["value"] = account_node.id
                policiesEdge.end["value"] = l.id
                policiesEdge.properties["description"] = "The source can create or update policies to execute commands on the target."
                self.edges.append(policiesEdge)

    # Compute MemberOf Edge
    def memberOf_Edges(self):
        for t in self.nodes:
            if t.kind == "jamfGroup":
                for b in eval(t.properties.get("members")):
                    for c in self.nodes:
                        if c.kind == "jamfAccount":
                            #TODO: Hardcoded string comparison, find a better way to check this
                            if str(str(self.tenantID) + "-A" + str(b.get("id"))) == c.id and b.get("name") == c.properties.get("name"):
                                memberOfEdge = Edge("MemberOf")
                                memberOfEdge.start["value"] = c.id
                                memberOfEdge.end["value"] = t.id
                                memberOfEdge.properties["description"] = "The source node is a member of the destination node."
                                self.edges.append(memberOfEdge)


    # Global only, not restricted to sites
    def computerExtension_Edges(self):
        for x in self.nodes:
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Create Computer Extension Attributes" in x.properties["privilegesJSSObjects"] or "Update Computer Extension Attributes" in x.properties["privilegesJSSObjects"]:
                        for z in self.computers:
                             computerExtensionEdge = Edge("ComputerExtensions")
                             computerExtensionEdge.start["value"] = x.id
                             computerExtensionEdge.end["value"] = z.id
                             computerExtensionEdge.properties["description"] = "The source can create or update computer extensions executing code on all computers in the JAMF tenant."
                             self.edges.append(computerExtensionEdge) 
            if x.kind == "jamfApiClient":
                if "Create Computer Extension Attributes" in x.properties.get("privileges") or "Update Computer Extension Attributes" in x.properties.get("privileges"):
                    for l in self.computers:
                        computerExtensionEdge = Edge("ComputerExtensions")
                        computerExtensionEdge.start["value"] = x.id
                        computerExtensionEdge.end["value"] = l.id
                        computerExtensionEdge.properties["description"] = "The source can create or update computer extensions executing code on all computers in the JAMF tenant."
                        self.edges.append(computerExtensionEdge)


    # Global only, not site restricted
    def createApiIntegrations_Edges(self):
        for x in self.nodes:
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Create API Integrations" in x.properties["privilegesJSSObjects"]:
                         computerExtensionEdge = Edge("CreateAPIClients")
                         computerExtensionEdge.start["value"] = x.id
                         computerExtensionEdge.end["value"] = self.tenantID
                         computerExtensionEdge.properties["description"] = "The source can create API clients to assume API Roles in the JAMF tenant."
                         self.edges.append(computerExtensionEdge)
                         self.createApiRoles_Edges(x) # Only create the create or update API roles edges if we can create or update clients
                         self.updateApiRoles_Edges(x)
            if x.kind == "jamfApiClient":
                if "Create API Integrations" in x.properties.get("privileges"):
                    computerExtensionEdge = Edge("CreateAPIClients")
                    computerExtensionEdge.start["value"] = x.id
                    computerExtensionEdge.end["value"] = self.tenantID
                    computerExtensionEdge.properties["description"] = "The source can create API clients to assume API Roles in the JAMF tenant."
                    self.edges.append(computerExtensionEdge)
                    self.createApiRoles_Edges(x) # Only create the create or update API roles edges if we can create or update clients
                    self.updateApiRoles_Edges(x)

    # Global only, not restricted to sites
    def updateApiIntegrations_Edges(self):
        for x in self.nodes:
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Update API Integrations" in x.properties["privilegesJSSObjects"]:
                        for z in self.apiclients:
                             computerExtensionEdge = Edge("UpdateAPIClients")
                             computerExtensionEdge.start["value"] = x.id
                             computerExtensionEdge.end["value"] = z.id
                             computerExtensionEdge.properties["description"] = "The source can update update API Clients in the JAMF tenant."
                             self.edges.append(computerExtensionEdge)
                             self.createApiRoles_Edges(x) # Only create the create or update API roles edges if we can create or update clients #TODO: Dedup this
                             self.updateApiRoles_Edges(x)
            if x.kind == "jamfApiClient":
                if "Update API Integrations" in x.properties.get("privileges"):
                    for l in self.apiclients:
                        computerExtensionEdge = Edge("UpdateAPIClients")
                        computerExtensionEdge.start["value"] = x.id
                        computerExtensionEdge.end["value"] = l.id
                        computerExtensionEdge.properties["description"] = "The source can update API Clients in the JAMF tenant."
                        self.edges.append(computerExtensionEdge)
                        self.createApiRoles_Edges(x) # Only create the create or update API roles edges if we can create or update clients
                        self.updateApiRoles_Edges(x)

    # Global only, not site restricted
    def createApiRoles_Edges(self, x):
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:
                    if "Create API Roles" in x.properties["privilegesJSSObjects"]:
                         computerExtensionEdge = Edge("CreateAPIRoles")
                         computerExtensionEdge.start["value"] = x.id
                         computerExtensionEdge.end["value"] = self.tenantID
                         computerExtensionEdge.properties["description"] = "The source can create API Roles in the JAMF tenant and generate credentials for API clients."
                         self.edges.append(computerExtensionEdge)
            if x.kind == "jamfApiClient":
                if "Create API Roles" in x.properties.get("privileges"):
                    computerExtensionEdge = Edge("CreateAPIRoles")
                    computerExtensionEdge.start["value"] = x.id
                    computerExtensionEdge.end["value"] = self.tenantID
                    computerExtensionEdge.properties["description"] = "The source can create API Roles in the JAMF tenant and generate credentials for API clients."
                    self.edges.append(computerExtensionEdge)


    # Global only, not site restricted
    def updateApiRoles_Edges(self, x):
            if x.kind == "jamfAccount" or x.kind == "jamfGroup":
                if x not in self.admins:  
                    if "Update API Roles" in x.properties["privilegesJSSObjects"]:
                         computerExtensionEdge = Edge("UpdateAPIRoles")  
                         computerExtensionEdge.start["value"] = x.id
                         computerExtensionEdge.end["value"] = self.tenantID
                         computerExtensionEdge.properties["description"] = "The source can update API Roles in the JAMF tenant."
                         self.edges.append(computerExtensionEdge)
            if x.kind == "jamfApiClient":
                if "Update API Roles" in x.properties.get("privileges"):
                    computerExtensionEdge = Edge("UpdateAPIRoles")  
                    computerExtensionEdge.start["value"] = x.id
                    computerExtensionEdge.end["value"] = self.tenantID
                    computerExtensionEdge.properties["description"] = "The source can update API Roles in the JAMF tenant."
                    self.edges.append(computerExtensionEdge)

    # Global only, not site restricted #TODO: This could probably be generalized to just a create edge function call
    def computerUser_Edge(self):
        for m in self.computerusers:
            for n in self.computers:
                if n.id.endswith(m.properties.get("computer")):
                    computerUserEdge = Edge("AssignedUser")
                    computerUserEdge.start["value"] = n.id
                    computerUserEdge.end["value"] = m.id
                    computerUserEdge.properties["description"] = "The specified user is assigned to the source computer."
                    self.edges.append(computerUserEdge)


    # Creates an edge between computer users and accounts if the emails are the same
    def matchingEmails_Edge(self):
        for x in self.computerusers:
             if len(x.properties.get("email")) > 1:
                 for y in self.accounts:
                     if y.properties.get("email") == x.properties.get("email"):
                         matchEdge = Edge("MatchedEmail")
                         matchEdge.start["value"] = x.id
                         matchEdge.end["value"] = y.id
                         matchEdge.properties["description"] = "The JAMF principal email attribute matched the JAMF account email indicating it is likely the same account."
                         self.edges.append(matchEdge)

   #TODO : Edge for display names/names matching
