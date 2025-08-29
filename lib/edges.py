from lib.models import Edge

#Module to contain edge calculations
    #Generic function to call new edge computes as they are added
def compute_edges(PreProcessor, jservice):
        contains_Tenant_Edges(PreProcessor)
        adminTo_Tenant_Edge(PreProcessor)
        adminTo_Site_Edge(PreProcessor)
        update_account_Edges(PreProcessor)
        create_account_Edges(PreProcessor)
        policies_and_scripts_Edges(PreProcessor)
        memberOf_Edges(PreProcessor)
        computerExtension_Edges(PreProcessor, jservice)
        createApiIntegrations_Edges(PreProcessor)
#        updateApiIntegrations_Edges(PreProcessor)
        matchingEmails_Edge(PreProcessor)
        computerUser_Edge(PreProcessor)
        matchingUserNames_Edge(PreProcessor)
        recurringScripts_Edge(PreProcessor, jservice)

    #Compute AdminTo Edges for Tenant by checking enabled accounts with Full Access and Administrator
def adminTo_Tenant_Edge(self):
        for y in self.nodes:
            if y.properties.get("accessLevel") == "Full Access" and y.properties.get("privilegeSet") == "Administrator": # y.properties.get("enabled") == "Enabled" and y.properties.get("privilegeSet") == "Administrator":
                adminEdge = Edge("AdminTo")
                adminEdge.start["value"] = y.id
                adminEdge.end["value"] = self.tenantID
                adminEdge.properties["description"] = "The source has full administrative control over the target and all resources controlled by the target."
                adminEdge = self.check_traversable(adminEdge, y)
                self.admins.append(y)
                self.edges.append(adminEdge)
    
    #Compute AdminTo Edges for Sites by checking enabled accounts with Site Access and Administrator    
def adminTo_Site_Edge(self):
        for b in self.nodes:
            if self.is_Jamf_Account_Or_Group(b):
                if b.properties.get("accessLevel") == "Site Access" and b.properties.get("privilegeSet") == "Administrator":
                    adminSiteEdge = Edge("AdminToSite")
                    adminSiteEdge.start["value"] = b.id
                    adminSiteEdge.end["value"] = f"{self.tenantID}-S{b.properties['siteID']}" #TODO: Hardcoded site static value, better to convert to finding site UID in future probably
                    adminSiteEdge.properties["description"] = "The source has administrative control over the site and all resources controlled by the site. This includes creating policies that impact resources of the site, send or clear MDM commands, remotely administer site devices and computers,  create computer objects for the site."
                    adminSiteEdge = self.check_traversable(adminSiteEdge, b)
                    self.admins.append(b) 
                    self.edges.append(adminSiteEdge) 

    #Compute contains Edges for Tenant resources #accounts, #computers, #sites, #groups, etc...
def contains_Tenant_Edges(self):
        for s in self.nodes:
            if not s.id == self.tenantID and s.kind != "jamf_ComputerUser":
                if contains_site_Edges(self, s):
                    tcontainsEdge = Edge("Contains")
                    tcontainsEdge.start["value"] = self.tenantID # "T-1" Hardcoded base tenant value
                    tcontainsEdge.end["value"] = s.id
                    tcontainsEdge.properties["description"] = "The source contains the target resource."
                    tcontainsEdge.properties["traversable"] = True
                    self.edges.append(tcontainsEdge)

    #Compute if a site contains an object
def contains_site_Edges(self, v):
        if not v.id == self.tenantID and v.kind != "jamf_Site" and v.kind != "jamf_Account" and v.kind != "jamf_ApiClient" and v.kind != "jamf_DisabledApiClient": # Do not create additional contains edges to tenant itself or sites. These are only contained by the tenant.
            if v.properties["siteID"] != "-1":
                siteObject = ""
                for r in self.nodes:
                    if r.kind == "jamf_Site" and r.id == f"{self.tenantID}-S{v.properties["siteID"]}": #Compare the supplied node siteID with jamf_Sites in Node list
                        vcontainsEdge = Edge("Contains")
                        vcontainsEdge.start["value"] = r.id
                        vcontainsEdge.end["value"] = v.id
                        vcontainsEdge.properties["description"] = "The source contains the target resource."
                        vcontainsEdge.properties["traversable"] = True
                        self.edges.append(vcontainsEdge)
                        return False
        return True


    #Compute Update Account Edge
def update_account_Edges(self):
        for x in self.nodes:
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:
                    if "Update Accounts" in x.properties["privilegesJSSObjects"]:
                            updateAccountsEdge = Edge("UpdateAccounts")
                            updateAccountsEdge.start["value"] = x.id
                            updateAccountsEdge.end["value"] = self.tenantID
                            updateAccountsEdge.properties["description"] = "The source possesses the 'Update Accounts' JSS Object permission which allows altering the permissions of existing accounts or groups. If the source is a local Jamf account they can grant themself additional permissions, grant permissions to other accounts, grant permissions to any existing groups, modify members of groups to include adding themselves if the source is a Jamf account, enable disabled accounts, and reset the password of any Jamf account."
                            updateAccountsEdge = self.check_traversable(updateAccountsEdge, x)
                            self.edges.append(updateAccountsEdge)
            if self.is_Jamf_API_Client(x):
                if "Update Accounts" in x.properties["privileges"]:
                        updateAccountsEdge = Edge("UpdateAccounts")
                        updateAccountsEdge.start["value"] = x.id
                        updateAccountsEdge.end["value"] = self.tenantID
                        updateAccountsEdge.properties["description"] = "The source possesses the 'Update Accounts' JSS Object permission which allows altering the permissions of existing accounts or groups. If the source is a local Jamf account they can grant themself additional permissions or make themself a Full-Access Administrator, grant permissions to other accounts, grant permissions to any existing groups, modify members of groups to include adding themselves if the source is a Jamf acount, enable disabled accounts, and reset the password of any Jamf account."
                        updateAccountsEdge = self.check_traversable(updateAccountsEdge, x)
                        self.edges.append(updateAccountsEdge) 

    #Compute Create Account Edge
def create_account_Edges(self):
        for x in self.nodes:
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:
                    if "Create Accounts" in x.properties["privilegesJSSObjects"]:
                        updateAccountsEdge = Edge("CreateAccounts")
                        updateAccountsEdge.start["value"] = x.id
                        updateAccountsEdge.end["value"] = self.tenantID # "T-1"
                        updateAccountsEdge.properties["description"] = "The account possesses the 'Create Accounts' JSS Object permission which allows creating new accounts, including administrators, as well as creating new groups with any permissions and defining Jamf accounts assigned to them."
                        updateAccountsEdge = self.check_traversable(updateAccountsEdge, x)
                        self.edges.append(updateAccountsEdge)

            if self.is_Jamf_API_Client(x):
                if "Create Accounts" in x.properties["privileges"]:
                    updateAccountsEdge = Edge("CreateAccounts")
                    updateAccountsEdge.start["value"] = x.id
                    updateAccountsEdge.end["value"] = self.tenantID # "T-1"
                    updateAccountsEdge.properties["description"] = "The API client possesses the 'Create Accounts' JSS Object permission which allows creating new accounts, including administrators, as well as creating new groups with any permissions and defining Jamf accounts assigned to them."
                    updateAccountsEdge = self.check_traversable(updateAccountsEdge, x)
                    self.edges.append(updateAccountsEdge)

    # Compute Push Scripts and Policies Edge
def policies_and_scripts_Edges(self):
        for x in self.nodes:
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:
                    if "Create Policies" in x.properties["privilegesJSSObjects"]:
                         create_policies_Edges(self, x)
                    if "Update Policies" in x.properties["privilegesJSSObjects"] and self.policies: # Check if at least one policy exists with this permission
                         update_policies_Edges(self, x)
                    if "Create Scripts" in x.properties["privilegesJSSObjects"] or "Update Scripts" in x.properties["privilegesJSSObjects"]:
                        # Check for site limitations #TODO : This may need to be updated in the future to handle accounts assigned to multiple sites
                        if x.properties.get("accessLevel") == "Site Access":
                            for k in self.sites:
                                if k.properties.get("siteID") == x.properties.get("siteID"):
                                    scriptsPoliciesEdge = Edge("ScriptsNonTraversable")
                                    scriptsPoliciesEdge.start["value"] = x.id
                                    scriptsPoliciesEdge.end["value"] = k.id
                                    scriptsPoliciesEdge.properties["description"] = "The source can create or update scripts on the target."
                                    scriptsPoliciesEdge.properties["traversable"] = False # Make non-traversable until we get logic for checking if there are any recurring script executions
                                    self.edges.append(scriptsPoliciesEdge)
                        else:
                            scriptsPoliciesEdge = Edge("ScriptsNonTraversable")
                            scriptsPoliciesEdge.start["value"] = x.id
                            scriptsPoliciesEdge.end["value"] = self.tenantID
                            scriptsPoliciesEdge.properties["description"] = "The source can create or update scripts on the target."
                            scriptsPoliciesEdge.properties["traversable"] = False # Make non-traversable until we get logic for checking if there are any recurring script executions
                            self.edges.append(scriptsPoliciesEdge)
            if self.is_Jamf_API_Client(x):
                if "Create Policies" in x.properties.get("privileges"):
                    create_policies_Edges(self, x)
                if "Update Policies" in x.properties.get("privileges") and self.policies: # Check if at least one policy exists with this permission
                    update_policies_Edges(self, x)
                if "Create Scripts" in x.properties["privileges"] or "Update Scripts" in x.properties["privileges"]:
                    scriptsPoliciesEdge = Edge("ScriptsNonTraversable")
                    scriptsPoliciesEdge.start["value"] = x.id
                    scriptsPoliciesEdge.end["value"] = self.tenantID
                    scriptsPoliciesEdge.properties["description"] = "The source can create or update scripts on the target."
                    scriptsPoliciesEdge.properties["traversable"] = False
                    self.edges.append(scriptsPoliciesEdge)

    # Create Policies Edge
def create_policies_Edges(self, account_node):
        # Check for site limitations
        if account_node.properties.get("accessLevel") == "Site Access":
            for k in self.computers:
                if k.properties.get("siteID") == account_node.properties.get("siteID"):
                    policiesEdge = Edge("CreatePolicies")
                    policiesEdge.start["value"] = account_node.id
                    policiesEdge.end["value"] = k.id
                    policiesEdge.properties["description"] = "The source can possesses the 'Create Policies' privilege allowing code execution on the target."
                    policiesEdge.properties["Code_Execution_Methods"] = policy_execution_Primitives(self, account_node)
                    policiesEdge = self.check_traversable(policiesEdge, account_node)
                    self.edges.append(policiesEdge)
        else:
            # Iterate through computers
            for l in self.computers:
                policiesEdge = Edge("CreatePolicies")
                policiesEdge.start["value"] = account_node.id
                policiesEdge.end["value"] = l.id
                policiesEdge.properties["description"] = "The source can possesses the 'Create Policies' privilege allowing code execution on the target."
                policiesEdge.properties["Code_Execution_Methods"] = policy_execution_Primitives(self, account_node)
                policiesEdge = self.check_traversable(policiesEdge, account_node) # Use defined class method
                self.edges.append(policiesEdge)

    # Update Policies Edge
def update_policies_Edges(self, account_node):
        # Check for site limitations
        if account_node.properties.get("accessLevel") == "Site Access":
            for k in self.computers:
                if k.properties.get("siteID") == account_node.properties.get("siteID"): #TODO, may be needed to determine if a policy is applied tenant wide or at the site level
                    policiesEdge = Edge("UpdatePolicies")
                    policiesEdge.start["value"] = account_node.id
                    policiesEdge.end["value"] = k.id
                    policiesEdge.properties["description"] = "The source possesses the 'Update Policies' privilege and at least one policy already exists in the tenant allowing code execution on the target."
                    policiesEdge.properties["Code_Execution_Methods"] = policy_execution_Primitives(self, account_node)
                    policiesEdge = self.check_traversable(policiesEdge, account_node)
                    self.edges.append(policiesEdge)
        else:
            # Iterate through computers
            for l in self.computers:
                policiesEdge = Edge("UpdatePolicies")
                policiesEdge.start["value"] = account_node.id
                policiesEdge.end["value"] = l.id
                policiesEdge.properties["description"] = "The source possesses the 'Update Policies' privilege and at least one policy already exists in the tenant allowing code execution on the target."
                policiesEdge.properties["Code_Execution_Methods"] = policy_execution_Primitives(self, account_node)
                policiesEdge = self.check_traversable(policiesEdge, account_node) # Use defined class method
                self.edges.append(policiesEdge)
                
def policy_execution_Primitives(self, object_node):
     execution_methods = ["Execute Command - The source can execute commands on targets using Process and File checks within policies."]
     #TODO: Check if a script exists in the tenant, if so then the source can also execute existing scripts without needing to create or modify
     if self.is_Jamf_API_Client(object_node):
          if "Create Scripts" in object_node.properties["privileges"]:
               execution_methods.append("Script Creation - The source possesses the privilege 'Create Scripts' to create new scripts to be run by policies.")
          if "Update Scripts" in object_node.properties["privileges"]: #TODO: Check for at least one script that exists in the tenant
               execution_methods.append("Script Updates - The source possesses the privilege 'Update Scripts' to update existing scripts to be run by policies.")
          #if "Create Packages" in object_node.properties["privileges"]: #TODO: Check if this is all that is needed to run malicious packages with policies
          #     execution_methods.append("Package Creation - The source possesses the privilege 'Create Packages' to create new PKG files to be run by policies.")
          #if "Update Packages" in object_node.properties["privileges"]: #TODO: Check if this is all that is needed to run malicious packages with policies
          #     execution_methods.append("Package Creation - The source possesses the privilege 'Update Packages' to update existing PKG files to be run by policies.")
     elif self.is_Jamf_Account_Or_Group(object_node):
          if "Create Scripts" in object_node.properties["privilegesJSSObjects"]:
               execution_methods.append("Script Creation - The source possesses the privilege 'Create Scripts' to create new scripts to be run by policies.")
          if "Update Scripts" in object_node.properties["privilegesJSSObjects"]: #TODO: Check for at least one script that exists in the tenant
               execution_methods.append("Script Updates - The source possesses the privilege 'Update Scripts' to update existing scripts to be run by policies.")
          #if "Create Packages" in object_node.properties["privilegesJSSObjects"]: #TODO: Check if this is all that is needed to run malicious packages with policies
          #     execution_methods.append("Package Creation - The source possesses the privilege 'Create Packages' to create new PKG files to be run by policies.")
          #if "Update Packages" in object_node.properties["privilegesJSSObjects"]: #TODO: Check if this is all that is needed to run malicious packages with policies
          #     execution_methods.append("Package Creation - The source possesses the privilege 'Update Packages' to update existing PKG files to be run by policies.")
     else:
          print("ERROR: During Policy Execution Processing an unsupported policy edge node type was provided.") #TODO: Official error handling needed
     return execution_methods

    # Compute MemberOf Edge
def memberOf_Edges(self):
        for t in self.nodes:
            if t.kind == "jamf_Group":
                for b in eval(t.properties.get("members")):
                    for c in self.nodes:
                        if c.kind == "jamf_Account" or c.kind == "jamf_DisabledAccount":
                            #TODO: Hardcoded string comparison, find a better way to check this
                            if str(str(self.tenantID) + "-A" + str(b.get("id"))) == c.id and b.get("name") == c.properties.get("name"):
                                memberOfEdge = Edge("MemberOf")
                                memberOfEdge.start["value"] = c.id
                                memberOfEdge.end["value"] = t.id
                                memberOfEdge.properties["description"] = "The source node is a member of the destination node."
                                memberOfEdge = self.check_traversable(memberOfEdge, c)
                                self.edges.append(memberOfEdge)


    # Global only, not restricted to sites
def computerExtension_Edges(self, jservice):
        for x in self.nodes:
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:
                    if "Create Computer Extension Attributes" in x.properties["privilegesJSSObjects"]:
                        for z in self.computers:
                             computerExtensionEdge = Edge("CreateComputerExtensions")
                             computerExtensionEdge.start["value"] = x.id
                             computerExtensionEdge.end["value"] = z.id
                             computerExtensionEdge.properties["description"] = "The source can create computer extension attributes executing code on all computers in the Jamf tenant."
                             computerExtensionEdge = self.check_traversable(computerExtensionEdge, x)
                             self.edges.append(computerExtensionEdge)
                    if "Update Computer Extension Attributes" in x.properties["privilegesJSSObjects"]:
                        try:
                          response = jservice.getComputerExtensionAttributes()
                          if len(response.get("computer_extension_attributes")) > 0: # Check if at least one computer extension attribute exists
                               print(x.properties.get("name"))
                               for z in self.computers:
                                 computerExtensionEdge = Edge("UpdateComputerExtensions")
                                 computerExtensionEdge.start["value"] = x.id
                                 computerExtensionEdge.end["value"] = z.id
                                 computerExtensionEdge.properties["description"] = "The source can update computer extension attributes and at least one computer extension attribute exists allowing execution of code on all computers in the Jamf tenant."
                                 computerExtensionEdge = self.check_traversable(computerExtensionEdge, x)
                                 self.edges.append(computerExtensionEdge)
                        except Exception as e:
                             print(str(e))  
            if self.is_Jamf_API_Client(x):
                if "Create Computer Extension Attributes" in x.properties.get("privileges"):
                    for l in self.computers:
                        computerExtensionEdge = Edge("CreateComputerExtensions")
                        computerExtensionEdge.start["value"] = x.id
                        computerExtensionEdge.end["value"] = l.id
                        computerExtensionEdge.properties["description"] = "The source can create computer extension attributes executing code on all computers in the Jamf tenant."
                        computerExtensionEdge = self.check_traversable(computerExtensionEdge, x)
                        self.edges.append(computerExtensionEdge)
                if "Update Computer Extension Attributes" in x.properties.get("privileges"):
                    try:
                          response = jservice.getComputerExtensionAttributes()
                          if len(response.get("computer_extension_attributes")) > 0: # Check if at least one computer extension attribute exists
                            for l in self.computers:
                              computerExtensionEdge = Edge("UpdateComputerExtensions")
                              computerExtensionEdge.start["value"] = x.id
                              computerExtensionEdge.end["value"] = l.id
                              computerExtensionEdge.properties["description"] = "The source can update computer extension attributes and at least one computer extension attribute exists allowing execution of code on all computers in the Jamf tenant."
                              computerExtensionEdge = self.check_traversable(computerExtensionEdge, x)
                              self.edges.append(computerExtensionEdge)
                    except Exception as e:
                            print(str(e))


    # Global only, not site restricted
def createApiIntegrations_Edges(self):
        for x in self.nodes:
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:
                    if "Create API Integrations" in x.properties["privilegesJSSObjects"]:
                         createCombination_Edges(self, x)
                    if "Update API Integrations" in x.properties["privilegesJSSObjects"]:
                         updateCombination_Edges(self, x)
            if self.is_Jamf_API_Client(x):
                if "Create API Integrations" in x.properties.get("privileges"):
                    createCombination_Edges(self, x)
                if "Update API Integrations" in x.properties["privileges"]:
                    updateCombination_Edges(self, x)
            createApiRoles_Edges(self, x) # These are always going to be non-traversable without another previous permission like Create or Update API Integrations
            updateApiRoles_Edges(self, x) # This may be traversable if the source is an Api Client

# Creating our first complex edges, used for privilege escalation
def createCombination_Edges(self, x):
    # Create New Client and Create New Role
    if x.properties.get("privilegesJSSObjects"): # Jamf Account
        if "Create API Roles" in x.properties["privilegesJSSObjects"]:
            newEdge = Edge("Create_API_Client_and_Create_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Create API Integrations' and 'Create API Roles' permissions, which together allow the creation of new API clients with any permissions in newly assigned roles and retrieving credentials to authenticate with the permissions of the new client."
            newEdge.properties["traversable"] = True
            self.edges.append(newEdge) # Append our new edge

    # Create New Client and Assign an Updated Role
        if "Update API Roles" in x.properties["privilegesJSSObjects"] and self.rolesData.get("results"): # Check for permission and that we have at least one created Role
            newEdge = Edge("Create_API_Client_and_Update_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Create API Integrations' and 'Update API Roles' permissions and at least one API role exists in the tenant. Combined these allow the creation of new API clients to assume roles, modifying the permissions of existing roles, and retrieving credentials to authenticate with the permissions of the new client."
            newEdge.properties["traversable"] = True
            self.edges.append(newEdge) # Append our new edge

    # Create New Client and Assign an Existing Role
        if self.rolesData.get("results"): # Test if anything is contained in results and if so, we know we can assign roles
            newEdge = Edge("Create_API_Client_and_Assign_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Create API Integrations' permission and at least one role has been created in the tenant. Combined these allow the creation of new API clients to assume the permissions of existing roles and retrieving credentials to authenticate with the permissions of the new client."
            #Check each role to determine elligible permissions to be assigned
            elligible_privs = []
            if self.rolesData.get("results"):
                for n in self.rolesData.get("results"):
                    elligible_privs.append(f"Role: {n.get("displayName")} - {", ".join(n.get("privileges"))}")
            newEdge.properties["Existing_Roles_and_Privileges"] = elligible_privs
            newEdge.properties["traversable"] = True
            self.edges.append(newEdge) # Append our new edge

    elif x.properties.get("privileges"): # API Client
        if "Create API Roles" in x.properties["privileges"]:
            newEdge = Edge("Create_API_Client_and_Create_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Create API Integrations' and 'Create API Roles' permissions, which together allow the creation of new API clients with any permissions in newly assigned roles and retrieving credentials to authenticate with the permissions of the new client."
            newEdge.properties["traversable"] = True
            self.edges.append(newEdge) # Append our new edge

    # Create New Client and Assign an Updated Role
        if "Update API Roles" in x.properties["privileges"] and self.rolesData.get("results"): # Check for permission and that we have at least one created Role
            newEdge = Edge("Create_API_Client_and_Update_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Create API Integrations' and 'Update API Roles' permissions and at least one API role exists in the tenant. Combined these allow the creation of new API clients to assume roles, modifying the permissions of existing roles, and retrieving credentials to authenticate with the permissions of the new client."
            newEdge.properties["traversable"] = True
            self.edges.append(newEdge) # Append our new edge

    # Create New Client and Assign an Existing Role
        if self.rolesData.get("results"): # Test if anything is contained in results and if so, we know we can assign roles
            newEdge = Edge("Create_API_Client_and_Assign_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Create API Integrations' permission and at least one role has been created in the tenant. Combined these allow the creation of new API clients to assume the permissions of existing roles and retrieving credentials to authenticate with the permissions of the new client."
            #Check each role to determine elligible permissions to be assigned
            elligible_privs = []
            if self.rolesData.get("results"):
                for n in self.rolesData.get("results"):
                    elligible_privs.append(f"Role: {n.get("displayName")} - {", ".join(n.get("privileges"))}")
            newEdge.properties["Existing_Roles_and_Privileges"] = elligible_privs
            newEdge.properties["traversable"] = True
            self.edges.append(newEdge) # Append our new edge

    else: #How Did We Get Here?
        print("Unsupported Node Type Identified .. skipping") #TODO: Error Logging

# Creating our second complex edges, used for privilege escalation
def updateCombination_Edges(self, x):
    if x.properties.get("privilegesJSSObjects"): # Jamf Account
         # Update Api Client and Assign Updated Role
        if "Update API Roles" in x.properties["privilegesJSSObjects"] and self.rolesData.get("results") and len(self.apiclients) > 0:
            newEdge = Edge("Update_API_Client_and_Update_Roles")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Update API Integrations' and 'Update API Roles' permissions and at least one Api Client and Role exist in the tenant, which together allow upedating existing API clients with any permissions by updating existing roles."
            newEdge.properties["traversable"] = False #Non-Traversable since we do not have a method to retrieve credentials as Jamf Account or Jamf Group without "Create API Integration Permission"
            self.edges.append(newEdge) # Append our new edge

        # Update Api Client and Assign New Role
        if "Create API Roles" in x.properties["privilegesJSSObjects"] and len(self.apiclients) > 0: # Check if there is at least one Api Client created
            newEdge = Edge("Update_API_Client_and_Create_Roles")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Update API Integrations' and 'Create API Roles' permissions and at least one API client exists in the tenant. Combined these allow updating API clients and assigning new roles created with any included permissions."
            newEdge.properties["traversable"] = False #Non-Traversable since we do not have a method to retrieve credentials unless we have "Create API Integrations"
            self.edges.append(newEdge) # Append our new edge

        # Update Api Client and Assign an Existing Role
        if len(self.apiclients) > 0 and self.rolesData.get("results"): # Test if anything is contained in results and if so, we know we can assign roles if an API client exists
            newEdge = Edge("Update_API_Client_and_Assign_Role")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source possesses the 'Update API Integrations' permission and at least one role has been created in the tenant. Combined these allow updating existing API clients to assume the permissions of existing roles."
            #Check each role to determine elligible permissions to be assigned
            elligible_privs = []
            if self.rolesData.get("results"):
                for n in self.rolesData.get("results"):
                    elligible_privs.append(f"Role: {n.get("displayName")} - {", ".join(n.get("privileges"))}")
            newEdge.properties["Existing_Roles_and_Privileges"] = elligible_privs
            newEdge.properties["traversable"] = False # Same as preceding 2
            self.edges.append(newEdge) # Append our new edge
    
    elif x.properties.get("privileges"): # API Client
         # Update Api Client and Assign Updated Role -> Update Self and Update Roles
        if "Update API Roles" in x.properties["privileges"] and self.rolesData.get("results"): #Third check not needed since this should be an API client
            newEdge = Edge("Update_Self_and_Update_Roles")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source is an API Client that possesses 'Update API Integrations' and 'Update API Roles' permissions and at least one Role exists in the tenant, which together allows the client to update itself or other Api clients to assign any permissions by updating and assigning a role."
            newEdge.properties["traversable"] = True #Traversable since we are in the context of an API client
            self.edges.append(newEdge) # Append our new edge
        # Update Api Client and Assign New Role
        if "Create API Roles" in x.properties["privileges"]:
            newEdge = Edge("Update_Self_and_Create_Roles")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source is an API client that possesses the 'Update API Integrations' and 'Create API Roles' permissions. Combined these allow the API client to update itself or other Api clients and assigning new roles created with any included permissions."
            newEdge.properties["traversable"] = True #Traversable since we are in the context of an API client
            self.edges.append(newEdge) # Append our new edge

        # Update Api Client and Assign an Existing Role
        if self.rolesData.get("results"): # Test if anything is contained in results and if so, we know we can assign roles to the Api Client
            newEdge = Edge("Update_Self_and_Assign_Roles")
            newEdge.start["value"] = x.id
            newEdge.end["value"] = self.tenantID
            newEdge.properties["description"] = "The source is an API client that possesses the 'Update API Integrations' permission and at least one role has been created in the tenant. Combined these allow the Api client to update itself to assume the permissions of existing roles."
            #Check each role to determine elligible permissions to be assigned
            elligible_privs = []
            if self.rolesData.get("results"):
                for n in self.rolesData.get("results"):
                    elligible_privs.append(f"Role: {n.get("displayName")} - {", ".join(n.get("privileges"))}")
            newEdge.properties["Existing_Roles_and_Privileges"] = elligible_privs
            newEdge.properties["traversable"] = True # Same as preceding 2
            self.edges.append(newEdge) # Append our new edge

    # Global only, not restricted to sites
'''def updateApiIntegrations_Edges(self):
        for x in self.nodes:
            if x.kind == "jamf_Account" or x.kind == "jamf_DisabledAccount" or x.kind == "jamf_Group":
                if x not in self.admins:
                    if "Update API Integrations" in x.properties["privilegesJSSObjects"]:
                        for z in self.apiclients:
                             computerExtensionEdge = Edge("UpdateAPIClients")
                             computerExtensionEdge.start["value"] = x.id
                             computerExtensionEdge.end["value"] = z.id
                             computerExtensionEdge.properties["description"] = "The source can update update API Clients in the JAMF tenant."
                             computerExtensionEdge = self.check_traversable(computerExtensionEdge, x)
                             self.edges.append(computerExtensionEdge)
                             self.createApiRoles_Edges(x) # Only create the create or update API roles edges if we can create or update clients #TODO: Dedup this
                             self.updateApiRoles_Edges(x)
            if x.kind == "jamf_ApiClient" or x.kind == "jamf_DisabledApiClient":
                if "Update API Integrations" in x.properties.get("privileges"):
                    for l in self.apiclients:
                        computerExtensionEdge = Edge("UpdateAPIClients")
                        computerExtensionEdge.start["value"] = x.id
                        computerExtensionEdge.end["value"] = l.id
                        computerExtensionEdge.properties["description"] = "The source can update API Clients in the JAMF tenant."
                        computerExtensionEdge = self.check_traversable(computerExtensionEdge, x)
                        self.edges.append(computerExtensionEdge)
                        self.createApiRoles_Edges(x) # Only create the create or update API roles edges if we can create or update clients
                        self.updateApiRoles_Edges(x)'''

    # Global only, not site restricted
def createApiRoles_Edges(self, x):
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:
                    if "Create API Roles" in x.properties["privilegesJSSObjects"]:
                         computerExtensionEdge = Edge("CreateAPIRoles")
                         computerExtensionEdge.start["value"] = x.id
                         computerExtensionEdge.end["value"] = self.tenantID
                         computerExtensionEdge.properties["description"] = "The source can create API Roles in the Jamf tenant."
                         computerExtensionEdge.properties["traversable"] = False # Non-Traversable without another create Api Integrations or Update Api Integrations Edge, already enumerated previously
                         self.edges.append(computerExtensionEdge)
            if self.is_Jamf_API_Client(x):
                if "Create API Roles" in x.properties.get("privileges"):
                    computerExtensionEdge = Edge("CreateAPIRoles")
                    computerExtensionEdge.start["value"] = x.id
                    computerExtensionEdge.end["value"] = self.tenantID
                    computerExtensionEdge.properties["description"] = "The source can create API Roles in the Jamf tenant."
                    computerExtensionEdge.properties["traversable"] = False # Non-Traversable without another create Api Integrations or Update Api Integrations Edge
                    self.edges.append(computerExtensionEdge)


    # Global only, not site restricted
def updateApiRoles_Edges(self, x):
            if self.is_Jamf_Account_Or_Group(x):
                if x not in self.admins:  
                    if "Update API Roles" in x.properties["privilegesJSSObjects"]:
                         computerExtensionEdge = Edge("UpdateAPIRoles")  
                         computerExtensionEdge.start["value"] = x.id
                         computerExtensionEdge.end["value"] = self.tenantID
                         computerExtensionEdge.properties["description"] = "The source can update API Roles in the Jamf tenant."
                         computerExtensionEdge.properties["traversable"] = False # Non-Traversable if the source is not an API client
                         self.edges.append(computerExtensionEdge)
            if self.is_Jamf_API_Client(x):
                if "Update API Roles" in x.properties.get("privileges"):
                    computerExtensionEdge = Edge("Update_Roles_Assigned_To_Self")  
                    computerExtensionEdge.start["value"] = x.id
                    computerExtensionEdge.end["value"] = self.tenantID
                    computerExtensionEdge.properties["description"] = "The source is an API client possessing the 'Update API Roles' privilege which allows updating existing API roles with any permissions including roles assigned to itself."
                    computerExtensionEdge.properties["traversable"] = True # Traversable if an Api Client can update roles, also if it has privileges this means it has at least 1 role assigned
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
                    computerUserEdge.properties["traversable"] = True
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
                         matchEdge.properties["description"] = "The Jamf principal email attribute matched the Jamf account email indicating it is likely the same account."
                         matchEdge.properties["traversable"] = True
                         self.edges.append(matchEdge)
    # Creates an edge between computer users and accounts if the displaynames are the same
def matchingUserNames_Edge(self):
        for x in self.computerusers:
            if len(x.properties.get("displayname")) > 1:
                for y in self.accounts:
                    if y.properties.get("name") == x.properties.get("displayname") or y.properties.get("displayname") == x.properties.get("displayname"):
                        matchEdge = Edge("MatchedName")
                        matchEdge.start["value"] = x.id
                        matchEdge.end["value"] = y.id
                        matchEdge.properties["description"] = "The Jamf principal name or displayname attributes matched the Jamf account name."
                        matchEdge.properties["traversable"] = True
                        self.edges.append(matchEdge)

# If there is a policy configured to recurringly run a script, and any principal has 'Update Scripts' permission then this is a traversable edge to any computer/computer_group/user/user_group targeted by the policy
# This is increasingly one of the more complex edges
def recurringScripts_Edge(self, jservice):
     if self.scripts and self.policies: # Check if there are scripts and existing policies in the first place
          policies = []
          for y in self.policies:
               # The one time frequencies allowed are: once per computer, once per user, once per user per computer, besides those all others are recurring at
               # Daily, Weekly, Monthly, or every jamf checkin intervals
               if y.get("Properties").get("enabled") == True:
                    #if y.get("Properties").get("trigger_checkin") == True or y.get("Properties").get("trigger_login") == True or y.get("Properties").get("trigger_network_state_changed") == True or  y.get("Properties").get("trigger_startup") == True :
                    if "per user" not in y.get("Properties").get("frequency") and "per computer" not in y.get("Properties").get("frequency"):
                         policy_id = y.get("Properties").get("id") # For properties and follow on query
                         policy_name = y.get("Properties").get("name")
                         full_policy = jservice.getPolicy(policy_id)
                         # print(full_policy) : TODO : Make this into a write out of recurring_policies.json for pkg analysis edges
                         if len(full_policy.get("policy").get("scripts")) > 0:
                              scripts = []
                              for x in full_policy.get("policy").get("scripts"):
                                   scripts.append(f"ScriptID - {x.get("id")} : ScriptName - {x.get("name")}")
#                                   scripts[x.get("id")] = x.get("name") #Property
                              policy_exclusions = full_policy.get("policy").get("scope").get("exclusions")
                              computers = [] #Target Nodes
                              if full_policy.get("policy").get("scope").get("all_computers") == True:
                                   if len(policy_exclusions.get("computers")) < 0:
                                      print(policy_id, " has no Computers Specified in List.")
                                      if len(policy_exclusions.get("computer_groups")) < 0: 
                                           if len(policy_exclusions.get("users")) < 0:
                                                if len(policy_exclusions.get("user_groups")) < 0:
                                                     if len(policy_exclusions.get("network_segments")) < 0:
                                                          if len(policy_exclusions.get("departments")) < 0:
                                                               if len(policy_exclusions.get("buildings")) < 0:
                                                                    if len(policy_exclusions.get("ibeacons")) < 0:
                                                                         #No Exclusions, Runs on All computers, TODO: Look into limitations
                                                                         computers = self.computers
                                                                         policies.append(f"{policy_id} : {policy_name}")
                                   else:
                                           udids1 = []
                                           for y in policy_exclusions.get("computers"):
                                                udids1.append(y.get("udid"))
                                           for z in self.computers:
                                                if z.properties.get("udid") not in udids1:
                                                     computers.append(z)
                                           policies.append(f"{policy_id} : {policy_name}")
                              #TODO: Elif computer_groups
                              #TODO: Elif User_Groups
                              #TODO: Elif Users : Not sure if I'm going to support the other network_segments, departments, ibeacons, etc...
                              else: #Not All Computers so we are going to iterate through in scope computers, assuming in scope computers are not excluded, might need to check users
                                   udids2 = []
                                   for m in full_policy.get("policy").get("scope").get("computers"):
                                        udids2.append(m.get("udid"))
                                   for n in self.computers:
                                        if n.properties.get("udid") in udids2:
                                             computers.append(n)
                                   policies.append(f"{policy_id} : {policy_name}")          
                              #build our edges
                              for r in self.nodes:
                                  if self.is_Jamf_Account_Or_Group(r):
                                      if r not in self.admins:
                                          if "Update Scripts" in r.properties["privilegesJSSObjects"]:
                                              for c in computers:
                                                  scriptsEdge = Edge("Update_Recurring_Scripts")
                                                  scriptsEdge.start["value"] = r.id
                                                  scriptsEdge.end["value"] = c.id
                                                  scriptsEdge.properties["description"] = "The source possesses the 'Update Scripts' permission and there are scripts configured to run repeatedly on target computers in the Jamf tenant. This allows the source to update specific scripts to execute code on the in-scope computers for the policy."
                                                  scriptsEdge.properties["target_scripts"] = scripts
                                                  scriptsEdge.properties["traversable"] = True 
                                                  scriptsEdge.properties["policies"] = policies
                                                  self.edges.append(scriptsEdge)
                                  if self.is_Jamf_API_Client(r):
                                       if "Update Scripts" in r.properties["privileges"]:
                                              for c in computers:
                                                  scriptsEdge = Edge("Update_Recurring_Scripts")
                                                  scriptsEdge.start["value"] = r.id
                                                  scriptsEdge.end["value"] = c.id
                                                  scriptsEdge.properties["description"] = "The source possesses the 'Update Scripts' permission and there are scripts configured to run repeatedly on target computers in the Jamf tenant. This allows the source to update specific scripts to execute code on the in-scope computers for the policy."
                                                  scriptsEdge.properties["target_scripts"] = scripts
                                                  scriptsEdge.properties["traversable"] = True
                                                  scriptsEdge.properties["policies"] = policies 
                                                  self.edges.append(scriptsEdge)     
                                         
              
