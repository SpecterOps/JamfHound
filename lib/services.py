#!/usr/bin/env python3
from __future__ import annotations
from os.path import exists
from lib.common import (
    Object,
    Common,
    Generic,
    Request,
    Response,
    Session,
    TypeVar,
    Union,
    datetime,
    Any
)
from lib.presentation import (
    ModelView,
    AccountView,
    ComputerView,
    PolicyView
)
from lib.models import (
    Model,
    User,
    Computer,
    Account,
    Me,
    Script,
    Policy,
    Data
)
from requests.auth import HTTPBasicAuth

_T = TypeVar("_T")
_M = TypeVar("_M", bound=Union[Model, User, Computer, Script, Policy, Me, Data, None])
_V = TypeVar("_V", bound=Union[ModelView, AccountView, ComputerView, PolicyView, None])

class JAMFService(Common):
    def __init__(self, *ag, **kw):
        Common.__init__(self, *ag)
        self.session = Session()
        self.baseUrl = "https://tenant.jamfcloud.com"
        self.username = "auditor"
        self.password = "EXAMPLEpass21"
        self.token = ""
        self.lastCall = ""
        self.set(**kw)

    def authenticate(self, *ag, **kw) -> JAMFService:
        self.set(token=self.getToken(*ag, **kw))
        if not bool(self.token):
            raise Exception("Failed to authenticate")
        return self

    @property
    def headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
         }

    def retrieve(self, url: str, *ag, **kw) -> Any:
        self.lastCall = f"{self.baseUrl.rstrip('/')}/{url.lstrip('/')}"
        response = self.session.get(
            url=self.lastCall,
            headers=self.headers,
            *ag, **kw
        )
        response.raise_for_status()
        return response.json()

    def post(self, url: str, *ag, **kw) -> Any:
        self.lastCall = f"{self.baseUrl.rstrip('/')}/{url.lstrip('/')}"
        response = self.session.post(
            url=self.lastCall,
            headers=self.headers,
            *ag, **kw
        )
        response.raise_for_status()
        return response.json()

    def getToken(self, path: str = "") -> Any:
        if exists(path):
            token: Object = self.readJsonFile(path)
            expiry = self.getExpiration(token.get("expires"))
            if expiry > datetime.now():
                return token.get("token")
        else:
            response = self.post(
                url="/api/v1/auth/token",
                auth=HTTPBasicAuth(self.username, self.password)
            )
            return response.get("token")
        # TODO: prompt ?
        return None

    # TODO: separate into controller

    def searchComputers(self, match: str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/computers/match/{match}"
        )
        return response

    def getComputers(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/computers"
        )
        return response

    def getComputer(self, identifier: str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/computers/id/{identifier}"
        )
        return response

    def getSites(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/sites"
        )
        return response

    # TODO: separate into controller

    def getScripts(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/scripts"
        )
        return response

    def getScript(self, identifier: str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/scripts/id/{identifier}"
        )
        return response
    
    #TODO: separate into controller
    def getComputerExtensionAttributes(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/computerextensionattributes"
        )
        return response

    # TODO: separate into controller

    def getPolicies(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/policies"
        )
        return response

    def getPolicy(self, identifier: str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/policies/id/{identifier}"
        )
        return response

    # TODO: separate into controller

    def getUsers(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/users"
        )
        return response

    def getUser(self, identifier: str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/users/id/{identifier}"
        )
        return response

    def getAccounts(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/accounts"
        )
        return response

    def getAccount(self, identifier: str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/accounts/userid/{identifier}"
        )
        return response

    def getAccountGroups(self) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/accounts"
        )
        return response

    def getGroup(self, identifier:str) -> Any:
        response = self.retrieve(
            url=f"/JSSResource/accounts/groupid/{identifier}"
        )
        return response

    def getApiRoles(self) -> Any:
        response = self.retrieve(
            url=f"/api/v1/api-roles"
        )
        return response

    def getApiClients(self) -> Any:
        response = self.retrieve(
            url=f"/api/v1/api-integrations"    
        )
        return response

    def getMe(self) -> Any:
        response = self.retrieve(
            url=f"/api/v1/auth"
        )
        return response

class Controller(JAMFService, Generic[_M, _V]):
    def __init__(self, view: _V, *ag, **kw):
        JAMFService.__init__(self, *ag, **kw)
        self.view: _V = view
        self.saveResults: bool = False
        self.results = {}
        self.collect: bool = False
        self.set(**kw)
        # self.authenticate()

class UserController(Controller[Account, AccountView]):
    dangerous = [
        "Create Accounts",
        "Update Accounts",
        "Create Policies",
        "Update Policies",
        "Create Scripts",
        "Update Scripts"
    ]
    def __init__(self, **kw):
        Controller.__init__(self, AccountView(**kw), **kw)
        self.getMyPermissions: bool = False
        self.getAccountsPermissions: bool = False
        self.getAccountPermissions: str = ""
        self.getUsersPermissions: bool = False
        self.getUserPermissions: str = ""
        self.getMySiteNames: bool = False
        self.siteFilter: str = "all"
        self.me: _M = None
        self.set(**kw)
        self.authenticate()
        self.getMe()

    # Business Logic

    def populateUser(self, account: Any) -> _M:
        try:
            uuid = f"{self.baseUrl.rstrip('/')}/JSSResource/accounts/userid/{account.get('id')}"
            privileges = account.get("privilegesBySite")
            sites = dict(list([
                (site["name"], privileges[site["id"]])
                for site in account.get("sites")
                if site["id"] in privileges
            ])) if privileges else account.get("sites", [])
            level = account.get("access_level", account.get("accessLevel"))
            permissions = account.get("privilege_set", account.get("privilegeSet"))
            if not isinstance(account, Account):
                account = Account(**account)
            account.set(
                uuid=uuid,
                accessLevel=level,
                privilegeSet=permissions,
                sites=sites
            )
        except Exception as err:
            self.view.error(err)
        return account

    def getUser(self, identifier: str) -> _M:
        try:
            user = JAMFService.getUser(self, identifier)
            attrs = user.get("account", user.get("user"))
            attrs.update(sites=attrs.get("sites", user.get("sites")))
            account = Account(
                uuid=self.lastCall,
                **attrs
            )
            return self.populateUser(account)
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"User not found")
            return None

    def getUsers(self) -> list:
        try:
            results = JAMFService.getUsers(self)
            accounts = [
                self.populateUser(self.getUser(account["id"]))
                for account in results.get("users")
            ]
            if self.saveResults:
                self.view.success(f"Saving users to users.json")
                data = Data(
                    data=[user.properties() for user in accounts],
                )
                data.meta.set(type="Account")
                self.writeJsonFile(f"users.json", data.properties())
            return accounts
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Unable to get users")
            return list()

    def getAccounts(self) -> list:
        try:
            results = JAMFService.getAccounts(self)
            accounts = [
                self.populateUser(self.getAccount(account["id"]))
                for account in results.get("accounts").get("users")
            ]
            if self.saveResults:
                self.view.success(f"Saving accounts to accounts.json")
                data = Data(
                    data=[account.properties() for account in accounts],
                )
                data.meta.set(type="Account")
                self.writeJsonFile(f"accounts.json", data.properties())
            return accounts
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Unable to get accounts")
            return list()

    #TODO: Change self.getAccount to self.getGroup, and change self.populateUser
    def getGroups(self) -> list:
        try:    
            results = JAMFService.getAccounts(self)
            accounts = [
                self.populateUser(self.getAccount(group["id"]))
                for group in results.get("accounts").get("groups")
            ]
            if self.saveResults:
                self.view.success(f"Saving groups to groups.json")
                data = Data(
                    data=[account.properties() for account in accounts],
                )
                data.meta.set(type="Group")
                self.writeJsonFile(f"groups.json", data.properties())
            return accounts
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Unable to get groups")
            return list()



    def getAccount(self, identifier: str) -> _M:
        try:
            user = JAMFService.getAccount(self, identifier)
            account = Account(
                uuid=self.lastCall,
                sites=user.get("sites"),
                **user.get("account")
            )
            return self.populateUser(account)
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Account not found")
            return None

    def getMe(self) -> _M:
        try:
            if not self.me:
                user = JAMFService.getMe(self)
                account = Account(
                    uuid=self.lastCall,
                    sites=user.get("sites"),
                    **user.get("account")
                )
                self.me = self.populateUser(account)
                if self.saveResults and not self.collect:
                    self.view.success(f"Saving account to account.json")
                    data = Data(
                        data=self.me.properties(),
                    )
                    data.meta.set(type="Account")
                    self.writeJsonFile(f"account.json", data.properties())
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Current user not found")
        return self.me

    # View Actions

    def accountsPermissions(self) -> UserController:
        accounts = self.getAccounts()
        [
            self.accountPermissions(account)
            for account in accounts
            if account is not None
        ]
        return self

    def accountPermissions(self, account: Any) -> UserController:
        account = account if isinstance(account, Account) else self.getAccount(account)
        if account is not None:
            self.view.accountPermissions(account, self.dangerous)
        return self

    def myPermissions(self) -> UserController:
        me = self.getMe()
        if me is not None:
            self.view.myPermissions(me, self.dangerous, self.siteFilter)
        return self

    def mySites(self) -> UserController:
        me = self.getMe()
        if me is not None:
            self.view.mySites(me)
        return self

    def userPermissions(self, user: Any) -> UserController:
        account = user if isinstance(user, Account) else self.getUser(user)
        if account is not None:
            self.view.accountPermissions(account, self.dangerous)
        return self

    def usersPermissions(self) -> UserController:
        accounts = self.getUsers()
        [
            self.userPermissions(account)
            for account in accounts
            if account is not None
        ]
        return self

class ComputerController(Controller[Computer, ComputerView]):
    def __init__(self, **kw):
        Controller.__init__(self, ComputerView(**kw), **kw)
        self.getJamfComputers: bool = False
        self.getJamfComputer: str = ""
        self.set(**kw)
        self.authenticate()

    # Business Logic
    def getComputer(self, identifier: str) -> _M:
        try:
            computer = JAMFService.getComputer(self, identifier)
            attrs = computer.get("computer", {})
            computer = Computer(
                uuid=self.lastCall,
                **attrs.get("general", {})
            ).set(**attrs.get("security", {}))
            computer.set(**attrs.get("location", {}))
            computer.set(**attrs.get("hardware", {}))
            try: #TODO specific error handling
                computer.set(**attrs.get("extension_attributes", {}))
            except:
                pass
            computer.set(**attrs.get("groups_accounts", {}))
            try:
                computer.set(**attrs.get("configuration_profiles", {}))
            except:
                pass
            return computer
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Computer not found")
            return None

    def getComputers(self) -> list:
        try:
            results = JAMFService.getComputers(self)
            computers = []
#                    self.getComputer(computer["id"])
#                    for computer in results.get("computers", [])
#                    if computer is not None
            for computer in results.get("computers", []):
                if computer is not None:
                    try:
                        computers.append(self.getComputer(computer["id"]))
                    except Exception as err:
                        self.view.error(f"Error for computer id: {computer["id"]}")
                        self.view.error(err)
                        self.view.failure(f"Error for computer id: {computer["id"]}")
                        self.view.failure(err)
#            ]
            if self.saveResults:
                self.view.success(f"Saving computers to computers.json")
                data = Data(
                    data=[computer.properties() for computer in computers],
                )
                data.meta.set(type="Computer")
                self.writeJsonFile(f"computers.json", data.properties())
            return computers
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Unable to get computers")
            return list()

    # View Actions

    def jamfComputers(self) -> ComputerController:
        computers = self.getComputers()
        [
            self.view.jamfComputer(computer)
            for computer in computers
            if computer is not None
        ]
        return self

    def jamfComputer(self, computer: Any) -> ComputerController:
        computer = computer if isinstance(computer, Computer) else self.getComputer(computer)
        if computer is not None:
            self.view.jamfComputer(computer)
        return self

class PolicyController(Controller[Policy, PolicyView]):
    def __init__(self, **kw):
        Controller.__init__(self, PolicyView(**kw), **kw)
        self.getJamfPolicies: bool = False
        self.getJamfPolicy: str = ""
        self.set(**kw)
        self.authenticate()

    # Business Logic
    def getPolicy(self, identifier: str) -> _M:
        try:
            computer = JAMFService.getPolicy(self, identifier)
            attrs = computer.get("policy", {})
            policy = Policy(
                uuid=self.lastCall,
                **attrs.get("general", {})
            )
            return policy
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Policy not found")
            return None

    def getPolicies(self) -> list:
        try:
            results = JAMFService.getPolicies(self)
            policies = [
                self.getPolicy(policy["id"])
                for policy in results.get("policies", [])
                if policy is not None
            ]
            if self.saveResults:
                self.view.success(f"Saving policies to policies.json")
                data = Data(
                    data=[policy.properties() for policy in policies],
                )
                data.meta.set(type="Policy")
                self.writeJsonFile(f"policies.json", data.properties())
            return policies
        except Exception as err:
            self.view.error(err)
            self.view.failure(f"Unable to get policies")
            return list()

    # View Actions

    def jamfPolicies(self) -> PolicyController:
        policies = self.getPolicies()
        [
            self.view.jamfPolicy(policy)
            for policy in policies
            if policy is not None
        ]
        return self

    def jamfPolicy(self, policy: Any) -> PolicyController:
        policy = policy if isinstance(policy, Policy) else self.getPolicy(policy)
        if policy is not None:
            self.view.jamfPolicy(policy)
        return self
