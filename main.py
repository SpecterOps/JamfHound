#!/usr/bin/env python3
from __future__ import annotations
from argparse import (
    ArgumentParser as Parser,
    Namespace
)
from lib.services import (
    UserController,
    ComputerController,
    PolicyController,
    JAMFService
)

from lib.preprocess import Preprocessor, checkAzureUsers
import json
import os
from datetime import datetime

def main():
    parser: Parser = Parser(
        description="JAMFhound: A BloodHound generic data collector for JAMF tenants.",
        add_help=True
    )
    parser.add_argument(
        "--username", "--username", "-u",
        dest="username",
        type=str,
        # default="jd",
        default="",
        action="store",
        help="Username for authentication"
    )
    parser.add_argument(
        "--password", "-p",
        dest="password",
        type=str,
        default="",
        action="store",
        help="Password for authentication"
    )
    parser.add_argument(
        "--token", "-t",
        dest="token",
        type=str,
        default="",
        action="store",
        help="Token file to use in place of credentials"
    )
    parser.add_argument(
        "--target", "--api", "--url", "-a",
        dest="baseUrl",
        type=str,
        default="https://tenant.jamfcloud.com",
        action="store",
        help="Base url of target API"
    )
    parser.add_argument(
        "--permission", "-permission", "-me ",
        dest="getMyPermissions",
        default=False,
        action="store_true",
        help="Display current users permissions"
    )
    parser.add_argument(
        "--accounts", "-accounts",
        dest="getAccountsPermissions",
        default=False,
        action="store_true",
        help="Display all account permissions"
    )
    parser.add_argument(
        "--account", "-account",
        dest="getAccountPermissions",
        default="",
        action="store",
        help="Display account permissions by name"
    )
    parser.add_argument(
        "--users", "-users",
        dest="getUsersPermissions",
        default=False,
        action="store_true",
        help="Display all user permissions"
    )
    parser.add_argument(
        "--user", "-user",
        dest="getUserPermissions",
        default="",
        action="store",
        help="Display user permissions by name"
    )
    parser.add_argument(
        "--site", "--site", "-s",
        dest="siteFilter",
        type=str,
        default="all",
        action="store",
        help="Filter site permissions"
    )
    parser.add_argument(
        "--sites", "--sites",
        dest="getMySiteNames",
        default=False,
        action="store_true",
        help="Retrieve site names"
    )
    parser.add_argument(
        "--computers", "-computers",
        dest="getJamfComputers",
        default=False,
        action="store_true",
        help="Display all computers"
    )
    parser.add_argument(
        "--computer", "-computer",
        dest="getJamfComputer",
        default="",
        action="store",
        help="Display computer by ID"
    )
    parser.add_argument(
        "--policies", "-policies",
        dest="getJamfPolicies",
        default=False,
        action="store_true",
        help="Display all policies"
    )
    parser.add_argument(
        "--policy", "-policy",
        dest="getJamfPolicy",
        default="",
        action="store",
        help="Display policy by ID"
    )
    parser.add_argument(
        "--verbose", "-v",
        dest="verbose",
        default=False,
        action="store_true",
        help="Display verbose output"
    )
    parser.add_argument(
        "--throw", "-throw",
        dest="throw",
        default=False,
        action="store_true",
        help="Throw all exceptions"
    )
    parser.add_argument(
        "--save", "-save",
        dest="saveResults",
        default=False,
        action="store_true",
        help="Save results in JSON format"
    )

    parser.add_argument(
    "--collect", "-collect",
    dest="collect",
    default=False,
    action="store_true",
    help="Runs a collection of JAMF resources and saves the output as JSON for generic ingest into BloodHound."
    )

    parser.add_argument(
    "--checkAzureUsers", "-checkAzureUsers",
    dest="checkAzureUsers",
    type=str,
    default="",    
    action="store",
    help="Compares an AzureHound collection against a JamfHound collection to determine if any Azure accounts match JAMF principals. Requires the additional JAMFcollection argument with path to the JSON to compare."
    )

    parser.add_argument(
    "--JAMFcollection", "-JAMFcollection",
    dest="JAMFcollection",
    type=str,
    default="",
    action="store",
    help="Path to the additional JAMFcollection JSON file to use for processing."
    )

    args = parser.parse_args()
    if not ((args.username and args.password) or args.token or (args.checkAzureUsers and args.JAMFcollection)):
        if args.checkAzureUsers or args.JAMFcollection:
            parser.error("checkAzureUsers and JAMFcollection arguments require both arguments to be provided if either one is used")
        else:
            parser.error("Missing credentials or token file")

    # collection
    if args.collect:
        # Get current time and format it
        timestamp = datetime.now().strftime("Collection_%Y_%m_%d_%H_%M_%S")
        # Create collection directory
        os.makedirs(timestamp, exist_ok=True)
        # Change the current working directory
        os.chdir(timestamp)
        # Set save results to true
        args.saveResults = True
        # Set up initial controller
        ctl = UserController(**args.__dict__)
        # Print directory message
        ctl.view.success(f"Created collection directory: {timestamp}")

        # Collect accounts and users first
        try:
            ctl.getAccounts()
        except Exception as e:
            ctl.view.error(e)
            ctl.view.failure(f"Failed to collect accounts: {e}")
        # Collect Computers
        try:
            cptrs = ComputerController(**args.__dict__)
            cptrs.getComputers()
        except Exception as e:
            cptrs.view.error(e)
            cptrs.view.failure(f"Failed to collect computers: {e}")
        # Sites
        try:
            jservice = JAMFService(**args.__dict__)
            jservice.authenticate()
            cptrs.view.success("Saving sites to sites.json") #TODO either write a sites controller or stop using controllers and pass directly for processing
            sites = jservice.getSites()
            jservice.writeJsonFile("sites.json", sites)
        except Exception as e:
            cptrs.view.error(e)
            cptrs.view.failure(f"Failed to collect sites: {e}")
        # Collect account groups TODO: Move these actions to controller or services.py internal method calls
        try:
            agroups = jservice.getAccountGroups()
            groups = []
            for group in agroups.get("accounts").get("groups"):
                groups.append(jservice.getGroup(group.get("id")))
            group_out = {}
            group_out["Groups"] = groups
            jservice.writeJsonFile("groups.json", group_out)
            cptrs.view.success("Saving groups to groups.json")
        except Exception as e: 
            cptrs.view.error(e)
            cptrs.view.failure(f"Failed to collect groups: {e}")
        #TODO: Collect Policies to determine if any scripts are recurring/can be updated alone
        try:
            pols = PolicyController(**args.__dict__)
            pols.getPolicies()
        except Exception as e:
            pols.view.error(e)
            pols.view.failure(f"Failed to collect policies: {e}")
        # Collect Scripts
        try:
            scripts = jservice.getScripts()
            cptrs.view.success("Saving scripts to scripts.json") #TODO either write a sites controller or stop using controllers and pass directly for processing
            jservice.writeJsonFile("scripts.json", scripts)
        except Exception as e:
            cptrs.view.error(e)
            cptrs.view.failure(f"Failed to collect scripts: {e}")   
        # Api Clients and Roles Collection
        try:
            apiRoles = jservice.getApiRoles()
            jservice.writeJsonFile("apiroles.json", apiRoles)
        except Exception as e:
            cptrs.view.error(e)
            cptrs.view.failure(f"Failed to collect API roles: {e}")
        try:
            apiClients = jservice.getApiClients()
            jservice.writeJsonFile("apiclients.json", apiClients)
            cptrs.view.success("Saving api roles and clients to apiroles.json and apiclients.json")
        except Exception as e:
            cptrs.view.error(e)
            cptrs.view.failure(f"Failed to collect API clients: {e}")
        # Preprocessing to create JSON to import into BloodHound
        jamfPreprocessor = Preprocessor(args.baseUrl)
        jamfPreprocessor.process_nodes()
        cptrs.view.success(jamfPreprocessor.write_out_collection(jservice))
        return

    if args.checkAzureUsers:
        checkAzureUsers(args.checkAzureUsers, args.JAMFcollection)
        return

    # policies
    if args.getJamfPolicy or args.getJamfPolicies:
        ctl = PolicyController(**args.__dict__)
        if ctl.getJamfPolicies:
            ctl.jamfPolicies()
        elif ctl.getJamfPolicy:
            ctl.jamfPolicy(ctl.getJamfPolicy)
        return

    # computers
    if args.getJamfComputer or args.getJamfComputers:
        ctl = ComputerController(**args.__dict__)
        if ctl.getJamfComputers:
            ctl.jamfComputers()
        elif ctl.getJamfComputer:
            ctl.jamfComputer(ctl.getJamfComputer)
        return

    # users
    ctl = UserController(**args.__dict__)
    if ctl.getMyPermissions:
        ctl.myPermissions()
    elif ctl.getAccountsPermissions:
        ctl.accountsPermissions()
    elif ctl.getMySiteNames:
        ctl.mySites()
    elif ctl.getUsersPermissions:
        ctl.usersPermissions()
    elif ctl.getAccountPermissions:
        ctl.accountPermissions(ctl.getAccountPermissions)
    elif ctl.getUserPermissions:
        ctl.userPermissions(ctl.getUserPermissions)
    return


if __name__ == "__main__":
    main()
