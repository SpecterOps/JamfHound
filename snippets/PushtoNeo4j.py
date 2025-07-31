import json
from neo4j import GraphDatabase

# Neo4j connection setup
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "pass"))

# Load JSON data
def load_json(filepath):
    with open(filepath, "r") as file:
        return json.load(file)

# Add Account nodes
def add_account_nodes(data):
    with driver.session() as session:
        for entry in data["data"]:
            account = entry["Properties"]
            uuid = account["uuid"]
            name = account["name"]
            privilege_set = account.get("privilegeSet", [])

            privileges = account.get("privileges", {}).get("jss_objects", [])

            # If "Update Accounts" exists, connect to all other accounts
            update_accounts = ""
            if "Update Accounts" in privileges:
                update_accounts = "Update Accounts"
            # Create Account node
            session.run(
                """
                MERGE (a:Account {uuid: $uuid})
                SET a.name = $name, a.privilegeSet = $privilege_set, a.privilege = $privilege
                """,
                {"uuid": uuid, "name": name, "privilege_set": privilege_set, "privilege": update_accounts }
            )

# Add Tenant node
def add_tenant_nodes(data):
    with driver.session() as session:
        for entry in data["data"]:
            tenant = entry["Properties"]
            uuid = tenant["uuid"]
            name = tenant["tenant"]

            # Create Tenant node
            session.run(
                """
                MERGE (t:Tenant {uuid: $uuid})
                SET t.name = $name
                """,
                {"uuid": uuid, "name": name}
            )

# Add CAN_SET_ADMIN edges for accounts with "Update Accounts"
def add_account_edges(data):
    with driver.session() as session:
        for entry in data["data"]:
            account = entry["Properties"]
            uuid = account["uuid"]
            privileges = account.get("privileges", {}).get("jss_objects", [])

            # If "Update Accounts" exists, connect to all other accounts
            if "Update Accounts" in privileges:
                for other_entry in data["data"]:
                    other_account = other_entry["Properties"]
                    other_uuid = other_account["uuid"]

                    # Avoid self-loops
                    if uuid != other_uuid:
                        session.run(
                            """
                            MATCH (a1:Account {uuid: $uuid}), (a2:Account {uuid: $other_uuid})
                            MERGE (a1)-[:CAN_SET_ADMIN]->(a2)
                            """,
                            {"uuid": uuid, "other_uuid": other_uuid}
                        )

# Add HAS_FULL_CONTROL edges for accounts with "Administrator" privilege
def add_tenant_control_edges(account_data, tenant_data):
    with driver.session() as session:
        for entry in account_data["data"]:
            account = entry["Properties"]
            uuid = account["uuid"]
            privilege_set = account.get("privilegeSet", [])

            # If "Administrator" exists in privilegeSet, create HAS_FULL_CONTROL relationship
            if "Administrator" in privilege_set:
                for tenant_entry in tenant_data["data"]:
                    tenant = tenant_entry["Properties"]
                    tenant_uuid = tenant["uuid"]

                    session.run(
                        """
                        MATCH (a:Account {uuid: $uuid}), (t:Tenant {uuid: $tenant_uuid})
                        MERGE (a)-[:HAS_FULL_CONTROL]->(t)
                        """,
                        {"uuid": uuid, "tenant_uuid": tenant_uuid}
                    )

def add_computers_control_edges(account_data, tenant_data, computer_data):
        with driver.session() as session:
            for entry in account_data["data"]:
                account = entry["Properties"]
                uuid = account["uuid"]
                privilege_set = account.get("privilegeSet", [])

                # If "Administrator" exists in privilegeSet, create HAS_FULL_CONTROL relationship
                if "Administrator" in privilege_set:
                    for computer_entry in computer_data["data"]:
                        computer = computer_entry["Properties"]
                        computer_uuid = computer["uuid"]

                        session.run(
                            """
                            MATCH (a:Account {uuid: $uuid}), (c:Computer {uuid: $computer_uuid})
                            MERGE (a)-[:HAS_FULL_CONTROL]->(c)
                            """,
                            {"uuid": uuid, "computer_uuid": computer_uuid}
                        )


# Add computer nodes
def add_computer_nodes(data):
    with driver.session() as session:
        for entry in data["data"]:
            computer = entry["Properties"]
            uuid = computer["uuid"]
            name = computer["name"]
            local_ip = computer["last_reported_ip"]
            last_contact_time = computer["last_contact_time"]  # Correct assignment

            session.run(
                """
                MERGE (c:Computer {uuid: $uuid})
                SET c.name = $name, c.local_ip = $local_ip, c.last_contact_time = $last_contact_time
                """,
                {"uuid": uuid, "name": name, "local_ip": local_ip, "last_contact_time": last_contact_time}
            )


# Main function
def main():
    # Load data from JSON
    account_json_path = "./snippet.json"
    tenant_json_path = "./tenant.json"
    computers_json_path = "./computers.json"

    account_data = load_json(account_json_path)
    tenant_data = load_json(tenant_json_path)
    computer_data = load_json(computers_json_path)

    # Add nodes and edges
    add_account_nodes(account_data)
    add_tenant_nodes(tenant_data)
    add_computer_nodes(computer_data)
    add_account_edges(account_data)
    add_tenant_control_edges(account_data, tenant_data)
    add_computers_control_edges(account_data, tenant_data, computer_data)

if __name__ == "__main__":
    main()
