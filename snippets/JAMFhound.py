import argparse

from auth import get_jamf_token

def collect(args):
    if args.token:
        # perform collection
        # collect(args.url, args.token)
        ...
    else:
        # Get a token
        token = get_jamf_token(args.url, args.user, args.password)

        # perform collection
        # collect(args.url, token)


def user(args):
    if args.token:
        print(f"Fetching user data from {args.url} using token {args.token}")
    else:
        # Get a token
        token = get_jamf_token(args.url, args.user, args.password)


def computers(args):
    if args.token:
        print(f"Fetching computer data from {args.url} using token {args.token}")
    else:
        # Get a token
        token = get_jamf_token(args.url, args.user, args.password)


def main():
    parser = argparse.ArgumentParser(description="JAMFhound: A tool for interacting with JAMF data.")
    subparsers = parser.add_subparsers(title="Subcommands", dest="command")
    subparsers.required = True

    # Authentication group
    auth_group = argparse.ArgumentParser(add_help=False)
    auth_exclusive = auth_group.add_mutually_exclusive_group(required=True)
    auth_exclusive.add_argument("-u", "--user", help="Username for authentication")
    auth_exclusive.add_argument("-t", "--token", help="Token for authentication")
    auth_group.add_argument("-p", "--password", help="Password for authentication (requires -u/--user)")

    # Subcommand: collect
    parser_collect = subparsers.add_parser("collect", help="Collect general data from JAMF.", parents=[auth_group])
    parser_collect.add_argument("-U", "--url", required=True, help="URL of the JAMF instance")
    parser_collect.set_defaults(func=collect)

    # Subcommand: user
    parser_user = subparsers.add_parser("user", help="Fetch user data from JAMF.", parents=[auth_group])
    parser_user.add_argument("-U", "--url", required=True, help="URL of the JAMF instance")
    parser_user.set_defaults(func=user)

    # Subcommand: computers
    parser_computers = subparsers.add_parser("computers", help="Fetch computer data from JAMF.", parents=[auth_group])
    parser_computers.add_argument("-U", "--url", required=True, help="URL of the JAMF instance")
    parser_computers.set_defaults(func=computers)

    # Parse the arguments
    args = parser.parse_args()

    # Validate dependencies between --user and --password
    if args.user and not args.password:
        parser.error("--password is required when using --user")
    
    args.func(args)

if __name__ == "__main__":
    main()
