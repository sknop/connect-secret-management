import configparser
import json
import argparse
import sys

import requests


def parse_passwords(filename):
    with open(filename) as f:
        raw = f.readlines()

    content = [line.rstrip('\n') for line in raw]

    result = {}

    for i in range(0, len(content), 4):
        connector = content[i]
        user = content[i + 1]
        password = content[i + 2]
        if (i+3) < len(content) and content[i+3] != '':
            print(f"Should have an empty line between section in line {i+3}. Bailing out for safety reasons")
            sys.exit(1)
        result[connector] = (user, password)

    return result


def post(session, url, entry):
    r = session.post(url, entry)
    if r.status_code != 200:
        print(r.status_code)
        print(r.text)

def create_secrets(content, arguments):
    session = requests.Session()

    if arguments.certificate_file:
        session.verify = arguments.certificate_file
    else:
        session.verify = False

    session.auth = (arguments.username, arguments.password)
    headers = {'Content-type': 'application/json' }
    session.headers = headers

    for connector, value in content.items():
        url_username = f"{arguments.url}/secret/paths/{connector}/keys/username/versions"
        url_password = f"{arguments.url}/secret/paths/{connector}/keys/password/versions"
        
        username_entry = json.dumps({'secret': value[0]})
        password_entry = json.dumps({'secret': value[1]})

        post(session,url_username, username_entry)
        post(session,url_password, password_entry)


def ensure(args, name):
    if not hasattr(args, name) or getattr(args,name) == None:
        print(f"Argument '{name}' is required")
        sys.exit(1)


def check_arguments(args):
    ensure(args, "url")
    ensure(args, "username")
    ensure(args, "password")


def load_configfile(arguments, filename):
    config_parser = configparser.ConfigParser()
    with open(filename) as f:
        # adding [top] section since ConfigParser needs sections, but don't want them in properties file
        lines = '[top]\n' + f.read()
        config_parser.read_string(lines)

    for k, v in config_parser.items('top'):
        arguments.__setattr__(k, v)

    return arguments


def main():
    parser = argparse.ArgumentParser(description="Connect Secret Manager")

    parser.add_argument('-p', '--password-file', help="Password file", required=True)
    parser.add_argument('-c', '--config-file', help="Configuration file for URL and passwords")
    parser.add_argument('--url', help="URL of a connect instance")
    parser.add_argument('--certificate-file', help="Optional certificate file (pem format)")
    parser.add_argument('--username', help="Username")
    parser.add_argument('--password', help="Password")

    parsed_args = parser.parse_args()

    if parsed_args.config_file:
        parsed_args = load_configfile(parsed_args, parsed_args.config_file)

    check_arguments(parsed_args)

    passwords = parse_passwords(parsed_args.password_file)

    create_secrets(passwords, parsed_args)


if __name__ == '__main__':
    main()
