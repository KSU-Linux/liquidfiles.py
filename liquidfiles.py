#!/usr/bin/env python3

import argparse
import configparser
import datetime
import json
import os 
import requests
import sys

# List of configuration files to read from as
# well as the order in which they are prioritized
CONFIG_FILES = [
    '/etc/liquidfiles.conf',
    '/usr/local/etc/liquidfiles.conf',
    os.path.expanduser("~") + '/.liquidfiles.conf'
]

# Default expiration for filelinks and messages
DEFAULT_EXPIRES = (datetime.datetime.now() + datetime.timedelta(days=7)).strftime("%Y-%m-%d")

# Global API key and server settings
API_KEY = None
SERVER = None

# Application version
VERSION = '0.0.4'

# Reads user config file and prints output
def config_print():
    configfile = os.path.expanduser("~") + '/.liquidfiles.conf'
    config = configparser.ConfigParser()
    config.read(configfile)
    if config.has_section("config"):
        print ("[config]")
        for (key, value) in config.items("config"):
            print(key + " = " + value)
    sys.exit(0)

# Saves user config file. Only saves settings provided
def config_set(api_key=None, server=None):
    configfile = os.path.expanduser("~") + '/.liquidfiles.conf'
    config = configparser.ConfigParser()
    config.read(configfile)
    if not config.has_section("config"):
        config.add_section("config")
    if api_key:
        config.set("config", "api_key", api_key)
    if server:
        config.set("config", "server", server)
    with open(configfile, 'w') as f:
        config.write(f)

# This is used as an ArgParser type in order to verify
# that the user provided a properly formated date
def expire_date(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        msg = "not a valid date: {0!r}".format(s)
        raise argparse.ArgumentTypeError(msg)

# Uses the LiquidFiles Attachment API to upload a file to the
# server. See https://man.liquidfiles.com/api/attachments
def liquidfiles_attach(server, api_key, filename):
    api_url = server + '/attachments/binary_upload'
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    data = open(filename, "rb")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    params = {
        "filename": os.path.basename(filename),
    }
    response = requests.post(
        api_url,
        params=params,
        headers=headers,
        auth=auth,
        data=data
    )
    response_json = process_response(response)
    return response_json

# Uses the LiquidFiles Messages API to list available attachments.
# See https://man.liquidfiles.com/api/attachments/
def liquidfiles_attachments(server, api_key):
    api_url = server + '/attachments'
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = requests.get(
        api_url,
        headers=headers,
        auth=auth,
    )
    response_json = process_response(response)
    return response_json

# Uses the LiquidFiles FileLink API to delete attachments.
# See https://man.liquidfiles.com/api/attachments/delete.html
def liquidfiles_delete_attachments(server, api_key, attachment_ids):
    api_url = server + '/attachments/'
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    for attachment_id in attachment_ids:
        response = requests.delete(
            api_url + attachment_id,
            headers=headers,
            auth=auth,
        )
        # Process response manually since the API does not
        # return JSON output for this call
        if response.status_code == requests.codes.ok:
            print("Success - The Attachment with ID %s was deleted" % attachment_id)
        elif response.status_code == requests.codes.unauthorized:
            response.raise_for_status()
        elif response.status_code == requests.codes.not_found:
            print("404: Not Found - The Attachment ID wasn't found.", file=sys.stderr)
            sys.exit(1)
        elif response.status_code == requests.codes.unprocessable:
            print("Not Permitted - The Request wasn't permitted.", file=sys.stderr)
            sys.exit(1)
        elif response.status_code == requests.codes.internal_server_error:
            response.raise_for_status()
        else:
            print("Unknown - An unknown error ocurred.", file=sys.stderr)
            sys.exit(1)

# Uses the LiquidFiles FileLink API to delete FileLinks.
# See https://man.liquidfiles.com/api/filelink_api.html#delete
def liquidfiles_delete_filelink(server, api_key, filelink_id):
    api_url = server + '/link/' + filelink_id.pop()
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = requests.delete(
        api_url,
        headers=headers,
        auth=auth,
    )
    # Process response manually since the API does not
    # return JSON output for this call
    if response.status_code == requests.codes.ok:
        print("Success - The FileLink was deleted")
    elif response.status_code == requests.codes.unauthorized:
        response.raise_for_status()
    elif response.status_code == requests.codes.not_found:
        print("404: Not Found - The FileLink ID wasn't found.", file=sys.stderr)
        sys.exit(1)
    elif response.status_code == requests.codes.unprocessable:
        print("Not Permitted - The Request wasn't permitted.", file=sys.stderr)
        sys.exit(1)
    elif response.status_code == requests.codes.internal_server_error:
        response.raise_for_status()
    else:
        print("Unknown - An unknown error ocurred.", file=sys.stderr)
        sys.exit(1)

# Uses the LiquidFiles FileLink API to create a new FileLink.
# See https://man.liquidfiles.com/api/filelink_api.html
def liquidfiles_filelink(server, api_key, expires, is_id, password, download_receipt, require_authentication, filename):
    api_url = server + '/link'
    attachment_id = ''
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if is_id:
        attachment_id = filename.pop()
    else:
        response = liquidfiles_attach(server, api_key, filename.pop())
        attachment_id = response["attachment"]["id"]

    data = {
        "link": {
            "attachment": attachment_id,
            "expires_at": expires,
            "download_receipt": download_receipt,
            "require_authentication": require_authentication,
        }
    }

    if password:
        data["link"]["password"] = password

    response = requests.post(
        api_url,
        headers=headers,
        auth=auth,
        data=json.dumps(data)
    )
    response_json = process_response(response)
    return response_json

# Uses the LiquidFiles Messages API to list available FileLinks.
# See https://man.liquidfiles.com/api/filelink_api.html#list
def liquidfiles_filelinks(server, api_key):
    api_url = server + '/link'
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = requests.get(
        api_url,
        headers=headers,
        auth=auth,
    )
    response_json = process_response(response)
    return response_json

# Uses the LiquidFiles File Requests API to request a file.
# See https://man.liquidfiles.com/api/file_request_api.html
def liquidfiles_file_request(server, api_key, expires, to, subject, message, message_file):
    api_url = server + '/requests'
    attachment_ids = []
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if message_file:
        with open(message_file, 'r') as f:
            message_body = f.read()
    else:
        message_body = message

    data = {
        "request": {
            "recipient": to,
            "subject": subject,
            "message": message_body,
            "send_email": True,
            "expires_at": expires,
            "multiuse": False,
            "bcc_myself": False,
        }
    }
    response = requests.post(
        api_url,
        headers=headers,
        auth=auth,
        data=json.dumps(data)
    )
    response_json = process_response(response)
    return response_json

# Uses the LiquidFiles Messages API to show client information.
# See https://man.liquidfiles.com/api/client_info_request.html
def liquidfiles_info(server, api_key):
    api_url = server + '/account'
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = requests.get(
        api_url,
        headers=headers,
        auth=auth,
    )
    response_json = process_response(response)
    return response_json

# Uses the LiquidFiles Messages API to list messages sent to you.
# See https://man.liquidfiles.com/api/messages/list_messages_and_download_attachments.html
def liquidfiles_messages(server, api_key):
    api_url = server + '/messages/inbox'
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = requests.get(
        api_url,
        headers=headers,
        auth=auth,
    )
    response_json = process_response(response)
    return response_json
    
# Uses the LiquidFiles Message API to upload given files and
# send a secure message. See https://man.liquidfiles.com/api/messages
def liquidfiles_send(server, api_key, expires, to, subject, message, message_file, file_type, filenames):
    api_url = server + '/message'
    attachment_ids = []
    auth = requests.auth.HTTPBasicAuth(api_key, 'x')
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if message_file:
        with open(message_file, 'r') as f:
            message_body = f.read()
    else:
        message_body = message

    if file_type == 'file_names':
        for file in filenames:
            response = liquidfiles_attach(server, api_key, file)
            attach_id = response["attachment"]["id"]
            attachment_ids.append(attach_id)
    elif file_type == 'directory':
        files = []
        for d in filenames:
            for f in os.listdir(d):
                f = os.path.join(d, f)
                if os.path.isfile(f):
                    files.append(f)
        for file in files:
            response = liquidfiles_attach(server, api_key, file)
            attach_id = response["attachment"]["id"]
            attachment_ids.append(attach_id)
    elif file_type == 'attachments':
        attachment_ids = filenames

    data = {
        "message": {
            "recipients": to.split(","),
            "subject": subject,
            "message": message_body,
            "expires_at": expires,
            "expires_after": 0,
            "send_email": True,
            "bcc_myself": False,
            "private_message": False,
            "authorization": 3,
            "attachments": attachment_ids,
        }
    }
    response = requests.post(
        api_url,
        headers=headers,
        auth=auth,
        data=json.dumps(data)
    )
    response_json = process_response(response)
    return response_json

# Takes unparsed command-line arguments and parses them
# using ArgumentParser. Returns the parsed arguments
def parse_args(unparsed_args):
    # Arguments that are shared across all sub-commands
    shared_parser = argparse.ArgumentParser(add_help=False)
    shared_parser.add_argument(
            '-k', '--api_key',
            dest='api_key',
            action='store',
            type=str,
            metavar='API_KEY',
            help='API key for LiquidFiles'
            )
    shared_parser.add_argument(
            '-s', '--server',
            dest='server',
            action='store',
            type=str,
            metavar='URL',
            help='url to the LiquidFiles server'
            )

    parser = argparse.ArgumentParser(
            description='command-line interface for LiquidFiles server',
            parents=[shared_parser]
            )

    subparsers = parser.add_subparsers(dest='command')

    # The 'attach' sub-command arguments
    attach_parser = subparsers.add_parser('attach', help='upload given files and returns the ids')
    attach_parser.add_argument(
            'file',
            nargs='+',
            help='file path to upload'
            )

    # The 'attachments' sub-command arguments
    attachents_parser = subparsers.add_parser('attachments', help='list available attachments')
 
    # The 'config' sub-command arguments
    config_parser = subparsers.add_parser('config', help='manage configuration')
    config_parser.add_argument(
            '-p', '--print',
            dest='print',
            action='store_true',
            default=False,
            help='print configuration'
            )
    config_parser.add_argument(
            '--set-api-key',
            dest='set_api_key',
            action='store',
            metavar='API_KEY',
            help='configure api key'
            )
    config_parser.add_argument(
            '--set-server',
            dest='set_server',
            action='store',
            metavar='SERVER',
            help='configure server'
            )

    # The 'delete-attachments' sub-command arguments
    delete_attachments_parser = subparsers.add_parser('delete-attachments', help='deletes the given attachments')
    delete_attachments_parser.add_argument(
            'attachment_ids',
            metavar='id',
            nargs='+',
            help='id of attachment to delete'
            )

    # The 'delete-filelink' sub-command arguments
    delete_filelink_parser = subparsers.add_parser('delete-filelink', help='deletes the given filelink')
    delete_filelink_parser.add_argument(
            'filelink_id',
            metavar='id',
            nargs=1,
            help='id of filelink to delete'
            )

    # The 'filelink' sub-command arguments
    filelink_parser = subparsers.add_parser('filelink', help='creates filelink for the given files')
    filelink_parser.add_argument(
            '--expires',
            dest='expires',
            action='store',
            default=DEFAULT_EXPIRES,
            metavar='YYYY-MM-DD',
            type=expire_date,
            help='expire date for the message (default: %(default)s)'
            )
    filelink_parser.add_argument(
            '--is-id',
            dest='is_id',
            action='store_true',
            default=False,
            help='if specified, then file is treated as an attachment id'
            )
    filelink_parser.add_argument(
            '--no-auth',
            dest='require_authentication',
            action='store_false',
            default=True,
            help='disable authentication when downloading a file'
            )
    filelink_parser.add_argument(
            '--no-receipt',
            dest='download_receipt',
            action='store_false',
            default=True,
            help='do not send download receipts when someone downloads a file'
            )
    filelink_parser.add_argument(
            '--password',
            dest='password',
            action='store',
            default=None,
            help='set a password before downloading of the filelink'
            )
    filelink_parser.add_argument(
            'file',
            nargs=1,
            help='file path or attachment id to create filelink'
            )

    # The 'filelinks' sub-command arguments
    filelinks_parser = subparsers.add_parser('filelinks', help='list available filelinks')

    # The 'file-request' sub-command arguments
    file_request_parser = subparsers.add_parser('file-request', help='send file request to specified user')
    file_request_parser.add_argument(
            '--expires',
            dest='expires',
            action='store',
            default=DEFAULT_EXPIRES,
            metavar='YYYY-MM-DD',
            type=expire_date,
            help='expire date for the message (default: %(default)s)'
            )
    file_request_parser_message_group = file_request_parser.add_mutually_exclusive_group()
    file_request_parser_message_group.add_argument(
            '--message',
            dest='message',
            action='store',
            metavar='MSG',
            help='message of composed email'
            )
    file_request_parser_message_group.add_argument(
            '--message-file',
            dest='message_file',
            action='store',
            metavar='FILE',
            help='file containing message of composed email'
            )
    file_request_parser.add_argument(
            '--subject',
            dest='subject',
            action='store',
            metavar='SUB',
            help='subject of composed email'
            )
    file_request_parser.add_argument(
            '--to',
            dest='to',
            action='store',
            required=True,
            help='username or email address to send a file to'
            )

    # The 'info' sub-command arguments
    info_parser = subparsers.add_parser('info', help='show client information')
 
    # The 'messages' sub-command arguments
    messages_parser = subparsers.add_parser('messages', help='list available messages')

    # The 'send' sub-command arguments
    send_parser = subparsers.add_parser('send', help='send file(s) to specified user')
    send_parser.add_argument(
            '--expires',
            dest='expires',
            action='store',
            default=DEFAULT_EXPIRES,
            metavar='YYYY-MM-DD',
            type=expire_date,
            help='expire date for the message (default: %(default)s)'
            )
    send_parser.add_argument(
            '--file-type',
            dest='file_type',
            choices=['file_names', 'directory', 'attachments'],
            default='file_names',
            metavar='TYPE',
            help='type of files being sent [%(choices)s] (default: %(default)s)'
            )
    send_parser_message_group = send_parser.add_mutually_exclusive_group()
    send_parser_message_group.add_argument(
            '--message',
            dest='message',
            action='store',
            metavar='MSG',
            help='message of composed email'
            )
    send_parser_message_group.add_argument(
            '--message-file',
            dest='message_file',
            action='store',
            metavar='FILE',
            help='file containing message of composed email'
            )
    send_parser.add_argument(
            '--subject',
            dest='subject',
            action='store',
            metavar='SUB',
            help='subject of composed email'
            )
    send_parser.add_argument(
            '--to',
            dest='to',
            action='store',
            required=True,
            help='username or email address to send a file to'
            )
    send_parser.add_argument(
            'file',
            nargs='+',
            help='file path(s),  attachments IDs or directories to send to user'
            )

    # The 'version' sub-command arguments
    version_parser = subparsers.add_parser('version', help='show version information')

    if len(unparsed_args) == 0:
        parser.print_help()

    parsed_args = parser.parse_args(args=unparsed_args)
    return parsed_args

# Takes the already parsed arguments and performs actions
# based on what was provided
def process_args(args):
    global API_KEY
    global SERVER
    global VERSION

    # Set the API key and server if they were provided
    # as command-line arguments
    if args.api_key:
        API_KEY = args.api_key
    if args.server:
        SERVER = args.server

    # Verify API_KEY and SERVER are set
    if args.command != 'config':
        if not API_KEY:
            print("Error - API key is required.", file=sys.stderr)
            sys.exit(1)
        elif not SERVER:
            print("Error - Server is required.", file=sys.stderr)
            sys.exit(1)

    # Check which sub-command was used and process accordingly
    if args.command == 'attach':
        for f in args.file:
            response = liquidfiles_attach(
                    server=SERVER,
                    api_key=API_KEY,
                    filename=f)
            print(json.dumps(response, indent=4))
    if args.command == 'attachments':
        response = liquidfiles_attachments(
                server=SERVER,
                api_key=API_KEY,
                )
        print(json.dumps(response, indent=4))

    if args.command == 'config':
        if args.set_api_key or args.set_server:
            config_set(
                    api_key=args.set_api_key,
                    server=args.set_server
                    )
        else:
            config_print()
    if args.command == 'delete-attachments':
        liquidfiles_delete_attachments(
                server=SERVER,
                api_key=API_KEY,
                attachment_ids=args.attachment_ids
                )
    if args.command == 'delete-filelink':
        liquidfiles_delete_filelink(
                server=SERVER,
                api_key=API_KEY,
                filelink_id=args.filelink_id
                )
    if args.command == 'filelink':
        response = liquidfiles_filelink(
                server=SERVER,
                api_key=API_KEY,
                expires=args.expires,
                is_id=args.is_id,
                password=args.password,
                download_receipt=args.download_receipt,
                require_authentication=args.require_authentication,
                filename=args.file
                )
        print(json.dumps(response, indent=4))
    if args.command == 'filelinks':
        response = liquidfiles_filelinks(
                server=SERVER,
                api_key=API_KEY,
                )
        print(json.dumps(response, indent=4))
    if args.command == 'file-request':
        response = liquidfiles_file_request(
                server=SERVER,
                api_key=API_KEY,
                expires=args.expires,
                to=args.to,
                subject=args.subject,
                message=args.message,
                message_file=args.message_file,
                )
        print(json.dumps(response, indent=4))
    if args.command == 'info':
        response = liquidfiles_info(
                server=SERVER,
                api_key=API_KEY,
                )
        print(json.dumps(response, indent=4))
    if args.command == 'messages':
        response = liquidfiles_messages(
                server=SERVER,
                api_key=API_KEY,
                )
        print(json.dumps(response, indent=4))
    if args.command == 'send':
        response = liquidfiles_send(
                server=SERVER,
                api_key=API_KEY,
                expires=args.expires,
                to=args.to,
                subject=args.subject,
                message=args.message,
                message_file=args.message_file,
                file_type=args.file_type,
                filenames=args.file
                )
        print(json.dumps(response, indent=4))
    if args.command == 'version':
        print(VERSION)

# Reads in settings from all available config files
def process_config():
    global API_KEY
    global SERVER
    config = configparser.ConfigParser()
    for configfile in CONFIG_FILES:
        config.read(configfile)
        if not config.has_section('config'):
            continue
        if config.has_option('config', 'api_key'):
            API_KEY = config.get('config', 'api_key')
        if config.has_option('config', 'server'):
            SERVER = config.get('config', 'server')

# Takes a requests response and verifies it. Returns the
# json output from the server's response
def process_response(response):
    if response.status_code == requests.codes.unauthorized or \
       response.status_code == requests.codes.internal_server_error:
        response.raise_for_status()

    response_json = response.json()

    # LiquidFiles provides error messages in its JSON output
    # if it is unable to process your request (422). This may happen
    # when, for example, you set a file expiration date beyond
    # what the system allows you to
    if response.status_code == requests.codes.unprocessable:
        for e in response_json["errors"]:
            print(e, file=sys.stderr)
        sys.exit(1)

    return response_json

if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    process_config()
    process_args(args)
    sys.exit(0)
