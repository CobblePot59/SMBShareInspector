import json
import asyncio
from argparse import ArgumentParser
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from SMBShareInspector.DescribeSDDL import parse_SDDL

RED = '\033[91m'
RESET = '\033[0m'

users_to_highlight = ["everyone", "anonymous", "authenticated user", "guest"]

async def handle_share(smb_url):
    try:
        smb_mgr = SMBConnectionFactory.from_url(smb_url)
        connection = smb_mgr.create_connection_newtarget(smb_mgr.get_target().get_hostname_or_ip())

        async with connection:
            _, err = await connection.login()
            if err is not None:
                raise err

            machine = SMBMachine(connection)
            async for obj, otype, err in machine.enum_all_recursively(depth=1, fetch_share_sd=True):
                if err:
                    print(f'Error : {err}')
                    continue

                if otype == 'share':
                    security_descriptor = obj.security_descriptor.to_sddl() if obj.security_descriptor else 'No SDDL'
                    json_sd = parse_SDDL(security_descriptor)

                    print(f'[+] Listing ACL for share: {obj.unc_path}')
                    
                    if "DACL" in json_sd:
                        print("[")

                        for ace in json_sd["DACL"]:
                            ace_json = json.dumps(ace, indent=4)
                            if any(user.lower() in ace['SID'].lower() for user in users_to_highlight):
                                print(f"{RED}{ace_json}{RESET},")
                            else:
                                print(f"{ace_json},")
                        
                        print("]")
    finally:
        await connection.disconnect()

def parse_arguments():
    parser = ArgumentParser(description='Process some arguments')
    parser.add_argument('-d', '--domain', required=True, help='Domain name of the target system.')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication.')
    parser.add_argument('-p', '--password', help='Password for authentication.')
    parser.add_argument('-H', '--hashes', help='Hashes for authentication.')
    parser.add_argument('--aes', help='AES for authentication.')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use kerberos instead of NTLM.')
    parser.add_argument('ip_address', help='Name of the Domain Controller.')
    args = parser.parse_args()
    return args

def parse_url(domain, username, hashes, aes_key, password, do_kerberos, ip_address):
    auth = 'kerberos-password' if do_kerberos and not aes_key and not hashes else 'ntlm-password'
    subdomain = domain.split('.')[0]

    if hashes:
        password, auth = hashes.split(':')[1], 'kerberos-rc4' if do_kerberos else 'ntlm-nt'
    if aes_key:
        password, auth = aes_key, 'kerberos-aes'
    return f"smb+{auth}://{subdomain}\\{username}:{password}@{ip_address}/?dc={ip_address}"

async def amain():
    from getpass import getpass

    args = parse_arguments()
    domain = args.domain
    username = args.username
    hashes = args.hashes
    aes_key = args.aes
    password = args.password or hashes or aes_key or getpass('Password :')
    do_kerberos = args.kerberos
    ip_address = args.ip_address

    url = parse_url(domain, username, hashes, aes_key, password, do_kerberos, ip_address)
    await handle_share(url)

def main():
    asyncio.run(amain())

if __name__ == '__main__':
    main()