#!/usr/bin/env python3

from criptam.decrypt import Decrypt
from criptam.device import Device
from criptam.ipsw import IPSW
from importlib.metadata import version

import argparse
import platform
import requests
import sys

__version__ = version(__package__)

RELEASE_API = 'https://api.ipsw.me/v4/device'
BETA_API = 'https://api.m1sta.xyz/betas'


def main():
    parser = argparse.ArgumentParser(
        description=f'Criptam {__version__} - iOS firmware key decrypter',
        usage="criptam -b 'buildid'",
    )

    parser.add_argument('-b', '--buildid', help='iOS build to decrypt keys for')
    args = parser.parse_args()

    if not args.buildid:
        sys.exit(parser.print_help(sys.stderr))

    if platform.system() == 'Windows':
        sys.exit('[ERROR] Windows systems are not supported. Exiting.')

    print(f'Criptam {__version__}')
    device = Device()

    buildid = args.buildid.upper()
    print(f'\nGetting IPSW URL for build: {buildid}')

    firm = None
    for API_URL in (RELEASE_API, BETA_API):
        api = requests.get(f"{API_URL}/{device.data['identifier']}").json()

        if API_URL == RELEASE_API:
            firmwares = api['firmwares']
        elif API_URL == BETA_API:
            firmwares = api

        try:
            firm = next(
                firm for firm in firmwares if firm['buildid'].lower() == buildid.lower()
            )
        except StopIteration:
            pass

    if firm is None:
        sys.exit(
            f"iOS Build {buildid} does not exist for device: {device.data['identifier']}. Exiting."
        )

    ipsw = IPSW(
        device,
        firm['url'],
    )

    if not device.pwned:
        print('Entering Pwned DFU mode...')
        device.pwn()

    print(
        f"Decrypting keys for iOS {firm['version']}, device: {device.data['identifier']}..."
    )
    ibss = ipsw.read_file(ipsw.manifest.get_path('iBSS'))
    ibec = ipsw.read_file(ipsw.manifest.get_path('iBEC'))
    llb = ipsw.read_file(ipsw.manifest.get_path('LLB'))
    iboot = ipsw.read_file(ipsw.manifest.get_path('iBoot'))

    decrypter = Decrypt(device)

    ibss_iv, ibss_key = decrypter.decrypt_keys(ibss)
    print(f'\niBSS KBAG: {ibss_iv + ibss_key}')

    ibec_iv, ibec_key = decrypter.decrypt_keys(ibec)
    print(f'iBEC KBAG: {ibec_iv + ibec_key}')

    llb_iv, llb_key = decrypter.decrypt_keys(llb)
    print(f'LLB KBAG: {llb_iv + llb_key}')

    iboot_iv, iboot_key = decrypter.decrypt_keys(iboot)
    print(f'iBoot KBAG: {llb_iv + llb_key}')

    print('\nDone!')


if __name__ == '__main__':
    main()
