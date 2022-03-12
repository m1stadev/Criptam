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
        usage="criptam [-b BUILDID] [-m MAJOR] [-a]",
    )

    version = parser.add_mutually_exclusive_group(required=True)
    version.add_argument(
        '-b', '--buildid', help='iOS build to decrypt firmware keys for'
    )
    version.add_argument(
        '-m', '--major', help='Major iOS version to decrypt all firmware keys for'
    )
    version.add_argument(
        '-a',
        '--all',
        help='Decrypt firmware keys for all versions',
        action='store_true',
    )

    args = parser.parse_args()

    if platform.system() == 'Windows':
        sys.exit('[ERROR] Windows systems are not supported. Exiting.')

    print(f'Criptam {__version__}')

    print(f'\nConnecting to DFU device...')
    device = Device()

    print(f"\nGetting firmware information for device: {device.data['identifier']}...")

    firmwares = list()
    for API_URL in (RELEASE_API, BETA_API):
        api = requests.get(f"{API_URL}/{device.data['identifier']}").json()

        if API_URL == RELEASE_API:
            firms = api['firmwares']
        elif API_URL == BETA_API:
            firms = api

        for firm in firms:
            if any(firm['buildid'] == f['buildid'] for f in firmwares):
                continue

            firmwares.append(firm)

    firmwares = sorted(firmwares, key=lambda x: x['buildid'], reverse=True)
    if args.buildid:
        buildid = args.buildid.upper()
        firmwares = [
            firm
            for firm in firmwares
            if firm['buildid'].casefold() == buildid.casefold()
        ]
        if len(firmwares) == 0:
            sys.exit(
                f"iOS Build {buildid} does not exist for device: {device.data['identifier']}. Exiting."
            )

    elif args.major:
        firmwares = [
            firm for firm in firmwares if firm['version'].startswith(args.major)
        ]
        if len(firmwares) == 0:
            sys.exit(
                f"iOS {args.major} does not exist for device: {device.data['identifier']}. Exiting."
            )

    elif args.all:
        pass

    if len(firmwares) > 10:
        try:
            input(
                f"[WARNING] This will decrypt bootchain firmware keys for {len(firmwares)} firmwares.\nPress ENTER to continue, or CTRL+C to cancel: "
            )
        except KeyboardInterrupt:
            sys.exit('\nExiting.')

    if not device.pwned:
        print('Entering Pwned DFU mode...')
        device.pwn()

    for firm in firmwares:
        try:
            ipsw = IPSW(
                device,
                firm['url'],
            )
        except:
            if len(firmwares) == 1:
                sys.exit(
                    f"[ERROR] Failed to download bootchain for iOS {firm['version']}, device: {device.data['identifier']}. Exiting."
                )
            else:
                print(
                    f"[ERROR] Failed to download bootchain for iOS {firm['version']}, device: {device.data['identifier']}. Skipping.\n"
                )

        print(
            f"Decrypting keys for iOS {firm['version']}, device: {device.data['identifier']}..."
        )
        ibss = ipsw.read_file(ipsw.manifest.get_path('iBSS'))
        ibec = ipsw.read_file(ipsw.manifest.get_path('iBEC'))
        llb = ipsw.read_file(ipsw.manifest.get_path('LLB'))
        iboot = ipsw.read_file(ipsw.manifest.get_path('iBoot'))

        decrypter = Decrypt(device)

        ibss_iv, ibss_key = decrypter.decrypt_keys(ibss)
        print(f"\niBSS KBAG for iOS {firm['version']}: {ibss_iv + ibss_key}")

        ibec_iv, ibec_key = decrypter.decrypt_keys(ibec)
        print(f"iBEC KBAG for iOS {firm['version']}: {ibec_iv + ibec_key}")

        llb_iv, llb_key = decrypter.decrypt_keys(llb)
        print(f"LLB KBAG for iOS {firm['version']}: {llb_iv + llb_key}")

        iboot_iv, iboot_key = decrypter.decrypt_keys(iboot)
        print(f"iBoot KBAG for iOS {firm['version']}: {iboot_iv + iboot_key}\n")

    print('Done!')


if __name__ == '__main__':
    main()
