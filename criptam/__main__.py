#!/usr/bin/env python3

from decrypt import Decrypt
from device import Device
from ipsw import IPSW

import argparse
import platform
import requests
import sys

if platform.system() == 'Windows':
    sys.exit('[ERROR] Windows systems are not supported. Exiting...')


def main():
    parser = argparse.ArgumentParser(
        description='Criptam - Automatic Firmware Key decryptor',
        usage="criptam -b 'buildid'",
    )

    parser.add_argument('-b', '--buildid', help='iOS build to decrypt keys for')
    args = parser.parse_args()

    if not args.buildid:
        sys.exit(parser.print_help(sys.stderr))

    input('Please connect an iOS device in DFU mode to your PC, then press enter...')
    device = Device()

    print(f'Getting IPSW URL for build: {args.buildid}')
    api = requests.get(
        f"https://api.ipsw.me/v4/device/{device.data['identifier']}?type=ipsw"
    ).json()

    try:
        ipsw = IPSW(
            device,
            next(_['url'] for _ in api['firmwares'] if _['buildid'] == args.buildid),
        )
    except StopIteration:
        sys.exit(
            f"Build {args.buildid} does not exist for device: {device.data['identifier']}. Exiting."
        )

    if not device.pwned:
        print('Entering Pwned DFU mode...')
        device.pwn()

    print('Decrypting keys...')
    ibss = ipsw.read_file(ipsw.manifest.get_path('iBSS'))
    ibec = ipsw.read_file(ipsw.manifest.get_path('iBEC'))
    llb = ipsw.read_file(ipsw.manifest.get_path('LLB'))
    iboot = ipsw.read_file(ipsw.manifest.get_path('iBoot'))

    decryptor = Decrypt(device)

    ibss_iv, ibss_key = decryptor.decrypt_keys(ibss)
    print(f'iBSS KBAG: {ibss_iv + ibss_key}')

    ibec_iv, ibec_key = decryptor.decrypt_keys(ibec)
    print(f'iBEC KBAG: {ibec_iv + ibec_key}')

    llb_iv, llb_key = decryptor.decrypt_keys(llb)
    print(f'LLB KBAG: {llb_iv + llb_key}')

    iboot_iv, iboot_key = decryptor.decrypt_keys(iboot)
    print(f'iBoot KBAG: {llb_iv + llb_key}')

    print('Done!')


if __name__ == '__main__':
    main()
