#!/usr/bin/env python3

import argparse
import pathlib
import platform
import sys
from importlib.metadata import version

import pyimg4
import requests
import yaml

from .decrypt import Decrypt
from .device import Device
from .ipsw import IPSW
from .manifest import IMAGE_NAMES

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
        '-m', '--major', help='Major iOS version to decrypt firmware keys for'
    )
    version.add_argument(
        '-a',
        '--all',
        help='Decrypt firmware keys for all versions',
        action='store_true',
    )

    parser.add_argument(
        '-y',
        '--hackdifferent',
        type=pathlib.Path,
        help="Export data in a YAML format suitable for Hack Different's keybag database",
        dest='hd',
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

    decrypter = Decrypt(device)
    decrypted_keys = dict()
    for firm in firmwares:
        decrypted_keys[firm['buildid']] = dict()

        try:
            ipsw = IPSW(
                device,
                firm['url'],
            )
        except:
            if len(firmwares) == 1:
                sys.exit(
                    f"\n[ERROR] Failed to download bootchain for iOS {firm['version']}, device: {device.data['identifier']}. Exiting."
                )
            else:
                print(
                    f"\n[ERROR] Failed to download bootchain for iOS {firm['version']}, device: {device.data['identifier']}. Skipping."
                )
                continue

        print(
            "\nDecrypting keys for iOS {}, device: {}{}...".format(
                firm['version'],
                device.data['identifier'],
                f" ({device.data['boardconfig']})"
                if 0x8000 <= device.data['CPID'] <= 0x8003
                else '',
            )
        )

        erase_id = ipsw.manifest.get_identity(device.data['boardconfig'], erase=True)
        for image in erase_id.images:
            if image.name not in IMAGE_NAMES.keys():
                continue

            # Only certain bootchain components are encrypted on iOS 10+
            if ipsw.manifest.version[0] >= 10 and image.name not in (
                'iBSS',
                'iBEC',
                'LLB',
                'iBoot',
                'iBootData',
                'SEP',
            ):
                continue

            if image.name == 'OS':  # Not downloading the entire filesystem
                continue

            try:
                image_file = pyimg4.IM4P(ipsw.read_file(image.path))
            except:  # Not an Image4 Payload
                continue

            # Confirm one more time that this is an encrypted image
            if not image_file.payload.encrypted:
                continue

            if image.name == 'SEP':
                kbag = next(
                    k
                    for k in image_file.payload.keybags
                    if k.type == pyimg4.KeybagType.PRODUCTION
                )
                if kbag is None:
                    raise ValueError('Failed to find production keybag for image')

                iv, key = kbag.iv.hex(), kbag.key.hex()
                image_encrypted = True
            else:
                iv, key = decrypter.decrypt_image(image_file)
                image_encrypted = False

                print(f"{image.name} KBAG for iOS {firm['version']}: {iv + key}")

            decrypted_keys[firm['buildid']][image.name] = {
                'filename': image.path.name,
                'iv': iv,
                'key': key,
                'encrypted': image_encrypted,
            }

        try:
            if ipsw.manifest.version[0] <= 9:
                update_id = ipsw.manifest.get_identity(
                    device.data['boardconfig'], erase=False
                )

                update_ramdisk = next(
                    i for i in update_id.images if i.name == 'RestoreRamDisk'
                )

                update_ramdisk_file = pyimg4.IM4P(
                    ipsw.read_file(update_ramdisk.path)
                )  # Confirm one more time that this is an encrypted image

                iv, key = decrypter.decrypt_image(update_ramdisk_file)
                decrypted_keys[firm['buildid']]['UpdateRamdisk'] = {
                    'filename': update_ramdisk.path.name,
                    'iv': iv,
                    'key': key,
                    'encrypted': False,
                }

                print(f"UpdateRamdisk KBAG for iOS {firm['version']}: {iv + key}")
        except:
            pass

    print('\nDone!')

    if args.hd:
        cpid_hex = int(hex(device.data['CPID']).removeprefix('0x'))
        bdid_hex = int(hex(device.data['BDID']).removeprefix('0x'))

        hd_data = {
            'metadata': {'description': str(), 'credits': list()},
            'constants': {'chip_id': cpid_hex},
            'keybag_boards': {bdid_hex: dict()},
        }

        for buildid in decrypted_keys.keys():
            images = dict()
            for image in decrypted_keys[buildid].keys():
                filename = decrypted_keys[buildid][image]['filename']
                iv = decrypted_keys[buildid][image]['iv']
                key = decrypted_keys[buildid][image]['key']

                if decrypted_keys[buildid][image]['encrypted'] == False:
                    images[
                        IMAGE_NAMES[image] if image in IMAGE_NAMES.keys() else image
                    ] = {
                        'filename': filename
                        if not filename.endswith('.dmg')
                        else filename.replace('.dmg', ''),
                        'iv': iv,
                        'key': key,
                    }
                else:
                    images[IMAGE_NAMES[image]] = {
                        'filename': filename,
                        'keybags': {
                            'production': {
                                'encrypted_iv': iv,
                                'encrypted_key': key,
                            }
                        },
                    }

            hd_data['keybag_boards'][bdid_hex][buildid] = {'components': images}

        with args.hd.open('w') as f:
            f.write(
                yaml.safe_dump(hd_data, sort_keys=False, explicit_start=True).replace(
                    r"''", ''
                )
            )

        print(f"Saved keys to: {args.hd}")


if __name__ == '__main__':
    main()
