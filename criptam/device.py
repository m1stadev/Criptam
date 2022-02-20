from collections import namedtuple
from ipwndfu.main import pwn
from libusbfinder import libusb1_path
from typing import Optional
import usb, usb.backend.libusb1, usb.util

import requests
import sys

Mode = namedtuple('Mode', ('RECOVERY', 'DFU'))
mode = Mode(0x1281, 0x1227)


class Device:
    def __init__(self):
        self.data = self._get_data()

    def _get_data(self) -> dict:
        device = self.get_device(mode.DFU)

        device_data = dict()
        for item in device.serial_number.split():
            device_data[item.split(':')[0]] = item.split(':')[1]

        device_data['ECID'] = hex(int(device_data['ECID'], 16))

        for i in ('CPID', 'CPRV', 'BDID', 'CPFM', 'SCEP', 'IBFL'):
            device_data[i] = int(device_data[i], 16)

        for item in usb.util.get_string(device, device.bDescriptorType).split():
            device_data[item.split(':')[0]] = item.split(':')[1]

        self.release_device(device)

        api = requests.get('https://api.ipsw.me/v4/devices').json()
        for d in api:
            for board in d['boards']:
                if (
                    board['cpid'] == device_data['CPID']
                    and board['bdid'] == device_data['BDID']
                ):
                    device_data['identifier'] = d['identifier']
                    device_data['boardconfig'] = board['boardconfig']

        return device_data

    def get_device(self, usb_mode: int, match: str = None) -> Optional[usb.core.Device]:
        if usb_mode not in mode:
            sys.exit(f'Invalid mode specified: {usb_mode}.')

        device: usb.core.Device = usb.core.find(
            idVendor=0x5AC,
            idProduct=usb_mode,
            backend=usb.backend.libusb1.get_backend(
                find_library=lambda x: libusb1_path()
            ),
        )

        if match is not None and match not in device.serial_number:
            device = None

        if device is None:
            sys.exit(f'Device not found.')

        return device

    def release_device(self, device: usb.core.Device) -> None:
        usb.util.dispose_resources(device)

    @property
    def baseband(self) -> bool:
        if self.data['identifier'].startswith('iPhone'):
            return True

        else:
            return self.data[
                'identifier'
            ] in (  # All (current) 64-bit cellular iPads vulerable to checkm8.
                'iPad4,2',
                'iPad4,3',
                'iPad4,5',
                'iPad4,6',
                'iPad4,8',
                'iPad4,9',
                'iPad5,2',
                'iPad5,4',
                'iPad6,4',
                'iPad6,8',
                'iPad6,12',
                'iPad7,2',
                'iPad7,4',
                'iPad7,6',
                'iPad7,12',
            )

    @property
    def pwned(self) -> bool:
        return 'PWND' in self.data.keys()

    def pwn(self) -> bool:
        if 'PWND' in self.data.keys():
            return True

        pwn(match_device=self.data['ECID'])
        self.data = self._get_data()

        return True
