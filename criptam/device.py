from criptam.utils import HiddenPrints
from ipwndfu.main import pwn
from ipwndfu import dfu

import requests
import sys


class Device:
    def __init__(self):
        self.data = self._get_data()

    def _get_data(self) -> dict:
        device = dfu.acquire_device(fatal=False)
        if device is None:
            sys.exit('[ERROR] Device in DFU mode not found. Exiting.')

        device_data = dict()
        for item in device.serial_number.split():
            device_data[item.split(':')[0]] = item.split(':')[1]

        for i in ('CPID', 'CPRV', 'BDID', 'CPFM', 'SCEP', 'IBFL'):
            device_data[i] = int(device_data[i], 16)

        dfu.release_device(device)

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

        with HiddenPrints():
            pwn(match_device=self.data['ECID'])

        self.data = self._get_data()
        return self.pwned
