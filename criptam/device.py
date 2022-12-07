import shutil
import subprocess
from contextlib import redirect_stdout
from pathlib import Path

import requests
import usb
import usb.backend.libusb1
import usb.util
from ipwndfu.main import decrypt_gid
from pyimg4 import Keybag


def get_backend() -> str:
    '''Attempt to find a libusb 1.0 library to use as pyusb's backend, exit if one isn't found.'''

    search_paths = (
        Path('/usr/local/lib'),
        Path('/usr/lib'),
        Path('/opt/homebrew/lib'),
        Path('/opt/procursus/lib'),
    )

    for path in search_paths:
        for file_ in path.rglob('*libusb-1.0*'):
            if not file_.is_file():
                continue

            if file_.suffix not in ('.so', '.dylib'):
                continue

            return usb.backend.libusb1.get_backend(find_library=lambda _: file_)

    pass  # TODO: raise error


class Device:
    def __init__(self):
        device = usb.core.find(
            idVendor=0x5AC,
            idProduct=0x1227,
            backend=get_backend(),
        )
        if device is None:
            print('no device found')  # TODO: raise error

        self._pwned = False
        for fourcc, value in [
            (item.split(':')[0], item.split(':')[1])
            for item in device.serial_number.split()
        ]:
            if fourcc == 'CPID':
                self._chip_id = int(value, 16)

            elif fourcc == 'BDID':
                self._board_id = int(value, 16)

            elif fourcc == 'ECID':
                self._ecid = int(value, 16)

            elif fourcc == 'PWND':
                self._pwned = True

        usb.util.dispose_resources(device)

        ipsw_api = requests.get('https://api.ipsw.me/v4/devices').json()
        for device in ipsw_api:
            for board in device['boards']:
                if board['cpid'] == self.chip_id and board['bdid'] == self.board_id:
                    self._identifier = device['identifier']
                    break

    @property
    def board_id(self) -> int:
        return self._board_id

    @property
    def chip_id(self) -> int:
        return self._chip_id

    @property
    def ecid(self) -> int:
        return self._ecid

    @property
    def identifier(self) -> str:
        return self._identifier

    @property
    def pwned(self) -> bool:
        return self._pwned

    @property
    def soc(self) -> str:
        if 0x8720 <= self.chip_id <= 0x8960:
            return f'S5L{self.chip_id:02x}'
        elif self.chip_id in range(0x7002, 0x8003):
            return f'S{self.chip_id:02x}'
        else:
            return f'T{self.chip_id:02x}'

    def decrypt_keybag(self, keybag=Keybag, _backend='ipwndfu') -> Keybag:
        if not isinstance(keybag, Keybag):
            raise TypeError('Invalid keybag provided')

        if _backend not in ('ipwndfu', 'gaster'):
            raise ValueError('Unknown backend provided')

        device = usb.core.find(
            idVendor=0x5AC,
            idProduct=0x1227,
            backend=get_backend(),
        )

        if _backend == 'ipwndfu':
            with redirect_stdout(None):  # Hide ipwndfu's output
                dec_kbag = decrypt_gid(device, (keybag.iv + keybag.key).hex())

            usb.util.dispose_resources(device)

            dec_kbag = Keybag(
                iv=bytes.fromhex(dec_kbag[:32]),
                key=bytes.fromhex(dec_kbag[-64:]),
            )

        elif _backend == 'gaster':
            if shutil.which('gaster') is None:
                raise FileNotFoundError(
                    'Specified to use gaster as backend, but gaster not found in PATH'
                )

            try:
                subprocess.check_output(('gaster', '--help'), universal_newlines=True)
            except subprocess.CalledProcessError as gaster:
                if 'decrypt_kbag' not in gaster.output:
                    raise ValueError(
                        'Specified to use gaster as backend, but installed gaster version does not support decrypting keybags'
                    )

            gaster_decrypt = subprocess.check_output(
                ('gaster', 'decrypt_kbag', (keybag.iv + keybag.key).hex()),
                universal_newlines=True,
            ).splitlines()[-1]

            dec_kbag = Keybag(
                iv=bytes.fromhex(gaster_decrypt.split('IV: ')[1].split(',')[0]),
                key=bytes.fromhex(gaster_decrypt.split('key: ')[1]),
            )

        return dec_kbag
