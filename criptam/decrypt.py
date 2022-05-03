from contextlib import redirect_stdout

from ipwndfu import dfu
from ipwndfu.main import decrypt_gid
from pyimg4 import IM4P, KeybagType

from .device import Device


class Decrypt:
    def __init__(self, device: Device):
        self.device = device

    def decrypt_keys(self, data: bytes) -> tuple:
        device = dfu.acquire_device(match=self.device.data['ECID'])

        image = IM4P(data)
        kbag = next(k for k in image.payload.keybags if k.type == KeybagType.RELEASE)

        with redirect_stdout(None):  # Hide ipwndfu's output
            dec_kbag = decrypt_gid(device, (kbag.iv + kbag.key).hex())

        return (dec_kbag[:32], dec_kbag[-64:])
