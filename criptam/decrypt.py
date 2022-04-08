from criptam.device import Device
from criptam.utils import HiddenPrints
from ipwndfu.main import decrypt_gid
from ipwndfu import dfu
from pyimg4 import IM4P


class Decrypt:
    def __init__(self, device: Device):
        self.device = device

    def decrypt_keys(self, data: bytes) -> tuple:
        image = IM4P(data)

        device = dfu.acquire_device(match=self.device.data['ECID'])
        with HiddenPrints():  # Hide ipwndfu's output
            dec_kbag = decrypt_gid(
                device, (image.keybags[0].iv + image.keybags[0].key).hex()
            )

        return (dec_kbag[:32], dec_kbag[-64:])
