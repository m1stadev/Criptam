from device import Device, mode
from kimg4.img4 import IM4P
from ipwndfu.main import decrypt_gid
from utils import HiddenPrints


class Decrypt:
    def __init__(self, device: Device):
        self.device = device

    def decrypt_keys(self, img: bytes) -> tuple:
        image = IM4P(img)

        device = self.device.get_device(mode.DFU, self.device.data['ECID'])
        with HiddenPrints():  # Hide ipwndfu's output
            dec_kbag = decrypt_gid(
                device,
                (image.kbag.keybags[0].iv + image.kbag.keybags[0].key).hex(),
            )

        return (dec_kbag[-32:], dec_kbag[:-64])
