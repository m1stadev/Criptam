from criptam.device import Device
from criptam.manifest import Manifest

import remotezip


class IPSW:
    def __init__(self, device: Device, url: str):
        self.device = device
        self.url = url

        self.manifest = self.read_manifest()

    def read_file(self, file: str) -> bytes:
        with remotezip.RemoteZip(self.url) as ipsw:
            return ipsw.read(file)

    def read_manifest(self):
        return Manifest(self.read_file('BuildManifest.plist'), self.device.data['boardconfig'])
