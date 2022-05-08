from pathlib import Path
from typing import Optional

import remotezip

from .device import Device
from .manifest import Manifest


class IPSW:
    def __init__(self, device: Device, url: str):
        self.device = device
        self.url = url

        self.manifest = self.read_manifest()

    def read_file(self, path: Path) -> Optional[bytes]:
        try:
            with remotezip.RemoteZip(self.url) as ipsw:
                return ipsw.read(str(path))

        except remotezip.RemoteIOError:
            return None

    def read_manifest(self) -> Manifest:
        return Manifest(self.read_file('BuildManifest.plist'))
