from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import remotezip
import requests

from .device import Device
from .manifest import Manifest


class IPSW:
    def __init__(self, device: Device, url: str):
        self.device = device
        self.url = url

    def read_file(self, path: Path) -> Optional[bytes]:
        try:
            with remotezip.RemoteZip(self.url) as ipsw:
                return ipsw.read(str(path))

        except remotezip.RemoteIOError:
            return None

    def read_manifest(self) -> Manifest:
        url = urlparse(self.url)
        manifest = requests.get(
            url._replace(
                path=str(Path(url.path).parents[0] / 'BuildManifest.plist')
            ).geturl()
        )

        if manifest.status_code == 200:
            return Manifest(manifest.content)
        else:
            return Manifest(self.read_file('BuildManifest.plist'))
