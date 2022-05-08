import plistlib
from pathlib import Path

IMAGE_NAMES = {
    'RestoreRamDisk': 'RestoreRamdisk',
    'AppleLogo': 'AppleLogo',
    'BatteryCharging0': 'BatteryCharging0',
    'BatteryCharging1': 'BatteryCharging1',
    'BatteryFull': 'BatteryFull',
    'BatteryLow0': 'BatteryLow0',
    'BatteryLow1': 'BatteryLow1',
    'DeviceTree': 'DeviceTree',
    'BatteryPlugin': 'GlyphPlugin',
    'iBEC': 'iBEC',
    'iBoot': 'iBoot',
    'iBootData': 'iBootData',
    'iBSS': 'iBSS',
    'KernelCache': 'Kernelcache',
    'LLB': 'LLB',
    'RecoveryMode': 'RecoveryMode',
    'SEP': 'SEPFirmware',
}


class ManifestImage:
    def __init__(self, name: str, data: dict):
        self._data = data

        self.name = name

        info = self._data.get('Info')
        if info is None:
            raise KeyError('Info dict is missing from manifest image')

        path = info.get('Path')
        if path is None:
            raise KeyError('Path is missing from manifest image')

        self.path = Path(path)


class ManifestIdentity:
    def __init__(self, data: dict):
        self._data = data

        manifest = self._data.get('Manifest')
        if manifest is None:
            raise KeyError('Firmware images are missing from manifest')

        self.images: list[ManifestImage] = list()
        for name, data in manifest.items():
            try:
                self.images.append(ManifestImage(name, data))
            except KeyError:
                pass

    @property
    def boardconfig(self) -> str:
        info = self._data.get('Info')
        if info is None:
            raise KeyError('Info dict is missing from manifest')

        boardconfig = info.get('DeviceClass')

        if boardconfig is None:
            raise KeyError('DeviceClass is missing from manifest')

        return boardconfig

    @property
    def restore_type(self) -> str:
        info = self._data.get('Info')
        if info is None:
            raise KeyError('Info dict is missing from manifest')

        restore_type = info.get('RestoreBehavior')

        if restore_type is None:
            raise KeyError('RestoreBehavior is missing from manifest')

        return restore_type


class Manifest:
    def __init__(self, data: bytes):
        self._data = plistlib.loads(data)

        self.version = tuple(int(_) for _ in self._data['ProductVersion'].split('.'))
        self.buildid = self._data['ProductBuildVersion']
        self.supported_devices = self._data['SupportedProductTypes']

        self.identities = [ManifestIdentity(i) for i in self._data['BuildIdentities']]

    def get_identity(self, board: str, erase: bool) -> ManifestIdentity:
        identity = next(
            (
                i
                for i in self.identities
                if i.boardconfig.casefold() == board.casefold()
                and i.restore_type == ('Erase' if erase == True else 'Update')
            ),
            None,
        )

        if identity is None:
            raise ValueError('Failed to find identity for board: {}'.format(board))

        return identity
