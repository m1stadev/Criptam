# Criptam
Criptam is a tool written in Python to easily fetch decrypted [iOS bootchain](https://www.theiphonewiki.com/wiki/Bootchain) [firmware keys](https://www.theiphonewiki.com/wiki/Firmware_Keys) (excluding SEPOS) from a connected device.

## Features
- Automatically fetch decrypted bootchain firmware keys for any iOS version, no IPSW download required.

## Requirements
- A UNIX-like OS
- An internet connection
- A 64-bit device connected in DFU mode vulnerable to [checkm8](https://github.com/hack-different/ipwndfu)

## Installation
Criptam can be installed from [PyPI](https://pypi.org/project/criptam/), or locally (requires [poetry](https://python-poetry.org/)):

    ./install.sh


## Usage
| Option (short) | Option (long) | Description |
|----------------|---------------|-------------|
| `-h` | `--help` | Shows all options avaiable |
| `-b BUILDID` | `--buildid BUILDID` | iOS build to decrypt keys for |
| `-m MAJOR` | `--major MAJOR` | Major iOS version to decrypt firmware keys for |
| `-a` | `--all` | Decrypt firmware keys for all versions |
| `-y` | `--hackdifferent` | Export data in a YAML format suitable for [Hack Different's keybag database](https://github.com/hack-different/apple-knowledge/tree/main/_data/keybags) |