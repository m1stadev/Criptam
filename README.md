# Criptam
Criptam is a tool written in Python to easily decrypt [Bootchain](https://www.theiphonewiki.com/wiki/Bootchain) [Firmware Keys](https://www.theiphonewiki.com/wiki/Firmware_Keys) (excluding SEPOS) for iOS devices.

## Features
- Automatically decrypt bootchain for any iOS version, no IPSW download required.

## Requirements
- A UNIX-like OS
- An internet connection
- A 64-bit device connected in DFU mode vulnerable to [checkm8](https://github.com/axi0mX/ipwndfu)
- Libraries:
    ```py
    pip3 install -r requirements.txt
    ```


## Usage
| Option (short) | Option (long) | Description |
|----------------|---------------|-------------|
| `-h` | `--help` | Shows all options avaiable |
| `-b BUILDID` | `--buildid BUILDID` | iOS build to decrypt keys for |

