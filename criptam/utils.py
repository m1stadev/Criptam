# Taken from: https://stackoverflow.com/a/45669280
import os, sys


class HiddenPrints:
    def __enter__(self):
        self._original_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

    def __exit__(self, _, __, ___):
        sys.stdout.close()
        sys.stdout = self._original_stdout
