#!/usr/bin/env python3 -u -B

import os
import sys

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir))
import backups_lib
__package__ = backups_lib.__package__

from . import backups_main


if __name__ == '__main__':
  if not backups_main.Main():
    sys.exit(1)
