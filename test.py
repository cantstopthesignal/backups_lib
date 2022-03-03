#!/usr/bin/env python3 -u -B

import argparse
import os
import sys

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir))
import backups_lib
__package__ = backups_lib.__package__

from . import backups_manager_lib_test
from . import backups_oneoff_lib_test
from . import checkpoint_lib_test
from . import checksums_lib_test
from . import checksums_oneoff_lib_test
from . import lib_test
from . import lib_test_util

from .test_util import SetPacificTimezone


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  parser.add_argument('--no-fake-disk-image-helper', dest='enable_fake_disk_image_helper',
                      action='store_false')
  args = parser.parse_args()

  SetPacificTimezone()
  lib_test_util.ENABLE_FAKE_DISK_IMAGE_HELPER = args.enable_fake_disk_image_helper

  lib_test.Test(tests=args.tests)
  backups_manager_lib_test.Test(tests=args.tests)
  backups_oneoff_lib_test.Test(tests=args.tests)
  checkpoint_lib_test.Test(tests=args.tests)
  checksums_lib_test.Test(tests=args.tests)
  checksums_oneoff_lib_test.Test(tests=args.tests)
