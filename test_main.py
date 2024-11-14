import argparse
import os
import sys
import unittest

from . import lib
from . import lib_test_util
from . import test_util


def RunCurrentFileUnitTests():
  parser = argparse.ArgumentParser()
  parser.add_argument('--fake-disk-image-level', choices=lib_test_util.FAKE_DISK_IMAGE_LEVEL_CHOICES,
                      default=lib_test_util.FAKE_DISK_IMAGE_LEVEL_MEDIUM)
  parser.add_argument('-v', '--verbose', action='store_true')
  parser.add_argument('unittest_args', nargs=argparse.REMAINDER)
  args = parser.parse_args()

  lib.KEYCHAIN_PASSWORDS_ENABLED = False
  test_util.SetPacificTimezone()
  test_util.VERBOSE_TESTS = args.verbose
  lib_test_util.FAKE_DISK_IMAGE_LEVEL = args.fake_disk_image_level

  unittest_argv = sys.argv[:1]
  if args.verbose:
    unittest_argv.append('-v')
  if args.unittest_args:
    if args.unittest_args[0] != '--':
      parser.print_help()
      parser.exit()
    unittest_argv.extend(args.unittest_args[1:])

  unittest.main(argv=unittest_argv)


def RunTestSuite():
  parser = argparse.ArgumentParser()
  parser.add_argument('--fake-disk-image-level', choices=lib_test_util.FAKE_DISK_IMAGE_LEVEL_CHOICES,
                      default=lib_test_util.FAKE_DISK_IMAGE_LEVEL_MEDIUM)
  parser.add_argument('-v', '--verbose', action='store_true')
  args = parser.parse_args()

  lib.KEYCHAIN_PASSWORDS_ENABLED = False
  test_util.SetPacificTimezone()
  test_util.VERBOSE_TESTS = args.verbose
  lib_test_util.FAKE_DISK_IMAGE_LEVEL = args.fake_disk_image_level

  suite = unittest.TestLoader().discover(os.path.dirname(sys.argv[0]), '*_test.py')
  runner = unittest.TextTestRunner(verbosity=args.verbose and 2 or 1)
  if not runner.run(suite).wasSuccessful():
    sys.exit(1)
  sys.exit(0)
