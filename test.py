#!/usr/bin/python -u -B

import argparse

import backups_lib_test
import backups_oneoff_lib_test
import checksums_lib_test
import lib_test

from test_util import SetPacificTimezone


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  SetPacificTimezone()

  lib_test.Test(tests=args.tests)
  backups_lib_test.Test(tests=args.tests)
  backups_oneoff_lib_test.Test(tests=args.tests)
  checksums_lib_test.Test(tests=args.tests)
