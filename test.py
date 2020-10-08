#!/usr/bin/python -u -B

import argparse

import lib_test
import backups_lib_test
import backups_oneoff_lib_test


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  lib_test.Test(tests=args.tests)
  backups_lib_test.Test(tests=args.tests)
  backups_oneoff_lib_test.Test(tests=args.tests)
