#!/usr/bin/python -u -B

import StringIO
import argparse
import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import xattr

import checksums_lib

from test_util import AssertEquals
from test_util import AssertLinesEqual
from test_util import AssertNotEquals
from test_util import CreateDir
from test_util import CreateDirs
from test_util import CreateFile
from test_util import CreateSymlink
from test_util import DeleteFileOrDir
from test_util import SetMTime
from test_util import TempDir

from lib_test_util import GetFileTreeManifest

from checksums_lib_test_util import DoVerify
from checksums_lib_test_util import DoSync


def VerifyTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')

    DoVerify(
      root_dir,
      expected_success=False,
      expected_output=['Not implemented'])


def SyncTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')

    DoSync(
      root_dir,
      expected_success=False,
      expected_output=['Not implemented'])


def Test(tests=[]):
  if not tests or 'VerifyTest' in tests:
    VerifyTest()
  if not tests or 'SyncTest' in tests:
    SyncTest()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  Test(tests=args.tests)
