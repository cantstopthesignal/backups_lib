#!/usr/bin/env -S python3 -u -B

import argparse
import os
import re
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir))
import backups_lib
__package__ = backups_lib.__package__

from . import checksums_lib
from . import lib
from . import test_main

from .test_util import AssertEquals
from .test_util import AssertNotEquals
from .test_util import BaseTestCase
from .test_util import CreateDir
from .test_util import CreateDirs
from .test_util import CreateFile
from .test_util import SetMTime
from .test_util import SetPacificTimezone
from .test_util import SetXattr
from .test_util import TempDir

from .checksums_lib_test_util import DoChecksumsMain
from .checksums_lib_test_util import DoCreate
from .checksums_lib_test_util import DoSync
from .checksums_lib_test_util import DoVerify


def DoOneoffAddXattrsKeys(
    root_path, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['oneoff-add-xattr-keys', root_path]
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


class OneoffAddXattrKeysTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')
    alt_manifest_path = os.path.join(test_dir, 'mymanifest.pbdata')

    DoCreate(root_dir, expected_output=None)

    fileX = CreateFile(root_dir, 'fX')
    SetXattr(fileX, 'example', b'example_value')
    SetXattr(fileX, 'com.apple.quarantine', b'quarantine1')

    fileT = CreateFile(root_dir, 'fT')
    SetXattr(fileT, 'example', b'example_value2')
    SetXattr(fileT, 'com.apple.quarantine', b'quarantine4')

    parent1 = CreateDir(root_dir, 'par!')
    file3 = CreateFile(parent1, 'f3')
    file4 = CreateFile(parent1, 'f4')
    SetXattr(file4, 'example', b'example_value3')

    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ fT',
                       '>f+++++++ fX',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f3',
                       '>f+++++++ par!/f4',
                       'Paths: 6 total (0b), 6 synced (0b), 4 checksummed (0b)'])

    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 6 total (0b), 4 checksummed (0b)'])

    checksums = checksums_lib.Checksums.Open(root_dir)
    for path, path_info in checksums.GetManifest().GetPathMap().items():
      path_info.xattr_keys = []
    checksums.GetManifest().Write()

    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['.f......x fT',
                              '.f......x fX',
                              '.f......x par!/f4',
                              'Paths: 6 total (0b), 3 mismatched (0b), 4 checksummed (0b)'])

    do_oneoff_expected_output = [
      "Updated xattr list for fT from [] to ['example']",
      "Updated xattr list for fX from [] to ['example']",
      "Updated xattr list for par!/f4 from [] to ['example']",
    'Paths: 3 paths with xattrs, 3 xattrs changed, 6 paths']

    DoOneoffAddXattrsKeys(
      root_dir, dry_run=True,
      expected_output=do_oneoff_expected_output)
    DoOneoffAddXattrsKeys(
      root_dir,
      expected_output=do_oneoff_expected_output)

    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 6 total (0b), 4 checksummed (0b)'])


if __name__ == '__main__':
  test_main.RunCurrentFileUnitTests()
