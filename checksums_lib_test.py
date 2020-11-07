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

from checksums_lib_test_util import DoCreate
from checksums_lib_test_util import DoVerify
from checksums_lib_test_util import DoSync


def CreateTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')

    DoCreate(
      root_dir, dry_run=True,
      expected_output=['Created checksums metadata for %s' % root_dir])

    DoCreate(
      root_dir,
      expected_output=['Created checksums metadata for %s' % root_dir])

    DoCreate(
      root_dir,
      expected_success=False,
      expected_output=['*** Error: Did not expect %s/.metadata to exist' % root_dir])


def VerifyTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')
    file1 = CreateFile(root_dir, 'f1', contents='1'*1025)
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2')
    ln1 = CreateSymlink(root_dir, 'ln1', 'INVALID')

    DoVerify(
      root_dir,
      expected_success=False,
      expected_output=['*** Error: Manifest file %s/.metadata/manifest.pbdata should exist' % root_dir])

    DoCreate(root_dir, expected_output=None)

    DoVerify(
      root_dir,
      expected_success=False,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2'])


def SyncTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')

    DoSync(
      root_dir,
      expected_success=False,
      expected_output=['*** Error: Manifest file %s/.metadata/manifest.pbdata should exist' % root_dir])

    DoCreate(root_dir, expected_output=None)

    DoSync(
      root_dir, dry_run=True,
      expected_output=['>d+++++++ .',
                       'Paths: 1 synced of 1 paths (0b of 0b), 0 checksummed (0b)'])

    DoVerify(
      root_dir, checksum_all=True,
      expected_success=False,
      expected_output=['>d+++++++ .'])
    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       'Paths: 1 synced of 1 paths (0b of 0b), 0 checksummed (0b)'])
    DoSync(
      root_dir,
      expected_output=[])

    DoVerify(root_dir, checksum_all=True, expected_output=[])

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    ln1 = CreateSymlink(root_dir, 'ln1', 'INVALID')

    DoSync(
      root_dir, dry_run=True,
      expected_output=['>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 4 synced of 5 paths (1kb of 1kb), 2 checksummed (1kb)'])
    DoSync(
      root_dir,
      expected_output=['>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 4 synced of 5 paths (1kb of 1kb), 2 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True, expected_output=[])

    file1 = CreateFile(root_dir, 'f1', contents='DEF')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025, mtime=None)
    ln1 = CreateSymlink(root_dir, 'ln1', 'f1')
    file3 = CreateFile(parent1, 'f3')
    parent2 = CreateDir(root_dir, 'par2')
    CreateFile(root_dir, '.DS_Store')
    CreateFile(parent1, '.DS_Store')

    DoSync(
      root_dir, dry_run=True,
      expected_output=['.Lc...... ln1 -> f1',
                       '.f..t.... par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       '>d+++++++ par2',
                       'Paths: 4 synced of 7 paths (1kb of 1kb), 2 checksummed (1kb)'])
    DoSync(
      root_dir, dry_run=True, checksum_all=True,
      expected_output=['>fc...... f1',
                       '.Lc...... ln1 -> f1',
                       '.f..t.... par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       '>d+++++++ par2',
                       'Paths: 5 synced of 7 paths (1kb of 1kb), 3 checksummed (1kb)'])
    DoVerify(root_dir,
             expected_success=False,
             expected_output=['.Lc...... ln1 -> f1',
                              '.f..t.... par! \\r/f2',
                              '>f+++++++ par! \\r/f3',
                              '>d+++++++ par2'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['>fc...... f1',
                              '.Lc...... ln1 -> f1',
                              '.f..t.... par! \\r/f2',
                              '>f+++++++ par! \\r/f3',
                              '>d+++++++ par2'])
    DoSync(
      root_dir,
      expected_output=['.Lc...... ln1 -> f1',
                       '.f..t.... par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       '>d+++++++ par2',
                       'Paths: 4 synced of 7 paths (1kb of 1kb), 2 checksummed (1kb)'])
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>fc...... f1',
                       'Paths: 1 synced of 7 paths (3b of 1kb), 3 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True, expected_output=[])

    file1 = CreateFile(root_dir, 'f1', contents='GHI', mtime=None)
    file2 = CreateFile(parent1, 'f2', contents='2'*1025, mtime=None)
    xattr.setxattr(root_dir, 'example', 'example_value')
    xattr.setxattr(parent1, 'example', 'example_value')
    DeleteFileOrDir(file3)
    DeleteFileOrDir(parent2)

    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['.d......x .',
                              '>fc.t.... f1',
                              '.d......x par! \\r',
                              '>fc...... par! \\r/f2',
                              '*deleting par! \\r/f3',
                              '*deleting par2'])
    DoSync(
      root_dir,
      expected_output=['.d......x .',
                       '>fc.t.... f1',
                       '.d......x par! \\r',
                       '*deleting par! \\r/f3',
                       '*deleting par2',
                       'Paths: 3 synced of 5 paths (3b of 1kb), 1 checksummed (3b)'])
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>fc...... par! \\r/f2',
                       'Paths: 1 synced of 5 paths (1kb of 1kb), 2 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True, expected_output=[])


def Test(tests=[]):
  if not tests or 'CreateTest' in tests:
    CreateTest()
  if not tests or 'VerifyTest' in tests:
    VerifyTest()
  if not tests or 'SyncTest' in tests:
    SyncTest()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  Test(tests=args.tests)
