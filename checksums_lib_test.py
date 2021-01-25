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
from test_util import RenameFile
from test_util import SetMTime
from test_util import TempDir

from lib_test_util import GetFileTreeManifest
from lib_test_util import SetEscapeKeyDetectorCancelAtInvocation

from checksums_lib_test_util import DoCreate
from checksums_lib_test_util import DoVerify
from checksums_lib_test_util import DoSync
from checksums_lib_test_util import DoRenamePaths
from checksums_lib_test_util import InteractiveCheckerReadyResults


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

    alt_manifest_path = os.path.join(test_dir, 'mymanifest.pbdata')

    DoCreate(
      root_dir, dry_run=True,
      manifest_path=alt_manifest_path,
      expected_output=['Created checksums metadata for %s' % root_dir])

    DoCreate(
      root_dir,
      manifest_path=alt_manifest_path,
      expected_output=['Created checksums metadata for %s' % root_dir])

    DoCreate(
      root_dir,
      manifest_path=alt_manifest_path,
      expected_success=False,
      expected_output=['*** Error: Did not expect %s to exist' % alt_manifest_path])


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
                       '>f+++++++ par! \\r/f2',
                       'Paths: 5 total (1kb), 5 mismatched (1kb)'])
    DoVerify(
      root_dir,
      paths=['par! \r'],
      expected_success=False,
      expected_output=['>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 2 total (0b), 2 mismatched (0b), 3 skipped'])
    DoVerify(
      root_dir,
      paths=['DOES_NOT_EXIST'],
      expected_output=['Paths: 0 total (0b), 5 skipped'])

    alt_manifest_path = os.path.join(test_dir, 'mymanifest.pbdata')

    DoVerify(
      root_dir,
      manifest_path=alt_manifest_path,
      expected_success=False,
      expected_output=['*** Error: Manifest file %s should exist' % alt_manifest_path])

    DoCreate(root_dir,
             manifest_path=alt_manifest_path,
             expected_output=None)

    DoVerify(
      root_dir,
      manifest_path=alt_manifest_path,
      expected_success=False,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 5 total (1kb), 5 mismatched (1kb)'])



def SyncTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')
    alt_manifest_path = os.path.join(test_dir, 'mymanifest.pbdata')

    DoSync(
      root_dir,
      expected_success=False,
      expected_output=['*** Error: Manifest file %s/.metadata/manifest.pbdata should exist' % root_dir])
    DoSync(
      root_dir,
      manifest_path=alt_manifest_path,
      expected_success=False,
      expected_output=['*** Error: Manifest file %s should exist' % alt_manifest_path])

    DoCreate(root_dir, expected_output=None)
    DoCreate(root_dir, manifest_path=alt_manifest_path, expected_output=None)

    DoSync(
      root_dir, dry_run=True,
      expected_output=['>d+++++++ .',
                       'Paths: 1 total (0b), 1 synced (0b)'])

    DoVerify(
      root_dir, checksum_all=True,
      expected_success=False,
      expected_output=['>d+++++++ .',
                       'Paths: 1 total (0b), 1 mismatched (0b)'])
    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       'Paths: 1 total (0b), 1 synced (0b)'])
    DoSync(
      root_dir, manifest_path=alt_manifest_path,
      expected_output=['>d+++++++ .',
                       'Paths: 1 total (0b), 1 synced (0b)'])
    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(False)
      DoSync(
        root_dir, interactive=True,
        expected_output=['Paths: 1 total (0b)'])

    DoVerify(root_dir, checksum_all=True, expected_output=None)
    DoVerify(root_dir, manifest_path=alt_manifest_path, checksum_all=True, expected_output=None)

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
                       'Paths: 5 total (1kb), 4 synced (1kb), 2 checksummed (1kb)'])
    DoSync(
      root_dir,
      expected_output=['>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 5 total (1kb), 4 synced (1kb), 2 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 5 total (1kb), 2 checksummed (1kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='DEF')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025, mtime=None)
    ln1 = CreateSymlink(root_dir, 'ln1', 'f1')
    file3 = CreateFile(parent1, 'f3')
    file4 = CreateFile(parent1, 'f4', contents='4'*1026, mtime=None)
    parent2 = CreateDir(root_dir, 'par2')
    CreateFile(root_dir, '.DS_Store')
    CreateFile(parent1, '.DS_Store')

    with SetEscapeKeyDetectorCancelAtInvocation(14):
      DoSync(
        root_dir, dry_run=True,
        expected_success=False,
        expected_output=['.Lc...... ln1 -> f1',
                         '.f..t.... par! \\r/f2',
                         '*** Cancelled at path par! \\r/f3'])
    DoSync(
      root_dir, dry_run=True,
      expected_output=['.Lc...... ln1 -> f1',
                       '.f..t.... par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       '>f+++++++ par! \\r/f4',
                       '>d+++++++ par2',
                       'Paths: 8 total (2kb), 5 synced (2kb), 3 checksummed (2kb)'])
    DoSync(
      root_dir, dry_run=True, checksum_all=True,
      expected_output=['>fc...... f1',
                       '.Lc...... ln1 -> f1',
                       '.f..t.... par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       '>f+++++++ par! \\r/f4',
                       '>d+++++++ par2',
                       'Paths: 8 total (2kb), 6 synced (2kb), 4 checksummed (2kb)'])
    DoVerify(root_dir,
             expected_success=False,
             expected_output=['.Lc...... ln1 -> f1',
                              '.f..t.... par! \\r/f2',
                              '>f+++++++ par! \\r/f3',
                              '>f+++++++ par! \\r/f4',
                              '>d+++++++ par2',
                              'Paths: 8 total (2kb), 5 mismatched (2kb), 1 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['>fc...... f1',
                              '.Lc...... ln1 -> f1',
                              '.f..t.... par! \\r/f2',
                              '>f+++++++ par! \\r/f3',
                              '>f+++++++ par! \\r/f4',
                              '>d+++++++ par2',
                              'Paths: 8 total (2kb), 6 mismatched (2kb), 2 checksummed (1kb)'])
    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(False)
      DoSync(
        root_dir, interactive=True,
        expected_success=False,
        expected_output=['.Lc...... ln1 -> f1',
                         '.f..t.... par! \\r/f2',
                         '>f+++++++ par! \\r/f3',
                         '>f+++++++ par! \\r/f4',
                         '>d+++++++ par2',
                         'Paths: 8 total (2kb), 5 synced (2kb), 3 checksummed (2kb)',
                         'Apply update? (y/N): n',
                         '*** Cancelled ***'])
    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(True)
      DoSync(
        root_dir, interactive=True,
        expected_output=['.Lc...... ln1 -> f1',
                         '.f..t.... par! \\r/f2',
                         '>f+++++++ par! \\r/f3',
                         '>f+++++++ par! \\r/f4',
                         '>d+++++++ par2',
                         'Paths: 8 total (2kb), 5 synced (2kb), 3 checksummed (2kb)',
                         'Apply update? (y/N): y'])
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>fc...... f1',
                       'Paths: 8 total (2kb), 1 synced (3b), 4 checksummed (2kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 8 total (2kb), 4 checksummed (2kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='GHI', mtime=None)
    file2 = CreateFile(parent1, 'f2', contents='2'*1025, mtime=None)
    file2_renamed = CreateFile(parent1, 'f2_renamed', contents='1'*1025, mtime=None)
    file2_renamed2 = CreateFile(parent1, 'f2_renamed2', contents='1'*1025)
    RenameFile(file4, file4 + '_renamed')
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
                              '>f+++++++ par! \\r/f2_renamed',
                              '>f+++++++ par! \\r/f2_renamed2',
                              '*deleting par! \\r/f3',
                              '*deleting par! \\r/f4',
                              '>f+++++++ par! \\r/f4_renamed',
                              '*deleting par2',
                              'Paths: 8 total (4kb), 10 mismatched (5kb), 2 checksummed (1kb)'])
    DoSync(
      root_dir, dry_run=True, detect_renames=False,
      expected_output=[
        '.d......x .',
        '>fc.t.... f1',
        '.d......x par! \\r',
        '>f+++++++ par! \\r/f2_renamed',
        '>f+++++++ par! \\r/f2_renamed2',
        '*deleting par! \\r/f3',
        '*deleting par! \\r/f4',
        '>f+++++++ par! \\r/f4_renamed',
        '*deleting par2',
        'Paths: 8 total (4kb), 9 synced (3kb), 3 deleted (0b), 4 checksummed (3kb)'])
    DoSync(
      root_dir,
      expected_output=[
        '.d......x .',
        '>fc.t.... f1',
        '.d......x par! \\r',
        '>f+++++++ par! \\r/f2_renamed',
        '  replacing duplicate: .f....... par! \\r/f2',
        '>f+++++++ par! \\r/f2_renamed2',
        '  replacing similar: .f..t.... par! \\r/f2',
        '*deleting par! \\r/f3',
        '*deleting par! \\r/f4',
        '  replaced by duplicate: .f....... par! \\r/f4_renamed',
        '>f+++++++ par! \\r/f4_renamed',
        '  replacing duplicate: .f....... par! \\r/f4',
        '*deleting par2',
        'Paths: 8 total (4kb), 9 synced (3kb), 1 renamed (1kb), 2 deleted (0b), 4 checksummed (3kb)'])
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>fc...... par! \\r/f2',
                       'Paths: 8 total (4kb), 1 synced (1kb), 5 checksummed (4kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 8 total (4kb), 5 checksummed (4kb)'])

    RenameFile(file4 + '_renamed', file4)

    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['>f+++++++ par! \\r/f4',
                              '*deleting par! \\r/f4_renamed',
                              'Paths: 8 total (4kb), 2 mismatched (2kb), 4 checksummed (3kb)'])
    DoSync(
      root_dir,
      expected_output=['>f+++++++ par! \\r/f4',
                       '  replacing duplicate: .f....... par! \\r/f4_renamed',
                       '*deleting par! \\r/f4_renamed',
                       '  replaced by duplicate: .f....... par! \\r/f4',
                       'Paths: 8 total (4kb), 2 synced (1kb), 1 renamed (1kb), 1 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 8 total (4kb), 5 checksummed (4kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='GHI')
    file2 = CreateFile(parent1, 'f2', contents='3'*1025)
    file5 = CreateFile(parent1, 'f5', contents='4'*1025)
    DeleteFileOrDir(file2_renamed)
    DeleteFileOrDir(file2_renamed2)
    xattr.setxattr(root_dir, 'example', 'example_value2')
    xattr.setxattr(parent1, 'example', 'example_value2')

    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['.d......x .',
                              '.f..t.... f1',
                              '.d......x par! \\r',
                              '>fc.t.... par! \\r/f2',
                              '*deleting par! \\r/f2_renamed',
                              '*deleting par! \\r/f2_renamed2',
                              '>f+++++++ par! \\r/f5',
                              'Paths: 7 total (3kb), 7 mismatched (4kb), 3 checksummed (2kb)'])
    with SetEscapeKeyDetectorCancelAtInvocation(15):
      DoSync(
        root_dir, dry_run=True,
        expected_success=False,
        expected_output=['.d......x .',
                         '.f..t.... f1',
                         '.d......x par! \\r',
                         '>fc.t.... par! \\r/f2',
                         '*** Cancelled at path par! \\r/f4'])
    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(False)
      with SetEscapeKeyDetectorCancelAtInvocation(15):
        DoSync(
          root_dir, interactive=True,
          expected_success=False,
          expected_output=['.d......x .',
                           '.f..t.... f1',
                           '.d......x par! \\r',
                           '>fc.t.... par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 7 total (3kb), 4 synced (1kb), 2 checksummed (1kb)',
                           'Apply update? (y/N): n',
                           '*** Cancelled ***'])
    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(True)
      with SetEscapeKeyDetectorCancelAtInvocation(15):
        DoSync(
          root_dir, interactive=True,
          expected_output=['.d......x .',
                           '.f..t.... f1',
                           '.d......x par! \\r',
                           '>fc.t.... par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 7 total (3kb), 4 synced (1kb), 2 checksummed (1kb)',
                           'Apply update? (y/N): y'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['*deleting par! \\r/f2_renamed',
                              '*deleting par! \\r/f2_renamed2',
                              '>f+++++++ par! \\r/f5',
                              'Paths: 7 total (3kb), 3 mismatched (3kb), 3 checksummed (2kb)'])
    DoSync(
      root_dir,
      expected_output=['*deleting par! \\r/f2_renamed',
                       '*deleting par! \\r/f2_renamed2',
                       '>f+++++++ par! \\r/f5',
                       'Paths: 7 total (3kb), 3 synced (1kb), 2 deleted (2kb), 1 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 7 total (3kb), 4 checksummed (3kb)'])

    DeleteFileOrDir(file1)
    parent3 = CreateDir(root_dir, 'par3')
    file6 = CreateFile(root_dir, 'f6')
    file7 = CreateFile(parent3, 'f7', contents='ABC')
    file8 = CreateFile(parent3, 'f8')

    DoSync(
      root_dir, dry_run=True,
      expected_output=['*deleting f1',
                       '>f+++++++ f6',
                       '>d+++++++ par3',
                       '>f+++++++ par3/f7',
                       '>f+++++++ par3/f8',
                       'Paths: 10 total (3kb), 5 synced (3b), 1 deleted (3b), 3 checksummed (3b)'])
    DoSync(
      root_dir, dry_run=True, paths=['par3'],
      expected_output=['>d+++++++ par3',
                       '>f+++++++ par3/f7',
                       '>f+++++++ par3/f8',
                       'Paths: 3 total (3b), 3 synced (3b), 2 checksummed (3b), 7 skipped'])
    DoSync(
      root_dir, paths=['par3'],
      expected_output=['>d+++++++ par3',
                       '>f+++++++ par3/f7',
                       '>f+++++++ par3/f8',
                       'Paths: 3 total (3b), 3 synced (3b), 2 checksummed (3b), 7 skipped'])

    file7 = CreateFile(parent3, 'f7', contents='DEF')
    DeleteFileOrDir(file8)

    DoSync(
      root_dir, paths=['par3'],
      expected_output=['*deleting par3/f8',
                       'Paths: 2 total (3b), 1 synced (0b), 1 deleted (0b), 7 skipped'])
    DoSync(
      root_dir, checksum_all=True, paths=['par3'],
      expected_output=['>fc...... par3/f7',
                       'Paths: 2 total (3b), 1 synced (3b), 1 checksummed (3b), 7 skipped'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['*deleting f1',
                              '>f+++++++ f6',
                              'Paths: 9 total (3kb), 2 mismatched (3b), 4 checksummed (3kb)'])

    DoSync(
      root_dir,
      expected_output=['*deleting f1',
                       '>f+++++++ f6',
                       'Paths: 9 total (3kb), 2 synced (0b), 1 deleted (3b), 2 checksummed (3b)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 9 total (3kb), 5 checksummed (3kb)'])


def RenamePathsTest():
  with TempDir() as test_dir:
    root_dir = CreateDir(test_dir, 'root')

    DoCreate(root_dir, expected_output=None)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    file3 = CreateFile(parent1, 'f3', contents='1'*1025)

    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       'Paths: 5 total (2kb), 5 synced (2kb), 3 checksummed (2kb)'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)

    DoRenamePaths(root_dir, dry_run=True,
                  path_regex_from='f2', path_regex_to='f2_new',
                  expected_output=['.f....... par! \\r/f2',
                                   '  renamed to par! \\r/f2_new',
                                   'Paths: 5 paths, 1 renamed'])

    DoRenamePaths(root_dir, dry_run=True,
                  path_regex_from='f2', path_regex_to='f3',
                  expected_success=False,
                  expected_output=['*** Error: renamed to path par! \\r/f3 already in manifest'])

    DoRenamePaths(root_dir, dry_run=True,
                  path_regex_from='^par[!] \\r/', path_regex_to='',
                  expected_output=['.f....... par! \\r/f2',
                                   '  renamed to f2',
                                   '.f....... par! \\r/f3',
                                   '  renamed to f3',
                                   'Paths: 5 paths, 2 renamed'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)

    DoRenamePaths(root_dir, dry_run=False,
                  path_regex_from='^par[!] \\r/', path_regex_to='',
                  expected_output=['.f....... par! \\r/f2',
                                   '  renamed to f2',
                                   '.f....... par! \\r/f3',
                                   '  renamed to f3',
                                   'Paths: 5 paths, 2 renamed'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['*deleting f2',
                              '*deleting f3',
                              '>f+++++++ par! \\r/f2',
                              '>f+++++++ par! \\r/f3',
                              'Paths: 5 total (2kb), 4 mismatched (4kb), 1 checksummed (3b)'])

    RenameFile(file2, os.path.join(root_dir, 'f2'))
    RenameFile(file3, os.path.join(root_dir, 'f3'))

    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])


def Test(tests=[]):
  if not tests or 'CreateTest' in tests:
    CreateTest()
  if not tests or 'VerifyTest' in tests:
    VerifyTest()
  if not tests or 'SyncTest' in tests:
    SyncTest()
  if not tests or 'RenamePathsTest' in tests:
    RenamePathsTest()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  Test(tests=args.tests)
