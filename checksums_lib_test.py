#!/usr/bin/env -S python3 -u -B

import argparse
import contextlib
import io
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir))
import backups_lib
__package__ = backups_lib.__package__

from . import checksums_lib
from . import lib
from . import lib_test_util
from . import test_main

from .test_util import AssertDiskImageFormat
from .test_util import AssertEquals
from .test_util import AssertLinesEqual
from .test_util import AssertNotEquals
from .test_util import BaseTestCase
from .test_util import CreateDir
from .test_util import CreateDirs
from .test_util import CreateFile
from .test_util import CreateSymlink
from .test_util import DeleteFileOrDir
from .test_util import GetRsyncCreatedDirectoryOutputLines
from .test_util import RenameFile
from .test_util import SetMTime
from .test_util import TempDir

from .lib_test_util import ApplyFakeDiskImageHelperLevel
from .lib_test_util import AssertFileSizeInRange
from .lib_test_util import GetFileTreeManifest
from .lib_test_util import HandleGetPass
from .lib_test_util import InteractiveCheckerReadyResults
from .lib_test_util import SetEscapeKeyDetectorCancelAtInvocation
from .lib_test_util import SetXattr

from .checksums_lib_test_util import DoCreate
from .checksums_lib_test_util import DoDeleteDuplicateFiles
from .checksums_lib_test_util import DoDiff
from .checksums_lib_test_util import DoImageFromFolder
from .checksums_lib_test_util import DoRenamePaths
from .checksums_lib_test_util import DoRestoreMeta
from .checksums_lib_test_util import DoSafeCopy
from .checksums_lib_test_util import DoSafeMove
from .checksums_lib_test_util import DoSync
from .checksums_lib_test_util import DoVerify
from .checksums_lib_test_util import SafeMoveOrCopyForceFromParentDirMtimeChangeForTest
from .checksums_lib_test_util import SetMaxRenameDetectionMatchingSizeFileCount


class CreateTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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


class DiffTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir1 = CreateDir(test_dir, 'root1')
    file1 = CreateFile(root_dir1, 'f1', contents='1'*1025)
    parent1 = CreateDir(root_dir1, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='2'*2025)
    ln1 = CreateSymlink(root_dir1, 'ln1', 'INVALID')

    root_dir2 = CreateDir(test_dir, 'root2')
    file1_2 = CreateFile(root_dir2, 'f1', contents='1'*1025)
    parent1_2 = CreateDir(root_dir2, 'par! \r')
    file2_2 = CreateFile(parent1_2, 'f2', contents='2'*2025)
    ln1_2 = CreateSymlink(root_dir2, 'ln1', 'INVALID')

    DoDiff(
      root_dir1,
      root_dir2,
      expected_success=False,
      expected_output=['*** Error: Could not determine the checksums root path for %s' % root_dir1,
                       '*** Error: Could not determine the checksums root path for %s' % root_dir2])

    DoCreate(root_dir1, expected_output=None)
    DoCreate(root_dir2, expected_output=None)

    DoDiff(
      root_dir1,
      root_dir2,
      expected_output=['Paths: 0 total'])
    DoDiff(
      root_dir1,
      root_dir2,
      root_path1=parent1,
      expected_success=False,
      expected_output=['*** Error: Manifest file %s/.metadata/manifest.pbdata should exist' % parent1])

    DoSync(root_dir1, expected_output=None)
    DoSync(root_dir2, expected_output=None)

    DoDiff(
      root_dir1,
      root_dir2,
      expected_output=['Paths: 5 total, 5 matched (3kb)'])
    DoDiff(
      parent1,
      parent1_2,
      expected_output=['Paths: 2 total, 2 matched (2kb)'])
    DoDiff(
      file1,
      file2,
      expected_success=False,
      expected_output=['>fcs..... .',
                       'Paths: 1 total, 1 mismatched (2kb)'])
    DoDiff(
      root_dir1,
      parent1,
      expected_success=False,
      expected_output=['.d..t.... .',
                       '*f.delete f1',
                       '>f+++++++ f2',
                       '  replacing duplicate: .f....... par! \\r/f2',
                       '*L.delete ln1',
                       '*d.delete par! \\r',
                       '*f.delete par! \\r/f2',
                       '  replaced by duplicate: .f....... f2',
                       'Paths: 6 total, 6 mismatched (5kb)'])
    DoDiff(
      parent1,
      root_dir2,
      expected_success=False,
      expected_output=['.d..t.... .',
                       '>f+++++++ f1',
                       '*f.delete f2',
                       '  replaced by duplicate: .f....... par! \\r/f2',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       '  replacing duplicate: .f....... f2',
                       'Paths: 6 total, 6 mismatched (5kb)'])


class VerifyTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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


class SyncTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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

    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(False)
      with SetEscapeKeyDetectorCancelAtInvocation(14):
        DoSync(
          root_dir, dry_run=True,
          expected_success=False,
          expected_output=['.Lc...... ln1 -> f1',
                           '.f..t.... par! \\r/f2',
                           '*** Cancelled at path par! \\r/f3',
                           'Paths: 8 total (2kb), 2 synced (1kb), 1 checksummed (1kb)',
                           'Apply update? (y/N): n',
                           '*** Cancelled ***'])
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
    file4_dup1 = CreateFile(parent1, 'f4_dup1', contents='4'*1026, mtime=None)
    file4_dup2 = CreateFile(parent1, 'f4_dup2', contents='4'*1026, mtime=None)
    SetXattr(root_dir, 'example', b'example_value')
    SetXattr(parent1, 'example', b'example_value')
    DeleteFileOrDir(file3)
    DeleteFileOrDir(parent2)

    DoVerify(
      root_dir, checksum_all=True,
      expected_success=False,
      expected_output=[
        '.d......x .',
        '>fc.t.... f1',
        '.d......x par! \\r',
        '>fc...... par! \\r/f2',
        '>f+++++++ par! \\r/f2_renamed',
        '>f+++++++ par! \\r/f2_renamed2',
        '*f.delete par! \\r/f3',
        '*f.delete par! \\r/f4',
        '>f+++++++ par! \\r/f4_dup1',
        '>f+++++++ par! \\r/f4_dup2',
        '>f+++++++ par! \\r/f4_renamed',
        '*d.delete par2',
        'Paths: 10 total (6kb), 12 mismatched (7kb), 2 checksummed (1kb)'])
    DoSync(
      root_dir, dry_run=True, detect_renames=False,
      expected_output=[
        '.d......x .',
        '>fc.t.... f1',
        '.d......x par! \\r',
        '>f+++++++ par! \\r/f2_renamed',
        '>f+++++++ par! \\r/f2_renamed2',
        '*f.delete par! \\r/f3',
        '*f.delete par! \\r/f4',
        '>f+++++++ par! \\r/f4_dup1',
        '>f+++++++ par! \\r/f4_dup2',
        '>f+++++++ par! \\r/f4_renamed',
        '*d.delete par2',
        'Paths: 10 total (6kb), 11 synced (5kb), 3 deleted (1kb), 6 checksummed (5kb)'])
    DoSync(
      root_dir, dry_run=True,
      expected_output=[
        '.d......x .',
        '>fc.t.... f1',
        '.d......x par! \\r',
        '>f+++++++ par! \\r/f2_renamed',
        '  replacing duplicate: .f....... par! \\r/f2',
        '>f+++++++ par! \\r/f2_renamed2',
        '  replacing similar: .f..t.... par! \\r/f2',
        '*f.delete par! \\r/f3',
        '*f.delete par! \\r/f4',
        '  replaced by duplicate: .f....... par! \\r/f4_dup1',
        '  replaced by duplicate: .f....... par! \\r/f4_dup2',
        '  replaced by duplicate: .f....... par! \\r/f4_renamed',
        '>f+++++++ par! \\r/f4_dup1',
        '  replacing duplicate: .f....... par! \\r/f4',
        '>f+++++++ par! \\r/f4_dup2',
        '  replacing duplicate: .f....... par! \\r/f4',
        '>f+++++++ par! \\r/f4_renamed',
        '  replacing duplicate: .f....... par! \\r/f4',
        '*d.delete par2',
        'Paths: 10 total (6kb), 11 synced (5kb), 1 renamed (1kb), 2 deleted (0b), 6 checksummed (5kb)'])
    with SetMaxRenameDetectionMatchingSizeFileCount(1):
      DoSync(
        root_dir, dry_run=True,
        expected_output=[
          '.d......x .',
          '>fc.t.... f1',
          '.d......x par! \\r',
          '>f+++++++ par! \\r/f2_renamed',
          '  replacing duplicate: .f....... par! \\r/f2',
          '>f+++++++ par! \\r/f2_renamed2',
          '  replacing similar: .f..t.... par! \\r/f2',
          '*f.delete par! \\r/f3',
          '*f.delete par! \\r/f4',
          '  too many potential renames to check: 3 > 1',
          '>f+++++++ par! \\r/f4_dup1',
          '  replacing duplicate: .f....... par! \\r/f4',
          '>f+++++++ par! \\r/f4_dup2',
          '  replacing duplicate: .f....... par! \\r/f4',
          '>f+++++++ par! \\r/f4_renamed',
          '  replacing duplicate: .f....... par! \\r/f4',
          '*d.delete par2',
          'Paths: 10 total (6kb), 11 synced (5kb), 3 deleted (1kb), 6 checksummed (5kb)'])
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
        '*f.delete par! \\r/f3',
        '*f.delete par! \\r/f4',
        '  replaced by duplicate: .f....... par! \\r/f4_dup1',
        '  replaced by duplicate: .f....... par! \\r/f4_dup2',
        '  replaced by duplicate: .f....... par! \\r/f4_renamed',
        '>f+++++++ par! \\r/f4_dup1',
        '  replacing duplicate: .f....... par! \\r/f4',
        '>f+++++++ par! \\r/f4_dup2',
        '  replacing duplicate: .f....... par! \\r/f4',
        '>f+++++++ par! \\r/f4_renamed',
        '  replacing duplicate: .f....... par! \\r/f4',
        '*d.delete par2',
        'Paths: 10 total (6kb), 11 synced (5kb), 1 renamed (1kb), 2 deleted (0b), 6 checksummed (5kb)'])
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>fc...... par! \\r/f2',
                       '  replaced by duplicate: .f....... par! \\r/f2_renamed',
                       '  replaced by similar: .f..t.... par! \\r/f2_renamed2',
                       'Paths: 10 total (6kb), 1 synced (1kb), 7 checksummed (6kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 10 total (6kb), 7 checksummed (6kb)'])

    RenameFile(file4 + '_renamed', file4)

    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['>f+++++++ par! \\r/f4',
                              '*f.delete par! \\r/f4_renamed',
                              'Paths: 10 total (6kb), 2 mismatched (2kb), 6 checksummed (5kb)'])
    DoSync(
      root_dir,
      expected_output=[
        '>f+++++++ par! \\r/f4',
        '  replacing duplicate: .f....... par! \\r/f4_dup1',
        '  replacing duplicate: .f....... par! \\r/f4_dup2',
        '  replacing duplicate: .f....... par! \\r/f4_renamed',
        '*f.delete par! \\r/f4_renamed',
        '  replaced by duplicate: .f....... par! \\r/f4_dup1',
        '  replaced by duplicate: .f....... par! \\r/f4_dup2',
        '  replaced by duplicate: .f....... par! \\r/f4',
        'Paths: 10 total (6kb), 2 synced (1kb), 1 renamed (1kb), 1 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 10 total (6kb), 7 checksummed (6kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='GHI')
    file2 = CreateFile(parent1, 'f2', contents='3'*1025)
    file5 = CreateFile(parent1, 'f5', contents='4'*1025)
    DeleteFileOrDir(file2_renamed)
    DeleteFileOrDir(file2_renamed2)
    SetXattr(root_dir, 'example', b'example_value2')
    SetXattr(parent1, 'example', b'example_value2')

    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['.d......x .',
                              '.f..t.... f1',
                              '.d......x par! \\r',
                              '>fc.t.... par! \\r/f2',
                              '*f.delete par! \\r/f2_renamed',
                              '*f.delete par! \\r/f2_renamed2',
                              '>f+++++++ par! \\r/f5',
                              'Paths: 9 total (5kb), 7 mismatched (4kb), 5 checksummed (4kb)'])
    with InteractiveCheckerReadyResults(
        checksums_lib.ChecksumsSyncer.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(False)
      with SetEscapeKeyDetectorCancelAtInvocation(15):
        DoSync(
          root_dir, dry_run=True,
          expected_success=False,
          expected_output=['.d......x .',
                           '.f..t.... f1',
                           '.d......x par! \\r',
                           '*** Cancelled at path par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 9 total (5kb), 3 synced (3b), 2 checksummed (1kb)',
                           'Apply update? (y/N): n',
                           '*** Cancelled ***'])
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
                           '*** Cancelled at path par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 9 total (5kb), 3 synced (3b), 2 checksummed (1kb)',
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
                           '*** Cancelled at path par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 9 total (5kb), 3 synced (3b), 2 checksummed (1kb)',
                           'Apply update? (y/N): y'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['*f.delete par! \\r/f2_renamed',
                              '*f.delete par! \\r/f2_renamed2',
                              '>f+++++++ par! \\r/f5',
                              'Paths: 9 total (5kb), 3 mismatched (3kb), 5 checksummed (4kb)'])
    DoSync(
      root_dir,
      expected_output=['*f.delete par! \\r/f2_renamed',
                       '*f.delete par! \\r/f2_renamed2',
                       '>f+++++++ par! \\r/f5',
                       'Paths: 9 total (5kb), 3 synced (1kb), 2 deleted (2kb), 1 checksummed (1kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 9 total (5kb), 6 checksummed (5kb)'])

    DeleteFileOrDir(file1)
    parent3 = CreateDir(root_dir, 'par3')
    file6 = CreateFile(root_dir, 'f6')
    file7 = CreateFile(parent3, 'f7', contents='ABC')
    file8 = CreateFile(parent3, 'f8')

    DoSync(
      root_dir, dry_run=True,
      expected_output=['*f.delete f1',
                       '>f+++++++ f6',
                       '>d+++++++ par3',
                       '>f+++++++ par3/f7',
                       '>f+++++++ par3/f8',
                       'Paths: 12 total (5kb), 5 synced (3b), 1 deleted (3b), 3 checksummed (3b)'])
    DoSync(
      root_dir, dry_run=True, paths=['par3'],
      expected_output=['>d+++++++ par3',
                       '>f+++++++ par3/f7',
                       '>f+++++++ par3/f8',
                       'Paths: 3 total (3b), 3 synced (3b), 2 checksummed (3b), 9 skipped'])
    DoSync(
      root_dir, paths=['par3'],
      expected_output=['>d+++++++ par3',
                       '>f+++++++ par3/f7',
                       '>f+++++++ par3/f8',
                       'Paths: 3 total (3b), 3 synced (3b), 2 checksummed (3b), 9 skipped'])

    file7 = CreateFile(parent3, 'f7', contents='DEF')
    DeleteFileOrDir(file8)

    DoSync(
      root_dir, paths=['par3'],
      expected_output=['*f.delete par3/f8',
                       'Paths: 2 total (3b), 1 synced (0b), 1 deleted (0b), 9 skipped'])
    DoSync(
      root_dir, checksum_all=True, paths=['par3'],
      expected_output=['>fc...... par3/f7',
                       'Paths: 2 total (3b), 1 synced (3b), 1 checksummed (3b), 9 skipped'])
    DoVerify(root_dir, checksum_all=True,
             expected_success=False,
             expected_output=['*f.delete f1',
                              '>f+++++++ f6',
                              'Paths: 11 total (5kb), 2 mismatched (3b), 6 checksummed (5kb)'])

    DoSync(
      root_dir,
      expected_output=['*f.delete f1',
                       '>f+++++++ f6',
                       'Paths: 11 total (5kb), 2 synced (0b), 1 deleted (3b), 2 checksummed (3b)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 11 total (5kb), 7 checksummed (5kb)'])

    file8 = CreateFile(parent3, 'f8', contents='8'*1024)
    file9 = CreateFile(parent3, 'f9', contents='9'*1024)
    file10 = CreateFile(parent3, 'f10', contents='10'*513)

    DoSync(
      root_dir,
      expected_output=['>f+++++++ par3/f10',
                       '>f+++++++ par3/f8',
                       '>f+++++++ par3/f9',
                       'Paths: 14 total (8kb), 3 synced (3kb), 3 checksummed (3kb)'])

    RenameFile(file8, file8 + '.tmp')
    RenameFile(file9, file8)
    RenameFile(file8 + '.tmp', file9)

    DoSync(
      root_dir, dry_run=True,
      expected_output=['Paths: 14 total (8kb)'])
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>fc...... par3/f8',
                       '  replaced by duplicate: .f....... par3/f9',
                       '>fc...... par3/f9',
                       '  replaced by duplicate: .f....... par3/f8',
                       'Paths: 14 total (8kb), 2 synced (2kb), 10 checksummed (8kb)'])

    RenameFile(file10, file10 + '.tmp')
    RenameFile(file9, file10)
    RenameFile(file10 + '.tmp', file9)

    DoSync(
      root_dir,
      expected_output=['>fcs..... par3/f10',
                       '  replaced by duplicate: .f....... par3/f9',
                       '>fcs..... par3/f9',
                       '  replaced by duplicate: .f....... par3/f10',
                       'Paths: 14 total (8kb), 2 synced (2kb), 2 checksummed (2kb)'])

    DeleteFileOrDir(file10)
    RenameFile(file9, file10)
    RenameFile(file8, file9)

    DoSync(
      root_dir,
      expected_output=[
        '>fcs..... par3/f10',
        '*f.delete par3/f8',
        '  replaced by duplicate: .f....... par3/f9',
        '>fcs..... par3/f9',
        '  replaced by duplicate: .f....... par3/f10',
        'Paths: 13 total (7kb), 3 synced (2kb), 1 renamed (1kb), 2 checksummed (2kb)'])


class RenamePathsTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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
                  expected_output=['*** Error: Renamed to path par! \\r/f3 already in manifest'])

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
             expected_output=['*f.delete f2',
                              '*f.delete f3',
                              '>f+++++++ par! \\r/f2',
                              '>f+++++++ par! \\r/f3',
                              'Paths: 5 total (2kb), 4 mismatched (4kb), 1 checksummed (3b)'])

    RenameFile(file2, os.path.join(root_dir, 'f2'))
    RenameFile(file3, os.path.join(root_dir, 'f3'))

    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])


class ImageFromFolderTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_NONE, test_case=self) as should_run:
      if should_run:
        with TempDir() as test_dir:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')

    image_ext = '.dmg'
    if platform.system() == lib.PLATFORM_LINUX:
      image_ext = '.img'

    image_path = os.path.join(test_dir, '1 $ " [ \\%s' % image_ext)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    SetXattr(file2, 'example', b'example_value')
    ln1 = CreateSymlink(root_dir, 'ln1', 'f1')
    ln2 = CreateSymlink(root_dir, 'ln2', 'INVALID')
    SetXattr(root_dir, 'example', b'example_value')

    DoImageFromFolder(root_dir, output_path=image_path, dry_run=True,
                      expected_output=[])
    if platform.system() == lib.PLATFORM_DARWIN:
      DoImageFromFolder(
        root_dir, output_path=image_path,
        expected_output=[
          'Creating temporary image from folder %s...' % root_dir,
          '>d+++++++ .',
          '>f+++++++ f1',
          '>L+++++++ ln1 -> f1',
          '>L+++++++ ln2 -> INVALID',
          '>d+++++++ par! \\r',
          '>f+++++++ par! \\r/f2',
          'Paths: 6 total (1kb), 6 synced (1kb), 2 checksummed (1kb)',
          'Converting to image %s with format UDZO...' % lib.EscapePath(image_path),
          'Verifying checksums in %s...' % lib.EscapePath(image_path),
          'Verifying source tree matches...',
          re.compile('^Created image %s [(]1[67]([.][0-9])?kb[)]; Source size 1kb$'
                     % re.escape(lib.EscapePath(image_path)))])
      AssertDiskImageFormat('UDZO', image_path)
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '16kb', '17.9kb')

      DoVerify(image_path,
               expected_output=['Paths: 6 total (1kb)'])
      DoVerify(image_path, checksum_all=True,
               expected_output=['Paths: 6 total (1kb), 2 checksummed (1kb)'])
    else:
      DoImageFromFolder(
        root_dir, output_path=image_path,
        expected_output=[
          'Creating temporary image from folder %s...' % root_dir,
          '>d+++++++ .',
          '>f+++++++ f1',
          '>L+++++++ ln1 -> f1',
          '>L+++++++ ln2 -> INVALID',
          '>d+++++++ lost+found',
          '>d+++++++ par! \\r',
          '>f+++++++ par! \\r/f2',
          'Paths: 7 total (1kb), 7 synced (1kb), 2 checksummed (1kb)',
          'Converting to read only image %s...' % lib.EscapePath(image_path),
          re.compile('^e2fsck .*$'),
          'Pass 1: Checking inodes, blocks, and sizes',
          'Pass 2: Checking directory structure',
          'Pass 3: Checking directory connectivity',
          'Pass 4: Checking reference counts',
          'Pass 5: Checking group summary information',
          re.compile('^[^ ]+[.]img: 18/25616 files [(]5.6% non-contiguous[)], 2652/25602 blocks'),
          re.compile('^resize2fs .*$'),
          re.compile('^Resizing the filesystem on [^ ]+[.]img to 2670 [(]4k[)] blocks.$'),
          re.compile('^The filesystem on [^ ]+[.]img is now 2670 [(]4k[)] blocks long.$'),
          re.compile('^e2fsck .*$'),
          'Pass 1: Checking inodes, blocks, and sizes',
          'Pass 2: Checking directory structure',
          'Pass 3: Checking directory connectivity',
          'Pass 4: Checking reference counts',
          'Pass 5: Checking group summary information',
          re.compile('^[^ ]+[.]img: 18/25616 files [(]5.6% non-contiguous[)], 2652/2670 blocks'),
          'Image size 100mb -> 10.4mb',
          'Verifying checksums in %s...' % lib.EscapePath(image_path),
          'Verifying source tree matches...',
          re.compile('^Created image %s [(]10[.]4?mb[)]; Source size 1kb$'
                     % re.escape(lib.EscapePath(image_path)))])
      AssertDiskImageFormat('ext4', image_path)
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '10mb', '11mb')

      DoVerify(image_path,
               expected_output=['Paths: 7 total (1kb)'])
      DoVerify(image_path, checksum_all=True,
               expected_output=['Paths: 7 total (1kb), 2 checksummed (1kb)'])

    DoImageFromFolder(
      root_dir, output_path=image_path, dry_run=True, expected_success=False,
      expected_output=['*** Error: Output path %s already exists' % lib.EscapePath(image_path)])
    DeleteFileOrDir(image_path)

    DoCreate(root_dir, expected_output=None)
    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>L+++++++ ln1 -> f1',
                       '>L+++++++ ln2 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 6 total (1kb), 6 synced (1kb), 2 checksummed (1kb)'])

    DoImageFromFolder(root_dir, output_path=image_path, dry_run=True,
                      expected_output=[])
    if platform.system() == lib.PLATFORM_DARWIN:
      DoImageFromFolder(
        root_dir, output_path=image_path,
        expected_output=[
          'Creating temporary image from folder %s...' % root_dir,
          'Using existing manifest from source path',
          'Converting to image %s with format UDZO...' % lib.EscapePath(image_path),
          'Verifying checksums in %s...' % lib.EscapePath(image_path),
          'Verifying source tree matches...',
          re.compile('^Created image %s [(]1[67]([.][0-9])?kb[)]; Source size 1kb$'
                     % re.escape(lib.EscapePath(image_path)))])
      AssertDiskImageFormat('UDZO', image_path)
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '16kb', '18kb')
    else:
      DoImageFromFolder(
        root_dir, output_path=image_path,
        expected_output=[
          'Creating temporary image from folder %s...' % root_dir,
          'Using existing manifest from source path',
          '>d+++++++ lost+found',
          'Paths: 7 total (1kb), 1 synced (0b), 2 checksummed (1kb)',
          'Converting to read only image %s...' % lib.EscapePath(image_path),
          re.compile('^e2fsck .*$'),
          'Pass 1: Checking inodes, blocks, and sizes',
          'Pass 2: Checking directory structure',
          'Pass 3: Checking directory connectivity',
          'Pass 4: Checking reference counts',
          'Pass 5: Checking group summary information',
          re.compile('^[^ ]+[.]img: 18/25616 files [(]5.6% non-contiguous[)], 2652/25603 blocks'),
          re.compile('^resize2fs .*$'),
          re.compile('^Resizing the filesystem on [^ ]+[.]img to 2670 [(]4k[)] blocks.$'),
          re.compile('^The filesystem on [^ ]+[.]img is now 2670 [(]4k[)] blocks long.$'),
          re.compile('^e2fsck .*$'),
          'Pass 1: Checking inodes, blocks, and sizes',
          'Pass 2: Checking directory structure',
          'Pass 3: Checking directory connectivity',
          'Pass 4: Checking reference counts',
          'Pass 5: Checking group summary information',
          re.compile('^[^ ]+[.]img: 18/25616 files [(]5.6% non-contiguous[)], 2652/2670 blocks'),
          'Image size 100mb -> 10.4mb',
          'Verifying checksums in %s...' % lib.EscapePath(image_path),
          'Verifying source tree matches...',
          re.compile('^Created image %s [(]10([.]4)?mb[)]; Source size 1kb$'
                     % re.escape(lib.EscapePath(image_path)))])
      AssertDiskImageFormat('ext4', image_path)
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '10mb', '11mb')

    DeleteFileOrDir(image_path)

    if platform.system() == lib.PLATFORM_DARWIN:
      DoImageFromFolder(
        root_dir, output_path=image_path, compressed=False,
        expected_output=[
          'Creating temporary image from folder %s...' % root_dir,
          'Using existing manifest from source path',
          'Converting to image %s with format UDRO...' % lib.EscapePath(image_path),
          'Verifying checksums in %s...' % lib.EscapePath(image_path),
          'Verifying source tree matches...',
          re.compile('^Created image %s [(]5[0-9][0-9]([.][0-9])?kb[)]; Source size 1kb$'
                     % re.escape(lib.EscapePath(image_path)))])
      AssertDiskImageFormat('UDRO', image_path)
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '500kb', '600kb')
    else:
      DoImageFromFolder(
        root_dir, output_path=image_path, compressed=False,
        expected_output=[
          'Creating temporary image from folder %s...' % root_dir,
          'Using existing manifest from source path',
          '>d+++++++ lost+found',
          'Paths: 7 total (1kb), 1 synced (0b), 2 checksummed (1kb)',
          'Converting to read only image %s...' % lib.EscapePath(image_path),
          re.compile('^e2fsck .*$'),
          'Pass 1: Checking inodes, blocks, and sizes',
          'Pass 2: Checking directory structure',
          'Pass 3: Checking directory connectivity',
          'Pass 4: Checking reference counts',
          'Pass 5: Checking group summary information',
          re.compile('^[^ ]+[.]img: 18/25616 files [(]5.6% non-contiguous[)], 2652/25603 blocks'),
          re.compile('^resize2fs .*$'),
          re.compile('^Resizing the filesystem on [^ ]+[.]img to 2670 [(]4k[)] blocks.$'),
          re.compile('^The filesystem on [^ ]+[.]img is now 2670 [(]4k[)] blocks long.$'),
          re.compile('^e2fsck .*$'),
          'Pass 1: Checking inodes, blocks, and sizes',
          'Pass 2: Checking directory structure',
          'Pass 3: Checking directory connectivity',
          'Pass 4: Checking reference counts',
          'Pass 5: Checking group summary information',
          re.compile('^[^ ]+[.]img: 18/25616 files [(]5.6% non-contiguous[)], 2652/2670 blocks'),
          'Image size 100mb -> 10.4mb',
          'Verifying checksums in %s...' % lib.EscapePath(image_path),
          'Verifying source tree matches...',
          re.compile('^Created image %s [(]10([.]4)?mb[)]; Source size 1kb$'
                     % re.escape(lib.EscapePath(image_path)))])
      AssertDiskImageFormat('ext4', image_path)
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '10mb', '11mb')

    DeleteFileOrDir(image_path)

    DoImageFromFolder(root_dir, output_path=image_path, temp_dir='/dev/null', expected_success=False,
                      expected_output=['*** Error: Temporary dir /dev/null is not a directory'])


class ImageFromFolderWithEncryptionTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_NONE, test_case=self) as should_run:
      if should_run:
        with TempDir() as test_dir:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')

    image_ext = '.dmg'
    if platform.system() == lib.PLATFORM_LINUX:
      image_ext = '.luks.img'

    image_path = os.path.join(test_dir, '1%s' % image_ext)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    SetXattr(file2, 'example', b'example_value')
    ln1 = CreateSymlink(root_dir, 'ln1', 'f1')
    ln2 = CreateSymlink(root_dir, 'ln2', 'INVALID')
    SetXattr(root_dir, 'example', b'example_value')

    DoImageFromFolder(root_dir, output_path=image_path, encrypt=True, dry_run=True,
                      expected_output=[])
    with HandleGetPass(
        expected_prompts=['Enter a new password to secure "1%s": ' % image_ext,
                          'Re-enter new password: '],
        returned_passwords=['abc $ [ "', 'abc $ [ "']):
      if platform.system() == lib.PLATFORM_DARWIN:
        DoImageFromFolder(
          root_dir, output_path=image_path, encrypt=True,
          expected_output=[
            'Creating temporary image from folder %s...' % root_dir,
            '>d+++++++ .',
            '>f+++++++ f1',
            '>L+++++++ ln1 -> f1',
            '>L+++++++ ln2 -> INVALID',
            '>d+++++++ par! \\r',
            '>f+++++++ par! \\r/f2',
            'Paths: 6 total (1kb), 6 synced (1kb), 2 checksummed (1kb)',
            'Converting to image %s with format UDZO...' % lib.EscapePath(image_path),
            'Verifying checksums in %s...' % lib.EscapePath(image_path),
            'Verifying source tree matches...',
            re.compile('^Created image %s [(]13[67]([.][0-9])?kb[)]; Source size 1kb$'
                       % re.escape(lib.EscapePath(image_path)))])
        AssertDiskImageFormat('UDZO', image_path, password='abc $ [ "')
        AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '130kb', '140kb')
      else:
        DoImageFromFolder(
          root_dir, output_path=image_path, encrypt=True,
          expected_output=[
            'Creating temporary image from folder %s...' % root_dir,
            '>d+++++++ .',
            '>f+++++++ f1',
            '>L+++++++ ln1 -> f1',
            '>L+++++++ ln2 -> INVALID',
            '>d+++++++ lost+found',
            '>d+++++++ par! \\r',
            '>f+++++++ par! \\r/f2',
            'Paths: 7 total (1kb), 7 synced (1kb), 2 checksummed (1kb)',
            'Converting to read only image %s...' % lib.EscapePath(image_path),
            re.compile('^e2fsck .*$'),
            'Pass 1: Checking inodes, blocks, and sizes',
            'Pass 2: Checking directory structure',
            'Pass 3: Checking directory connectivity',
            'Pass 4: Checking reference counts',
            'Pass 5: Checking group summary information',
            re.compile('^/dev/mapper/[^ ]+: 18/21520 files [(]5.6% non-contiguous[)], 2394/21506 blocks'),
            re.compile('^resize2fs .*$'),
            re.compile('^Resizing the filesystem on /dev/mapper/[^ ]+ to 2412 [(]4k[)] blocks.$'),
            re.compile('^The filesystem on /dev/mapper/[^ ]+ is now 2412 [(]4k[)] blocks long.$'),
            re.compile('^e2fsck .*$'),
            'Pass 1: Checking inodes, blocks, and sizes',
            'Pass 2: Checking directory structure',
            'Pass 3: Checking directory connectivity',
            'Pass 4: Checking reference counts',
            'Pass 5: Checking group summary information',
            re.compile('^/dev/mapper/[^ ]+: 18/21520 files [(]5.6% non-contiguous[)], 2394/2412 blocks'),
            'Image size 100mb -> 25.4mb',
            'Verifying checksums in %s...' % lib.EscapePath(image_path),
            'Verifying source tree matches...',
            re.compile('^Created image %s [(]25[.]4?mb[)]; Source size 1kb$'
                       % re.escape(lib.EscapePath(image_path)))])
        AssertDiskImageFormat('crypto_LUKS', image_path)
        AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '25mb', '26mb')

    with HandleGetPass(
        expected_prompts=[re.compile('^Enter password to access "[^"]+%s": $' % image_ext),
                          re.compile('^Enter password to access "[^"]+%s": $' % image_ext)],
        returned_passwords=['def', 'abc $ [ "']):
      if platform.system() == lib.PLATFORM_DARWIN:
        DoVerify(image_path,
                 expected_output=['Paths: 6 total (1kb)'])
      else:
        DoVerify(image_path,
                 expected_output=['Paths: 7 total (1kb)'])
    with HandleGetPass(
        expected_prompts=[re.compile('^Enter password to access "[^"]+%s": $' % image_ext)],
        returned_passwords=['abc $ [ "']):
      if platform.system() == lib.PLATFORM_DARWIN:
        DoVerify(image_path,
                 expected_output=['Paths: 6 total (1kb)'])
      else:
        DoVerify(image_path,
                 expected_output=['Paths: 7 total (1kb)'])
    with HandleGetPass(
        expected_prompts=[re.compile('^Enter password to access "[^"]+%s": $' % image_ext)],
        returned_passwords=['abc $ [ "']):
      if platform.system() == lib.PLATFORM_DARWIN:
        DoVerify(image_path, checksum_all=True,
                 expected_output=['Paths: 6 total (1kb), 2 checksummed (1kb)'])
      else:
        DoVerify(image_path, checksum_all=True,
                 expected_output=['Paths: 7 total (1kb), 2 checksummed (1kb)'])

    DoImageFromFolder(
      root_dir, output_path=image_path,  encrypt=True, dry_run=True, expected_success=False,
      expected_output=['*** Error: Output path %s already exists' % lib.EscapePath(image_path)])
    DeleteFileOrDir(image_path)

    DoCreate(root_dir, expected_output=None)
    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>L+++++++ ln1 -> f1',
                       '>L+++++++ ln2 -> INVALID',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       'Paths: 6 total (1kb), 6 synced (1kb), 2 checksummed (1kb)'])

    DoImageFromFolder(root_dir, output_path=image_path,  encrypt=True, dry_run=True,
                      expected_output=[])
    with HandleGetPass(
        expected_prompts=['Enter a new password to secure "1%s": ' % image_ext,
                          'Re-enter new password: '],
        returned_passwords=['abc $ [ "', 'abc $ [ "']):
      if platform.system() == lib.PLATFORM_DARWIN:
        DoImageFromFolder(
          root_dir, output_path=image_path, encrypt=True,
          expected_output=[
            'Creating temporary image from folder %s...' % root_dir,
            'Using existing manifest from source path',
            'Converting to image %s with format UDZO...' % lib.EscapePath(image_path),
            'Verifying checksums in %s...' % lib.EscapePath(image_path),
            'Verifying source tree matches...',
            re.compile('^Created image %s [(]13[67]([.][0-9])?kb[)]; Source size 1kb$'
                       % re.escape(lib.EscapePath(image_path)))])
        AssertDiskImageFormat('UDZO', image_path, password='abc $ [ "')
        AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '130kb', '140kb')
      else:
        DoImageFromFolder(
          root_dir, output_path=image_path, encrypt=True,
          expected_output=[
            'Creating temporary image from folder %s...' % root_dir,
            'Using existing manifest from source path',
            '>d+++++++ lost+found',
            'Paths: 7 total (1kb), 1 synced (0b), 2 checksummed (1kb)',
            'Converting to read only image %s...' % lib.EscapePath(image_path),
            re.compile('^e2fsck .*$'),
            'Pass 1: Checking inodes, blocks, and sizes',
            'Pass 2: Checking directory structure',
            'Pass 3: Checking directory connectivity',
            'Pass 4: Checking reference counts',
            'Pass 5: Checking group summary information',
            re.compile('^/dev/mapper/[^ ]+: 18/21520 files [(]5.6% non-contiguous[)], 2394/21507 blocks'),
            re.compile('^resize2fs .*$'),
            re.compile('^Resizing the filesystem on /dev/mapper/[^ ]+ to 2412 [(]4k[)] blocks.$'),
            re.compile('^The filesystem on /dev/mapper/[^ ]+ is now 2412 [(]4k[)] blocks long.$'),
            re.compile('^e2fsck .*$'),
            'Pass 1: Checking inodes, blocks, and sizes',
            'Pass 2: Checking directory structure',
            'Pass 3: Checking directory connectivity',
            'Pass 4: Checking reference counts',
            'Pass 5: Checking group summary information',
            re.compile('^/dev/mapper/[^ ]+: 18/21520 files [(]5.6% non-contiguous[)], 2394/2412 blocks'),
            'Image size 100mb -> 25.4mb',
            'Verifying checksums in %s...' % lib.EscapePath(image_path),
            'Verifying source tree matches...',
            re.compile('^Created image %s [(]25([.]4)?mb[)]; Source size 1kb$'
                       % re.escape(lib.EscapePath(image_path)))])
        AssertDiskImageFormat('crypto_LUKS', image_path)
        AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '25mb', '26mb')

    DeleteFileOrDir(image_path)

    with HandleGetPass(
        expected_prompts=['Enter a new password to secure "1%s": ' % image_ext,
                          'Re-enter new password: '],
        returned_passwords=['abc $ [ "', 'abc $ [ "']):
      if platform.system() == lib.PLATFORM_DARWIN:
        DoImageFromFolder(
          root_dir, output_path=image_path, encrypt=True, compressed=False,
          expected_output=[
            'Creating temporary image from folder %s...' % root_dir,
            'Using existing manifest from source path',
            'Converting to image %s with format UDRO...' % lib.EscapePath(image_path),
            'Verifying checksums in %s...' % lib.EscapePath(image_path),
            'Verifying source tree matches...',
            re.compile('^Created image %s [(][5-6][0-9][0-9]([.][0-9])?kb[)]; Source size 1kb$'
                       % re.escape(lib.EscapePath(image_path)))])
        AssertDiskImageFormat('UDRO', image_path, password='abc $ [ "')
        AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '500kb', '700kb')
      else:
        DoImageFromFolder(
          root_dir, output_path=image_path, encrypt=True, compressed=False,
          expected_output=[
            'Creating temporary image from folder %s...' % root_dir,
            'Using existing manifest from source path',
            '>d+++++++ lost+found',
            'Paths: 7 total (1kb), 1 synced (0b), 2 checksummed (1kb)',
            'Converting to read only image %s...' % lib.EscapePath(image_path),
            re.compile('^e2fsck .*$'),
            'Pass 1: Checking inodes, blocks, and sizes',
            'Pass 2: Checking directory structure',
            'Pass 3: Checking directory connectivity',
            'Pass 4: Checking reference counts',
            'Pass 5: Checking group summary information',
            re.compile('^/dev/mapper/[^ ]+: 18/21520 files [(]5.6% non-contiguous[)], 2394/21507 blocks'),
            re.compile('^resize2fs .*$'),
            re.compile('^Resizing the filesystem on /dev/mapper/[^ ]+ to 2412 [(]4k[)] blocks.$'),
            re.compile('^The filesystem on /dev/mapper/[^ ]+ is now 2412 [(]4k[)] blocks long.$'),
            re.compile('^e2fsck .*$'),
            'Pass 1: Checking inodes, blocks, and sizes',
            'Pass 2: Checking directory structure',
            'Pass 3: Checking directory connectivity',
            'Pass 4: Checking reference counts',
            'Pass 5: Checking group summary information',
            re.compile('^/dev/mapper/[^ ]+: 18/21520 files [(]5.6% non-contiguous[)], 2394/2412 blocks'),
            'Image size 100mb -> 25.4mb',
            'Verifying checksums in %s...' % lib.EscapePath(image_path),
            'Verifying source tree matches...',
            re.compile('^Created image %s [(]25([.]4)?mb[)]; Source size 1kb$'
                       % re.escape(lib.EscapePath(image_path)))])
        AssertDiskImageFormat('crypto_LUKS', image_path)
        AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '25mb', '26mb')

    DeleteFileOrDir(image_path)

    DoImageFromFolder(
      root_dir, output_path=image_path, temp_dir='/dev/null', encrypt=True,
      expected_success=False, expected_output=['*** Error: Temporary dir /dev/null is not a directory'])


class SafeCopyTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      DoCreate(root_dir, expected_output=None)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    file3 = CreateFile(parent1, 'f3', contents='1'*1025)

    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       'Paths: 5 total (2kb), 5 synced (2kb), 3 checksummed (2kb)'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)

    file1_copy = os.path.join(root_dir, 'f1.copy')
    DoSafeCopy(file1, file1_copy, dry_run=True,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Copying %s to %s...' % (file1, file1_copy),
                                re.compile('^[>]f[+]{9,10} f1$'),
                                'Adding manifest entries...',
                                '>f+++++++ f1.copy',
                                '  replacing duplicate: .f....... f1',
                                'Verifying copied files...',
                                'Paths: 5 total (2kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      DoSafeCopy(file1, file1_copy, dry_run=False,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Copying %s to %s...' % (file1, file1_copy),
                                re.compile('^[>]f[+]{9,10} f1$'),
                                'Adding manifest entries...',
                                '.d..t.... .',
                                '>f+++++++ f1.copy',
                                '  replacing duplicate: .f....... f1',
                                'Verifying copied files...',
                                'Paths: 6 total (2kb), 1 checksummed (3b)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 6 total (2kb), 1 synced (0b), 4 checksummed (2kb)'])

    root2_dir = CreateDir(test_dir, 'root2')

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root2_dir)
      DoCreate(root2_dir, expected_output=None)

    root2_file1 = CreateFile(root2_dir, 'f1', contents='ABC2')
    root2_parent1 = CreateDir(root2_dir, 'par! \r')
    root2_file2 = CreateFile(root2_parent1, 'f2', contents='2'*1025)
    root2_file3 = CreateFile(root2_parent1, 'f3', contents='2'*1025)

    DoSync(
      root2_dir, checksum_all=True,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       'Paths: 5 total (2kb), 5 synced (2kb), 3 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True, expected_output=None)

    root2_file1_copy = os.path.join(root2_dir, 'f1.copy')
    DoSafeCopy(file1, root2_file1_copy, dry_run=True,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Verifying manifest for to root %s...' % root2_dir,
                                'Copying %s to %s...' % (file1, root2_file1_copy),
                                re.compile('^[>]f[+]{9,10} f1$'),
                                'Adding manifest entries...',
                                '>f+++++++ f1.copy',
                                'Verifying copied files...',
                                'Paths: 5 total (2kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True,
             expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root2_dir)
      DoSafeCopy(file1, root2_file1_copy, dry_run=False,
                 expected_output=['Verifying manifest for from root %s...' % root_dir,
                                  'Verifying manifest for to root %s...' % root2_dir,
                                  'Copying %s to %s...' % (file1, root2_file1_copy),
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '.d..t.... .',
                                  '>f+++++++ f1.copy',
                                  'Verifying copied files...',
                                  'Paths: 6 total (2kb), 1 checksummed (3b)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 6 total (2kb), 1 synced (0b), 4 checksummed (2kb)'])

    DoSafeCopy(file1, root2_file1_copy, dry_run=True, expected_success=False,
               expected_output=['*** Error: To path %s already exists' % root2_file1_copy])
    DoSafeCopy(file1 + '.missing', root2_file1_copy, dry_run=True, expected_success=False,
               expected_output=['*** Error: From path %s.missing does not exist' % file1])

    DoSafeCopy(os.path.dirname(root_dir), root2_dir, dry_run=True, expected_success=False,
               expected_output=['*** Error: Could not find manifest for from path %s' % os.path.dirname(root_dir)])
    DoSafeCopy(file1, os.path.dirname(root2_dir), dry_run=True, expected_success=False,
               expected_output=['*** Error: Could not find manifest for to path %s'
                                % os.path.join(os.path.dirname(root2_dir), os.path.basename(file1))])
    DoSafeCopy(root_dir, root2_dir, dry_run=True, expected_success=False,
               expected_output=['*** Error: Cannot move manifest root path %s' % root_dir])

    root2_file11 = CreateFile(root2_dir, 'f11', contents='ABC2')

    DoSafeCopy(file1, root2_file1_copy + '.other', dry_run=True, expected_success=False,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Verifying manifest for to root %s...' % root2_dir,
                                '>f+++++++ f11',
                                'Paths: 7 total (2kb), 1 mismatched (4b)'])

    DeleteFileOrDir(root2_file11)
    file11 = CreateFile(root_dir, 'f11', contents='ABC')

    DoSafeCopy(file1, root2_file1_copy + '.other', dry_run=True, expected_success=False,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                '>f+++++++ f11',
                                'Paths: 7 total (2kb), 1 mismatched (3b)'])

    DeleteFileOrDir(file11)
    root2_parent_copy = os.path.join(root2_dir, 'par! \r copy')

    DoSafeCopy(parent1, root2_parent_copy, dry_run=True,
               expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                 'Verifying manifest for to root %s...' % root2_dir,
                                 'Copying %s to %s...' % (lib.EscapePath(parent1), lib.EscapePath(root2_parent_copy)),
                                 ] + GetRsyncCreatedDirectoryOutputLines() +
                                [re.compile('^cd[+]{9,10} ./$'),
                                 re.compile('^[>]f[+]{9,10} f2$'),
                                 re.compile('^[>]f[+]{9,10} f3$'),
                                 'Adding manifest entries...',
                                 '>d+++++++ par! \\r copy',
                                 '>f+++++++ par! \\r copy/f2',
                                 '>f+++++++ par! \\r copy/f3',
                                 'Verifying copied files...',
                                 'Paths: 6 total (2kb)']))
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True,
             expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root2_dir)
      DoSafeCopy(parent1, root2_parent_copy, dry_run=False,
                 expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                   'Verifying manifest for to root %s...' % root2_dir,
                                   'Copying %s to %s...' % (lib.EscapePath(parent1), lib.EscapePath(root2_parent_copy)),
                                   ] + GetRsyncCreatedDirectoryOutputLines() +
                                  [re.compile('^cd[+]{9,10} ./$'),
                                   re.compile('^[>]f[+]{9,10} f2$'),
                                   re.compile('^[>]f[+]{9,10} f3$'),
                                   'Adding manifest entries...',
                                   '.d..t.... .',
                                   '>d+++++++ par! \\r copy',
                                   '>f+++++++ par! \\r copy/f2',
                                   '>f+++++++ par! \\r copy/f3',
                                   'Verifying copied files...',
                                   'Paths: 9 total (4kb), 2 checksummed (2kb)']))
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 9 total (4kb), 6 checksummed (4kb)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 9 total (4kb), 1 synced (0b), 6 checksummed (4kb)'])

    DoSafeCopy(os.path.join(root_dir, '.metadata'), os.path.join(root2_dir, 'metadatacopy'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: From path %s cannot be within metadata dir'
                                % os.path.join(root_dir, '.metadata')])
    DoSafeCopy(parent1, os.path.join(root2_dir, '.metadata'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: To path %s cannot be within metadata dir'
                                % lib.EscapePath(os.path.join(root2_dir, '.metadata', os.path.basename(parent1)))])
    DoSafeCopy(os.path.join(root_dir, '.metadata/manifest.pbdata'),
               os.path.join(root2_dir, 'manifestcopy'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: From path %s cannot be within metadata dir'
                                % os.path.join(root_dir, '.metadata/manifest.pbdata')])
    DoSafeCopy(file1, os.path.join(root2_dir, '.metadata/manifest.pbdata'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: To path %s cannot be within metadata dir'
                                % lib.EscapePath(os.path.join(root2_dir, '.metadata/manifest.pbdata'))])

    with lib.Chdir(root_dir):
      DoSafeCopy(os.path.basename(file1), 'f1.copy2', dry_run=True,
                 expected_output=['Verifying manifest for from root %s...' % os.getcwd(),
                                  'Copying f1 to f1.copy2...',
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '>f+++++++ f1.copy2',
                                  '  replacing duplicate: .f....... f1.copy',
                                  '  replacing duplicate: .f....... f1',
                                  'Verifying copied files...',
                                  'Paths: 6 total (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      with lib.Chdir(root_dir):
        DoSafeCopy(os.path.basename(file1), 'f1.copy2', dry_run=False,
                   expected_output=['Verifying manifest for from root %s...' % os.getcwd(),
                                    'Copying f1 to f1.copy2...',
                                    re.compile('^[>]f[+]{9,10} f1$'),
                                    'Adding manifest entries...',
                                    '.d..t.... .',
                                    '>f+++++++ f1.copy2',
                                    '  replacing duplicate: .f....... f1.copy',
                                    '  replacing duplicate: .f....... f1',
                                    'Verifying copied files...',
                                    'Paths: 7 total (2kb), 1 checksummed (3b)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 7 total (2kb), 5 checksummed (2kb)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 9 total (4kb), 6 checksummed (4kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 7 total (2kb), 1 synced (0b), 5 checksummed (2kb)'])

    with lib.Chdir(root2_dir):
      DoSafeCopy(file1, 'f1.copy3', dry_run=True,
                 expected_output=['Verifying manifest for from root %s...' % root_dir,
                                  'Verifying manifest for to root %s...' % os.getcwd(),
                                  'Copying %s to f1.copy3...' % file1,
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '>f+++++++ f1.copy3',
                                  '  replacing duplicate: .f....... f1.copy',
                                  'Verifying copied files...',
                                  'Paths: 9 total (4kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root2_dir)
      with lib.Chdir(root2_dir):
        DoSafeCopy(file1, 'f1.copy3', dry_run=False,
                   expected_output=['Verifying manifest for from root %s...' % root_dir,
                                    'Verifying manifest for to root %s...' % os.getcwd(),
                                    'Copying %s to f1.copy3...' % file1,
                                    re.compile('^[>]f[+]{9,10} f1$'),
                                    'Adding manifest entries...',
                                    '.d..t.... .',
                                    '>f+++++++ f1.copy3',
                                    '  replacing duplicate: .f....... f1.copy',
                                    'Verifying copied files...',
                                    'Paths: 10 total (4kb), 1 checksummed (3b)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 7 total (2kb), 5 checksummed (2kb)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 10 total (4kb), 7 checksummed (4kb)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 10 total (4kb), 1 synced (0b), 7 checksummed (4kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='DEF')

    file1_copy2 = os.path.join(root_dir, 'f1.copy.2')
    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      DoSafeCopy(file1, file1_copy2, dry_run=False, expected_success=False,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Copying %s to %s...' % (file1, file1_copy2),
                                re.compile('^[>]f[+]{9,10} f1$'),
                                'Adding manifest entries...',
                                '.d..t.... .',
                                '>f+++++++ f1.copy.2',
                                '  replacing duplicate: .f....... f1.copy2',
                                '  replacing duplicate: .f....... f1.copy',
                                '  replacing duplicate: .f....... f1',
                                'Verifying copied files...',
                                '>fc...... f1.copy.2',
                                'Paths: 8 total (2kb), 1 mismatched (3b), 1 checksummed (3b)'])
      DoVerify(root_dir, checksum_all=True, expected_success=False,
               expected_output=['>fc...... f1',
                                '>fc...... f1.copy.2',
                                'Paths: 8 total (2kb), 2 mismatched (6b), 6 checksummed (2kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            '>fc...... f1',
                            '  replaced by duplicate: .f....... f1.copy',
                            '  replaced by duplicate: .f....... f1.copy2',
                            '>fc...... f1.copy.2',
                            '  replaced by duplicate: .f....... f1.copy2',
                            '  replaced by duplicate: .f....... f1.copy',
                            'Paths: 8 total (2kb), 3 synced (6b), 6 checksummed (2kb)'])

    DoSafeCopy(parent1, root2_parent_copy, dry_run=True,
               expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                 'Verifying manifest for to root %s...' % root2_dir,
                                 'Copying %s to %s...'
                                 % (lib.EscapePath(parent1), lib.EscapePath(
                                   os.path.join(root2_parent_copy, os.path.basename(parent1)))),
                                 ] + GetRsyncCreatedDirectoryOutputLines() +
                                [re.compile('^cd[+]{9,10} ./$'),
                                 re.compile('^[>]f[+]{9,10} f2$'),
                                 re.compile('^[>]f[+]{9,10} f3$'),
                                 'Adding manifest entries...',
                                 '>d+++++++ par! \\r copy/par! \\r',
                                 '>f+++++++ par! \\r copy/par! \\r/f2',
                                 '  replacing duplicate: .f....... par! \\r copy/f2',
                                 '  replacing duplicate: .f....... par! \\r copy/f3',
                                 '>f+++++++ par! \\r copy/par! \\r/f3',
                                 '  replacing duplicate: .f....... par! \\r copy/f3',
                                 '  replacing duplicate: .f....... par! \\r copy/f2',
                                 'Verifying copied files...',
                                 'Paths: 10 total (4kb)']))
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 8 total (2kb), 6 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True,
             expected_output=['Paths: 10 total (4kb), 7 checksummed (4kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root2_parent_copy)
      DoSafeCopy(parent1, root2_parent_copy, dry_run=False,
                 expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                   'Verifying manifest for to root %s...' % root2_dir,
                                   'Copying %s to %s...'
                                   % (lib.EscapePath(parent1), lib.EscapePath(
                                     os.path.join(root2_parent_copy, os.path.basename(parent1)))),
                                   ] + GetRsyncCreatedDirectoryOutputLines() +
                                  [re.compile('^cd[+]{9,10} ./$'),
                                   re.compile('^[>]f[+]{9,10} f2$'),
                                   re.compile('^[>]f[+]{9,10} f3$'),
                                   'Adding manifest entries...',
                                   '.d..t.... par! \\r copy',
                                   '>d+++++++ par! \\r copy/par! \\r',
                                   '>f+++++++ par! \\r copy/par! \\r/f2',
                                   '  replacing duplicate: .f....... par! \\r copy/f2',
                                   '  replacing duplicate: .f....... par! \\r copy/f3',
                                   '>f+++++++ par! \\r copy/par! \\r/f3',
                                   '  replacing duplicate: .f....... par! \\r copy/f3',
                                   '  replacing duplicate: .f....... par! \\r copy/f2',
                                   'Verifying copied files...',
                                   'Paths: 13 total (6kb), 2 checksummed (2kb)']))
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 8 total (2kb), 6 checksummed (2kb)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 13 total (6kb), 9 checksummed (6kb)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... par! \\r copy',
                            'Paths: 13 total (6kb), 1 synced (0b), 9 checksummed (6kb)'])


class SafeMoveTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      DoCreate(root_dir, expected_output=None)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    file3 = CreateFile(parent1, 'f3', contents='1'*1025)

    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       'Paths: 5 total (2kb), 5 synced (2kb), 3 checksummed (2kb)'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)

    file1_copy = os.path.join(root_dir, 'f1.copy')
    DoSafeMove(file1, file1_copy, dry_run=True,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Copying %s to %s...' % (file1, file1_copy),
                                re.compile('^[>]f[+]{9,10} f1$'),
                                'Adding manifest entries...',
                                '>f+++++++ f1.copy',
                                '  replacing duplicate: .f....... f1',
                                'Verifying copied files...',
                                'Paths: 5 total (2kb)',
                                'Removing from files and manifest entries...',
                                '*f.delete f1',
                                'Verifying from checksums...',
                                'Paths: 5 total (2kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      with SafeMoveOrCopyForceFromParentDirMtimeChangeForTest():
        DoSafeMove(file1, file1_copy, dry_run=False,
                 expected_output=['Verifying manifest for from root %s...' % root_dir,
                                  'Copying %s to %s...' % (file1, file1_copy),
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '.d..t.... .',
                                  '>f+++++++ f1.copy',
                                  '  replacing duplicate: .f....... f1',
                                  'Verifying copied files...',
                                  'Paths: 6 total (2kb), 1 checksummed (3b)',
                                  'Removing from files and manifest entries...',
                                  '*f.delete f1',
                                  '.d..t.... .',
                                  'Verifying from checksums...',
                                  'Paths: 5 total (2kb)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 5 total (2kb), 1 synced (0b), 3 checksummed (2kb)'])

    root2_dir = CreateDir(test_dir, 'root2')

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root2_dir)
      DoCreate(root2_dir, expected_output=None)

    root2_file1 = CreateFile(root2_dir, 'f1', contents='ABC2')
    root2_parent1 = CreateDir(root2_dir, 'par! \r')
    root2_file2 = CreateFile(root2_parent1, 'f2', contents='2'*1025)
    root2_file3 = CreateFile(root2_parent1, 'f3', contents='2'*1025)

    DoSync(
      root2_dir, checksum_all=True,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f2',
                       '>f+++++++ par! \\r/f3',
                       'Paths: 5 total (2kb), 5 synced (2kb), 3 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True, expected_output=None)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>f+++++++ f1',
                       '  replacing duplicate: .f....... f1.copy',
                       'Paths: 6 total (2kb), 1 synced (3b), 4 checksummed (2kb)'])

    root2_file1_copy = os.path.join(root2_dir, 'f1.copy')
    DoSafeMove(file1, root2_file1_copy, dry_run=True,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Verifying manifest for to root %s...' % root2_dir,
                                'Copying %s to %s...' % (file1, root2_file1_copy),
                                re.compile('^[>]f[+]{9,10} f1$'),
                                'Adding manifest entries...',
                                '>f+++++++ f1.copy',
                                'Verifying copied files...',
                                'Paths: 5 total (2kb)',
                                'Removing from files and manifest entries...',
                                '*f.delete f1',
                                'Verifying from checksums...',
                                'Paths: 6 total (2kb)'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True,
             expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      mtime_preserver.PreserveMtime(root2_dir)
      DoSafeMove(file1, root2_file1_copy, dry_run=False,
                 expected_output=['Verifying manifest for from root %s...' % root_dir,
                                  'Verifying manifest for to root %s...' % root2_dir,
                                  'Copying %s to %s...' % (file1, root2_file1_copy),
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '.d..t.... .',
                                  '>f+++++++ f1.copy',
                                  'Verifying copied files...',
                                  'Paths: 6 total (2kb), 1 checksummed (3b)',
                                  'Removing from files and manifest entries...',
                                  '*f.delete f1',
                                  '.d..t.... .',
                                  'Verifying from checksums...',
                                  'Paths: 5 total (2kb)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 5 total (2kb), 3 checksummed (2kb)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 5 total (2kb), 1 synced (0b), 3 checksummed (2kb)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 6 total (2kb), 1 synced (0b), 4 checksummed (2kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>f+++++++ f1',
                       '  replacing duplicate: .f....... f1.copy',
                       'Paths: 6 total (2kb), 1 synced (3b), 4 checksummed (2kb)'])

    DoSafeMove(file1, root2_file1_copy, dry_run=True, expected_success=False,
               expected_output=['*** Error: To path %s already exists' % root2_file1_copy])
    DoSafeMove(file1 + '.missing', root2_file1_copy, dry_run=True, expected_success=False,
               expected_output=['*** Error: From path %s.missing does not exist' % file1])

    DoSafeMove(os.path.dirname(root_dir), root2_dir, dry_run=True, expected_success=False,
               expected_output=['*** Error: Could not find manifest for from path %s' % os.path.dirname(root_dir)])
    DoSafeMove(file1, os.path.dirname(root2_dir), dry_run=True, expected_success=False,
               expected_output=['*** Error: Could not find manifest for to path %s'
                                % os.path.join(os.path.dirname(root2_dir), os.path.basename(file1))])
    DoSafeMove(root_dir, root2_dir, dry_run=True, expected_success=False,
               expected_output=['*** Error: Cannot move manifest root path %s' % root_dir])

    root2_file11 = CreateFile(root2_dir, 'f11', contents='ABC2')

    DoSafeMove(file1, root2_file1_copy + '.other', dry_run=True, expected_success=False,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                'Verifying manifest for to root %s...' % root2_dir,
                                '>f+++++++ f11',
                                'Paths: 7 total (2kb), 1 mismatched (4b)'])

    DeleteFileOrDir(root2_file11)
    file11 = CreateFile(root_dir, 'f11', contents='ABC')

    DoSafeMove(file1, root2_file1_copy + '.other', dry_run=True, expected_success=False,
               expected_output=['Verifying manifest for from root %s...' % root_dir,
                                '>f+++++++ f11',
                                'Paths: 7 total (2kb), 1 mismatched (3b)'])

    DeleteFileOrDir(file11)
    root2_parent_copy = os.path.join(root2_dir, 'par! \r copy')

    DoSafeMove(parent1, root2_parent_copy, dry_run=True,
               expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                 'Verifying manifest for to root %s...' % root2_dir,
                                 'Copying %s to %s...' % (lib.EscapePath(parent1), lib.EscapePath(root2_parent_copy)),
                                 ] + GetRsyncCreatedDirectoryOutputLines() +
                                [re.compile('^cd[+]{9,10} ./$'),
                                 re.compile('^[>]f[+]{9,10} f2$'),
                                 re.compile('^[>]f[+]{9,10} f3$'),
                                 'Adding manifest entries...',
                                 '>d+++++++ par! \\r copy',
                                 '>f+++++++ par! \\r copy/f2',
                                 '>f+++++++ par! \\r copy/f3',
                                 'Verifying copied files...',
                                 'Paths: 6 total (2kb)',
                                 'Removing from files and manifest entries...',
                                 '*f.delete par! \\r/f3',
                                 '*f.delete par! \\r/f2',
                                 '*d.delete par! \\r',
                                 'Verifying from checksums...',
                                 'Paths: 6 total (2kb)']))
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True,
             expected_output=['Paths: 6 total (2kb), 4 checksummed (2kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      mtime_preserver.PreserveMtime(root2_dir)
      DoSafeMove(parent1, root2_parent_copy, dry_run=False,
                 expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                   'Verifying manifest for to root %s...' % root2_dir,
                                   'Copying %s to %s...' % (lib.EscapePath(parent1), lib.EscapePath(root2_parent_copy)),
                                   ] + GetRsyncCreatedDirectoryOutputLines() +
                                  [re.compile('^cd[+]{9,10} ./$'),
                                   re.compile('^[>]f[+]{9,10} f2$'),
                                   re.compile('^[>]f[+]{9,10} f3$'),
                                   'Adding manifest entries...',
                                   '.d..t.... .',
                                   '>d+++++++ par! \\r copy',
                                   '>f+++++++ par! \\r copy/f2',
                                   '>f+++++++ par! \\r copy/f3',
                                   'Verifying copied files...',
                                   'Paths: 9 total (4kb), 2 checksummed (2kb)',
                                   'Removing from files and manifest entries...',
                                   '*f.delete par! \\r/f3',
                                   '*f.delete par! \\r/f2',
                                   '*d.delete par! \\r',
                                   '.d..t.... .',
                                   'Verifying from checksums...',
                                   'Paths: 3 total (6b)']))
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 3 total (6b), 2 checksummed (6b)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 9 total (4kb), 6 checksummed (4kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 3 total (6b), 1 synced (0b), 2 checksummed (6b)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 9 total (4kb), 1 synced (0b), 6 checksummed (4kb)'])

    DoSafeMove(os.path.join(root_dir, '.metadata'), os.path.join(root2_dir, 'metadatacopy'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: From path %s cannot be within metadata dir'
                                % os.path.join(root_dir, '.metadata')])
    DoSafeMove(parent1, os.path.join(root2_dir, '.metadata'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: To path %s cannot be within metadata dir'
                                % lib.EscapePath(os.path.join(root2_dir, '.metadata', os.path.basename(parent1)))])
    DoSafeMove(os.path.join(root_dir, '.metadata/manifest.pbdata'),
               os.path.join(root2_dir, 'manifestcopy'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: From path %s cannot be within metadata dir'
                                % os.path.join(root_dir, '.metadata/manifest.pbdata')])
    DoSafeMove(file1, os.path.join(root2_dir, '.metadata/manifest.pbdata'), dry_run=True,
               expected_success=False,
               expected_output=['*** Error: To path %s cannot be within metadata dir'
                                % lib.EscapePath(os.path.join(root2_dir, '.metadata/manifest.pbdata'))])

    with lib.Chdir(root_dir):
      DoSafeMove(os.path.basename(file1), 'f1.copy2', dry_run=True,
                 expected_output=['Verifying manifest for from root %s...' % os.getcwd(),
                                  'Copying f1 to f1.copy2...',
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '>f+++++++ f1.copy2',
                                  '  replacing duplicate: .f....... f1.copy',
                                  '  replacing duplicate: .f....... f1',
                                  'Verifying copied files...',
                                  'Paths: 3 total (6b)',
                                  'Removing from files and manifest entries...',
                                  '*f.delete f1',
                                  'Verifying from checksums...',
                                  'Paths: 3 total (6b)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      with lib.Chdir(root_dir):
        with SafeMoveOrCopyForceFromParentDirMtimeChangeForTest():
          DoSafeMove(os.path.basename(file1), 'f1.copy2', dry_run=False,
                     expected_output=['Verifying manifest for from root %s...' % os.getcwd(),
                                      'Copying f1 to f1.copy2...',
                                      re.compile('^[>]f[+]{9,10} f1$'),
                                      'Adding manifest entries...',
                                      '.d..t.... .',
                                      '>f+++++++ f1.copy2',
                                      '  replacing duplicate: .f....... f1.copy',
                                      '  replacing duplicate: .f....... f1',
                                      'Verifying copied files...',
                                      'Paths: 4 total (9b), 1 checksummed (3b)',
                                      'Removing from files and manifest entries...',
                                      '*f.delete f1',
                                      '.d..t.... .',
                                      'Verifying from checksums...',
                                      'Paths: 3 total (6b)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 3 total (6b), 2 checksummed (6b)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 9 total (4kb), 6 checksummed (4kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 3 total (6b), 1 synced (0b), 2 checksummed (6b)'])

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>f+++++++ f1',
                       '  replacing duplicate: .f....... f1.copy',
                       '  replacing duplicate: .f....... f1.copy2',
                       'Paths: 4 total (9b), 1 synced (3b), 3 checksummed (9b)'])

    with lib.Chdir(root2_dir):
      DoSafeMove(file1, 'f1.copy3', dry_run=True,
                 expected_output=['Verifying manifest for from root %s...' % root_dir,
                                  'Verifying manifest for to root %s...' % os.getcwd(),
                                  'Copying %s to f1.copy3...' % file1,
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '>f+++++++ f1.copy3',
                                  '  replacing duplicate: .f....... f1.copy',
                                  'Verifying copied files...',
                                  'Paths: 9 total (4kb)',
                                  'Removing from files and manifest entries...',
                                  '*f.delete f1',
                                  'Verifying from checksums...',
                                  'Paths: 4 total (9b)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      mtime_preserver.PreserveMtime(root2_dir)
      with lib.Chdir(root2_dir):
        DoSafeMove(file1, 'f1.copy3', dry_run=False,
                   expected_output=['Verifying manifest for from root %s...' % root_dir,
                                    'Verifying manifest for to root %s...' % os.getcwd(),
                                    'Copying %s to f1.copy3...' % file1,
                                    re.compile('^[>]f[+]{9,10} f1$'),
                                    'Adding manifest entries...',
                                    '.d..t.... .',
                                    '>f+++++++ f1.copy3',
                                    '  replacing duplicate: .f....... f1.copy',
                                    'Verifying copied files...',
                                    'Paths: 10 total (4kb), 1 checksummed (3b)',
                                    'Removing from files and manifest entries...',
                                    '*f.delete f1',
                                    '.d..t.... .',
                                    'Verifying from checksums...',
                                    'Paths: 3 total (6b)'])
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 3 total (6b), 2 checksummed (6b)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 10 total (4kb), 7 checksummed (4kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 3 total (6b), 1 synced (0b), 2 checksummed (6b)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 10 total (4kb), 1 synced (0b), 7 checksummed (4kb)'])

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    DoSync(
      root_dir, checksum_all=True,
      expected_output=['>f+++++++ f1',
                       '  replacing duplicate: .f....... f1.copy',
                       '  replacing duplicate: .f....... f1.copy2',
                       'Paths: 4 total (9b), 1 synced (3b), 3 checksummed (9b)'])

    file1 = CreateFile(root_dir, 'f1', contents='DEF')

    file1_copy2 = os.path.join(root_dir, 'f1.copy.2')
    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      DoSafeMove(file1, file1_copy2, dry_run=False, expected_success=False,
                 expected_output=['Verifying manifest for from root %s...' % root_dir,
                                  'Copying %s to %s...' % (file1, file1_copy2),
                                  re.compile('^[>]f[+]{9,10} f1$'),
                                  'Adding manifest entries...',
                                  '.d..t.... .',
                                  '>f+++++++ f1.copy.2',
                                  '  replacing duplicate: .f....... f1.copy2',
                                  '  replacing duplicate: .f....... f1.copy',
                                  '  replacing duplicate: .f....... f1',
                                  'Verifying copied files...',
                                  '>fc...... f1.copy.2',
                                  'Paths: 5 total (12b), 1 mismatched (3b), 1 checksummed (3b)'])
      DoVerify(root_dir, checksum_all=True, expected_success=False,
               expected_output=['>fc...... f1',
                                '>fc...... f1.copy.2',
                                'Paths: 5 total (12b), 2 mismatched (6b), 4 checksummed (12b)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            '>fc...... f1',
                            '  replaced by duplicate: .f....... f1.copy',
                            '  replaced by duplicate: .f....... f1.copy2',
                            '>fc...... f1.copy.2',
                            '  replaced by duplicate: .f....... f1.copy2',
                            '  replaced by duplicate: .f....... f1.copy',
                            'Paths: 5 total (12b), 3 synced (6b), 4 checksummed (12b)'])

    parent1 = CreateDir(root_dir, 'par! \r')
    file2 = CreateFile(parent1, 'f2', contents='1'*1025)
    file3 = CreateFile(parent1, 'f3', contents='1'*1025)

    DoSync(root_dir, checksum_all=True,
           expected_output=['>d+++++++ par! \\r',
                            '>f+++++++ par! \\r/f2',
                            '>f+++++++ par! \\r/f3',
                            'Paths: 8 total (2kb), 3 synced (2kb), 6 checksummed (2kb)'])

    DoSafeMove(parent1, root2_parent_copy, dry_run=True,
               expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                 'Verifying manifest for to root %s...' % root2_dir,
                                 'Copying %s to %s...'
                                 % (lib.EscapePath(parent1), lib.EscapePath(
                                   os.path.join(root2_parent_copy, os.path.basename(parent1)))),
                                 ] + GetRsyncCreatedDirectoryOutputLines() +
                                [re.compile('^cd[+]{9,10} ./$'),
                                 re.compile('^[>]f[+]{9,10} f2$'),
                                 re.compile('^[>]f[+]{9,10} f3$'),
                                 'Adding manifest entries...',
                                 '>d+++++++ par! \\r copy/par! \\r',
                                 '>f+++++++ par! \\r copy/par! \\r/f2',
                                 '  replacing duplicate: .f....... par! \\r copy/f2',
                                 '  replacing duplicate: .f....... par! \\r copy/f3',
                                 '>f+++++++ par! \\r copy/par! \\r/f3',
                                 '  replacing duplicate: .f....... par! \\r copy/f3',
                                 '  replacing duplicate: .f....... par! \\r copy/f2',
                                 'Verifying copied files...',
                                 'Paths: 10 total (4kb)',
                                 'Removing from files and manifest entries...',
                                 '*f.delete par! \\r/f3',
                                 '*f.delete par! \\r/f2',
                                 '*d.delete par! \\r',
                                 'Verifying from checksums...',
                                 'Paths: 8 total (2kb)']))
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 8 total (2kb), 6 checksummed (2kb)'])
    DoVerify(root2_dir, checksum_all=True,
             expected_output=['Paths: 10 total (4kb), 7 checksummed (4kb)'])

    with lib.MtimePreserver() as mtime_preserver:
      mtime_preserver.PreserveMtime(root_dir)
      mtime_preserver.PreserveMtime(root2_parent_copy)
      DoSafeMove(parent1, root2_parent_copy, dry_run=False,
                 expected_output=(['Verifying manifest for from root %s...' % root_dir,
                                   'Verifying manifest for to root %s...' % root2_dir,
                                   'Copying %s to %s...'
                                   % (lib.EscapePath(parent1), lib.EscapePath(
                                     os.path.join(root2_parent_copy, os.path.basename(parent1)))),
                                   ] + GetRsyncCreatedDirectoryOutputLines() +
                                  [re.compile('^cd[+]{9,10} ./$'),
                                   re.compile('^[>]f[+]{9,10} f2$'),
                                   re.compile('^[>]f[+]{9,10} f3$'),
                                   'Adding manifest entries...',
                                   '.d..t.... par! \\r copy',
                                   '>d+++++++ par! \\r copy/par! \\r',
                                   '>f+++++++ par! \\r copy/par! \\r/f2',
                                   '  replacing duplicate: .f....... par! \\r copy/f2',
                                   '  replacing duplicate: .f....... par! \\r copy/f3',
                                   '>f+++++++ par! \\r copy/par! \\r/f3',
                                   '  replacing duplicate: .f....... par! \\r copy/f3',
                                   '  replacing duplicate: .f....... par! \\r copy/f2',
                                   'Verifying copied files...',
                                   'Paths: 13 total (6kb), 2 checksummed (2kb)',
                                   'Removing from files and manifest entries...',
                                   '*f.delete par! \\r/f3',
                                   '*f.delete par! \\r/f2',
                                   '*d.delete par! \\r',
                                   '.d..t.... .',
                                   'Verifying from checksums...',
                                   'Paths: 5 total (12b)']))
      DoVerify(root_dir, checksum_all=True,
               expected_output=['Paths: 5 total (12b), 4 checksummed (12b)'])
      DoVerify(root2_dir, checksum_all=True,
               expected_output=['Paths: 13 total (6kb), 9 checksummed (6kb)'])
    DoSync(root_dir, checksum_all=True,
           expected_output=['.d..t.... .',
                            'Paths: 5 total (12b), 1 synced (0b), 4 checksummed (12b)'])
    DoSync(root2_dir, checksum_all=True,
           expected_output=['.d..t.... par! \\r copy',
                            'Paths: 13 total (6kb), 1 synced (0b), 9 checksummed (6kb)'])


class RestoreMetaTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')

    DoCreate(root_dir, expected_output=None)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    file2 = CreateFile(root_dir, 'f2', contents='DEF')
    parent1 = CreateDir(root_dir, 'par! \r')
    file3 = CreateFile(parent1, 'f3', contents='1'*1025)
    parent2 = CreateDir(root_dir, 'par2')
    file4 = CreateFile(parent2, 'f4', contents='2'*1025)
    ln1 = CreateSymlink(root_dir, 'ln1', 'INVALID')
    ln2 = CreateSymlink(root_dir, 'ln2', 'f2')

    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>f+++++++ f2',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> f2',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f3',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f4',
                       'Paths: 9 total (2kb), 9 synced (2kb), 4 checksummed (2kb)'])

    DoRestoreMeta(
      root_dir, dry_run=True, expected_success=False,
      expected_output=['*** Error: --mtimes arg is required'])
    DoRestoreMeta(
      root_dir, dry_run=True, mtimes=True,
      expected_output=['Restoring metadata (mtimes)...',
                       'Paths: 9 total'])
    DoRestoreMeta(
      root_dir, dry_run=True, mtimes=True, paths=['f1'],
      expected_output=['Restoring metadata (mtimes)...',
                       'Paths: 9 total, 8 skipped'])

    DoVerify(root_dir, expected_output=None)

    SetMTime(file1, mtime=1510000000)
    SetMTime(parent1, mtime=1530000000)
    SetMTime(ln1, mtime=1520000000)
    SetMTime(ln2, mtime=1540000000)
    SetMTime(file4, mtime=1550000000)

    DoVerify(root_dir, expected_success=False,
             expected_output=['.f..t.... f1',
                              '.L..t.... ln1 -> INVALID',
                              '.L..t.... ln2 -> f2',
                              '.d..t.... par! \\r',
                              '.f..t.... par2/f4',
                              'Paths: 9 total (2kb), 5 mismatched (1kb), 2 checksummed (1kb)'])

    DoRestoreMeta(
      root_dir, dry_run=True, mtimes=True, paths=['f1'],
      expected_output=['Restoring metadata (mtimes)...',
                       '.f..t.... f1',
                       'Paths: 9 total, 1 updated, 8 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_success=False,
             expected_output=['.f..t.... f1',
                              '.L..t.... ln1 -> INVALID',
                              '.L..t.... ln2 -> f2',
                              '.d..t.... par! \\r',
                              '.f..t.... par2/f4',
                              'Paths: 9 total (2kb), 5 mismatched (1kb), 4 checksummed (2kb)'])

    DoRestoreMeta(
      root_dir, mtimes=True, paths=['f1'],
      expected_output=['Restoring metadata (mtimes)...',
                       '.f..t.... f1',
                       'Paths: 9 total, 1 updated, 8 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_success=False,
             expected_output=['.L..t.... ln1 -> INVALID',
                              '.L..t.... ln2 -> f2',
                              '.d..t.... par! \\r',
                              '.f..t.... par2/f4',
                              'Paths: 9 total (2kb), 4 mismatched (1kb), 4 checksummed (2kb)'])

    DoRestoreMeta(
      root_dir, mtimes=True, paths=['par2'],
      expected_output=['Restoring metadata (mtimes)...',
                       '.f..t.... par2/f4',
                       'Paths: 9 total, 1 updated, 7 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_success=False,
             expected_output=['.L..t.... ln1 -> INVALID',
                              '.L..t.... ln2 -> f2',
                              '.d..t.... par! \\r',
                              'Paths: 9 total (2kb), 3 mismatched (0b), 4 checksummed (2kb)'])

    DoRestoreMeta(
      root_dir, mtimes=True, paths=['ln1', 'ln2', os.path.basename(parent1)],
      expected_output=['Restoring metadata (mtimes)...',
                       '.L..t.... ln1 -> INVALID',
                       '.L..t.... ln2 -> f2',
                       '.d..t.... par! \\r',
                       'Paths: 9 total, 3 updated, 5 skipped'])
    DoVerify(root_dir, checksum_all=True,
             expected_output=['Paths: 9 total (2kb), 4 checksummed (2kb)'])


class DeleteDuplicateFilesTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
    root_dir = CreateDir(test_dir, 'root')

    DoCreate(root_dir, expected_output=None)

    file1 = CreateFile(root_dir, 'f1', contents='ABC')
    file2 = CreateFile(root_dir, 'f2', contents='DEF')
    parent1 = CreateDir(root_dir, 'par! \r')
    file3 = CreateFile(parent1, 'f3', contents='1'*1025)
    file6 = CreateFile(parent1, 'f6', contents='3'*1025)
    parent2 = CreateDir(root_dir, 'par2')
    file4 = CreateFile(parent2, 'f4', contents='2'*1025)
    file5 = CreateFile(parent2, 'f5', contents='3'*1025)
    ln1 = CreateSymlink(root_dir, 'ln1', 'INVALID')
    ln2 = CreateSymlink(root_dir, 'ln2', 'f2')

    DoSync(
      root_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>f+++++++ f2',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> f2',
                       '>d+++++++ par! \\r',
                       '>f+++++++ par! \\r/f3',
                       '>f+++++++ par! \\r/f6',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f4',
                       '>f+++++++ par2/f5',
                       'Paths: 11 total (4kb), 11 synced (4kb), 6 checksummed (4kb)'])

    checksums_bak = checksums_lib.Checksums.Open(root_dir)
    DoDeleteDuplicateFiles(
      root_dir, dry_run=True,
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Paths: 6 total'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    DoDeleteDuplicateFiles(
      root_dir, dry_run=True,
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f6',
                       '  duplicated by .f....... par2/f5',
                       'Paths: 6 total, 1 duplicate, 4 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    checksums_bak.GetManifest().Write()
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    DoDeleteDuplicateFiles(
      root_dir,
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f6',
                       '  duplicated by .f....... par2/f5',
                       '*f.delete par! \\r/f6',
                       '.d..t.... par! \\r',
                       'Paths: 6 total, 1 duplicate, 1 deleted, 4 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    checksums_bak.GetManifest().Write()
    DoSync(
      root_dir,
      expected_output=['.d..t.... par! \\r',
                       '*f.delete par! \\r/f6',
                       '  replaced by duplicate: .f....... par2/f5',
                       'Paths: 10 total (3kb), 2 synced (0b), 1 renamed (1kb), 2 checksummed (2kb)'])

    SetMTime(parent1, mtime=1530000000)
    file7 = CreateFile(parent1, 'f7', contents='3'*1025)
    file8 = CreateFile(parent1, 'f8', contents='3'*1025, mtime=1510000000)

    DoDeleteDuplicateFiles(
      root_dir, dry_run=True, expected_success=False,
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       '.d..t.... par! \\r',
                       '>f+++++++ par! \\r/f7',
                       '>f+++++++ par! \\r/f8',
                       'Paths: 12 total (5kb), 3 mismatched (2kb)'])
    DoSync(
      root_dir,
      expected_output=['.d..t.... par! \\r',
                       '>f+++++++ par! \\r/f7',
                       '  replacing duplicate: .f....... par2/f5',
                       '>f+++++++ par! \\r/f8',
                       '  replacing similar: .f..t.... par2/f5',
                       'Paths: 12 total (5kb), 3 synced (2kb), 2 checksummed (2kb)'])
    checksums_bak = checksums_lib.Checksums.Open(root_dir)
    DoDeleteDuplicateFiles(
      root_dir, dry_run=True,
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f7',
                       '  duplicated by .f....... par2/f5',
                       'Path par! \\r/f8',
                       '  similar to .f..t.... par2/f5',
                       'Paths: 7 total, 1 duplicate, 1 similar, 4 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    checksums_bak.GetManifest().Write()
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    DoDeleteDuplicateFiles(
      root_dir,
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f7',
                       '  duplicated by .f....... par2/f5',
                       'Path par! \\r/f8',
                       '  similar to .f..t.... par2/f5',
                       '*f.delete par! \\r/f7',
                       '.d..t.... par! \\r',
                       'Paths: 7 total, 1 duplicate, 1 similar, 1 deleted, 4 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)
    checksums_bak.GetManifest().Write()
    DoSync(
      root_dir,
      expected_output=['.d..t.... par! \\r',
                       '*f.delete par! \\r/f7',
                       '  replaced by duplicate: .f....... par2/f5',
                       '  replaced by similar: .f..t.... par! \\r/f8',
                       'Paths: 11 total (4kb), 2 synced (0b), 1 renamed (1kb), 3 checksummed (3kb)'])
    SetMTime(parent1, mtime=1530000000)
    DoSync(
      root_dir,
      expected_output=['.d..t.... par! \\r',
                       'Paths: 11 total (4kb), 1 synced (0b)'])

    root2_dir = CreateDir(test_dir, 'root2')
    DoCreate(root2_dir, expected_output=None)
    root2_file1 = CreateFile(root2_dir, 'f1', contents='3'*1025, mtime=1510000000)
    DoSync(
      root2_dir,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       'Paths: 2 total (1kb), 2 synced (1kb), 1 checksummed (1kb)'])
    checksums2_bak = checksums_lib.Checksums.Open(root2_dir)

    DoDeleteDuplicateFiles(
      root_dir, dry_run=True,
      source_manifest_path=checksums2_bak.GetManifest().GetPath(),
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f8',
                       '  duplicated by .f....... f1',
                       'Paths: 6 total, 1 duplicate, 4 skipped'])
    DoDeleteDuplicateFiles(
      root_dir,
      source_manifest_path=checksums2_bak.GetManifest().GetPath(),
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f8',
                       '  duplicated by .f....... f1',
                       '*f.delete par! \\r/f8',
                       '.d..t.... par! \\r',
                       'Paths: 6 total, 1 duplicate, 1 deleted, 4 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)

    DoDeleteDuplicateFiles(
      root_dir, dry_run=True, allow_source_path_match=True, expected_success=False,
      expected_output=['*** Error: --allow-source-path-match requires --source-manifest-path'])

    DoDeleteDuplicateFiles(
      root_dir, dry_run=True, expected_success=False,
      source_manifest_path=os.path.join(root_dir, '.metadata/manifest.pbdata'),
      expected_output=['*** Error: --source-manifest-path matches checksums manifest path'])

    alt_manifest_path = os.path.join(test_dir, 'alt_manifest.pbdata')
    shutil.copy(os.path.join(root_dir, '.metadata/manifest.pbdata'), alt_manifest_path)

    DoDeleteDuplicateFiles(
      root_dir, dry_run=True,
      source_manifest_path=alt_manifest_path,
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Paths: 5 total'])
    DoDeleteDuplicateFiles(
      root_dir, dry_run=True,
      source_manifest_path=alt_manifest_path, allow_source_path_match=True,
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path f1',
                       '  duplicated by .f....... f1',
                       'Path f2',
                       '  duplicated by .f....... f2',
                       'Path par! \\r/f3',
                       '  duplicated by .f....... par! \\r/f3',
                       'Path par2/f4',
                       '  duplicated by .f....... par2/f4',
                       'Path par2/f5',
                       '  duplicated by .f....... par2/f5',
                       'Paths: 5 total, 5 duplicate'])
    DoDeleteDuplicateFiles(
      root_dir,
      source_manifest_path=alt_manifest_path, allow_source_path_match=True,
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path f1',
                       '  duplicated by .f....... f1',
                       'Path f2',
                       '  duplicated by .f....... f2',
                       'Path par! \\r/f3',
                       '  duplicated by .f....... par! \\r/f3',
                       'Path par2/f4',
                       '  duplicated by .f....... par2/f4',
                       'Path par2/f5',
                       '  duplicated by .f....... par2/f5',
                       '*f.delete f1',
                       '*f.delete f2',
                       '*f.delete par! \\r/f3',
                       '*f.delete par2/f4',
                       '*f.delete par2/f5',
                       '.d..t.... par2',
                       'Paths: 5 total, 5 duplicate, 5 deleted'])

    file10 = CreateFile(parent1, 'f10', contents='4'*1025)
    file11 = CreateFile(parent2, 'f11', contents='4'*1025, mtime=1540000000)

    DoSync(
      root_dir,
      expected_output=['>f+++++++ par! \\r/f10',
                       '>f+++++++ par2/f11',
                       'Paths: 7 total (2kb), 2 synced (2kb), 2 checksummed (2kb)'])

    DoDeleteDuplicateFiles(
      root_dir,
      paths=['par! \r'],
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f10',
                       '  similar to .f..t.... par2/f11',
                       'Paths: 2 total, 1 similar, 1 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)

    DoDeleteDuplicateFiles(
      root_dir,
      paths=['par! \r'], ignore_mtimes=True,
      expected_output=['Verifying manifest for root %s...' % root_dir,
                       'Deleting duplicate files...',
                       'Path par! \\r/f10',
                       '  duplicated by .f..t.... par2/f11',
                       '*f.delete par! \\r/f10',
                       'Paths: 2 total, 1 duplicate, 1 deleted, 1 skipped'])
    DoVerify(root_dir, checksum_all=True, expected_output=None)


if __name__ == '__main__':
  test_main.RunCurrentFileUnitTests()
