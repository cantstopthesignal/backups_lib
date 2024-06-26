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
from .checksums_lib_test_util import DoDiff
from .checksums_lib_test_util import DoImageFromFolder
from .checksums_lib_test_util import DoRenamePaths
from .checksums_lib_test_util import DoSync
from .checksums_lib_test_util import DoVerify
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
                           '>fc.t.... par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 9 total (5kb), 4 synced (1kb), 2 checksummed (1kb)',
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
                           '>fc.t.... par! \\r/f2',
                           '*** Cancelled at path par! \\r/f4',
                           'Paths: 9 total (5kb), 4 synced (1kb), 2 checksummed (1kb)',
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
                           'Paths: 9 total (5kb), 4 synced (1kb), 2 checksummed (1kb)',
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
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path), '16kb', '17.1kb')

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


if __name__ == '__main__':
  test_main.RunCurrentFileUnitTests()
