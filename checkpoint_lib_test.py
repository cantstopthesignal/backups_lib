#!/usr/bin/env -S python3 -u -B

import argparse
import contextlib
import errno
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir))
import backups_lib
__package__ = backups_lib.__package__

from . import backups_main
from . import checkpoint_lib
from . import lib
from . import lib_test_util
from . import test_main

from .test_util import AssertEquals
from .test_util import AssertLinesEqual
from .test_util import AssertNotEquals
from .test_util import BaseTestCase
from .test_util import CreateDir
from .test_util import CreateFile
from .test_util import CreateSymlink
from .test_util import DeleteFileOrDir
from .test_util import DoBackupsMain
from .test_util import OverrideUmask
from .test_util import SetMTime
from .test_util import SetPacificTimezone
from .test_util import TempDir

from .lib_test_util import ApplyFakeDiskImageHelperLevel
from .lib_test_util import AssertFileSizeInRange
from .lib_test_util import CollapseApfsOperationsInOutput
from .lib_test_util import CreateGoogleDriveRemoteFile
from .lib_test_util import DoDumpManifest
from .lib_test_util import DoVerifyManifest
from .lib_test_util import GetManifestItemized
from .lib_test_util import HandleGetPass
from .lib_test_util import HandleGoogleDriveRemoteFiles
from .lib_test_util import InteractiveCheckerReadyResults
from .lib_test_util import SetHdiutilCompactOnBatteryAllowed
from .lib_test_util import SetOmitUidAndGidInPathInfoToString
from .lib_test_util import SetXattr

from .checkpoint_lib_test_util import DoCreate


def AssertRsyncLinesEqual(actual_lines, expected_lines):
  if platform.system() == lib.PLATFORM_LINUX:
    new_expected_lines = []
    for expected_line in expected_lines:
      if expected_line.startswith('*deleting '):
        new_expected_lines.append(expected_line)
      else:
        assert expected_line[11] in ['+', '.']
        new_expected_lines.append(expected_line[:11] + expected_line[12:])
    expected_lines = new_expected_lines
  AssertLinesEqual(actual_lines, expected_lines)


def RsyncPaths(from_path, to_path, checksum=True, dry_run=False,
               filters=checkpoint_lib.STAGED_BACKUP_DEFAULT_FILTERS):
  cmd = [lib.GetRsyncBin(),
         '-aXi',
         '--delete',
         '--numeric-ids',
         '--no-specials',
         '--no-devices']

  if checksum:
    cmd.append('--checksum')
  if dry_run:
    cmd.append('-n')

  if filters is not None:
    for a_filter in filters:
      cmd.append(a_filter.GetRsyncArg())

  cmd.append(lib.MakeRsyncDirname(from_path))
  cmd.append(lib.MakeRsyncDirname(to_path))

  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
  output = []
  with p.stdout:
    for line in p.stdout:
      line = line.strip()
      if not line:
        continue
      pieces = line.split(None, 1)
      assert len(pieces) == 2
      output.append((lib.DecodeRsyncEncodedString(pieces[1]), pieces[0]))
  if p.wait():
    print('\n'.join([ '%s %s' % (change, path) for (path, change) in output ]))
    raise Exception('Rsync failed')
  output.sort()
  return [ '%s %s' % (change, path) for (path, change) in output ]


def AssertEmptyRsync(from_path, to_path, checksum=True):
  AssertLinesEqual(RsyncPaths(from_path, to_path, checksum=checksum, dry_run=True), [])


def AssertBasisInfoFileEquals(metadata_path, basis_path=None):
  basis_info_path = os.path.join(metadata_path, lib.BASIS_INFO_FILENAME)
  if basis_path is None:
    AssertEquals(False, os.path.exists(basis_info_path))
    return
  else:
    AssertEquals(True, os.path.exists(basis_info_path))
    with open(basis_info_path) as in_file:
      json_data = json.load(in_file)
      AssertEquals(os.path.basename(basis_path), json_data['basis_filename'])


def AssertFileContents(expected_contents, path):
  with open(path, 'r') as in_f:
    AssertEquals(expected_contents, in_f.read())


def AssertCheckpointsList(checkpoints_dir, expected_list):
  AssertLinesEqual(
    expected_list,
    [p for p in sorted(os.listdir(checkpoints_dir))
     if checkpoint_lib.CheckpointPathParts.IsMatchingPath(p)])


def VerifyCheckpointContents(manifest, root_dir, prev_manifest=None):
  expected_paths = set()
  for path in manifest.GetPaths():
    manifest_path_info = manifest.GetPathInfo(path)
    prev_path_info = None
    if prev_manifest:
      prev_path_info = prev_manifest.GetPathInfo(path)

    itemized = lib.PathInfo.GetItemizedDiff(prev_path_info, manifest_path_info)
    if itemized.HasDiffs():
      expected_paths.add(path)

  for path in list(expected_paths):
    parent_dir = os.path.dirname(path)
    while parent_dir:
      expected_paths.add(parent_dir)
      parent_dir = os.path.dirname(parent_dir)

  for path in expected_paths:
    manifest_path_info = manifest.GetPathInfo(path)

    full_path = os.path.join(root_dir, path)
    src_path_info = lib.PathInfo.FromPath(path, full_path)
    if src_path_info.HasFileContents():
      src_path_info.sha256 = lib.Sha256(full_path)

    itemized = lib.PathInfo.GetItemizedDiff(src_path_info, manifest_path_info)
    if itemized.HasDiffs():
      raise Exception('Mismatched checkpoint contents: %s' % itemized)


def GetManifestDiffItemized(manifest1, manifest2):
  itemized_outputs = []
  for itemized in manifest2.GetDiffItemized(manifest1):
    itemized_outputs.append(str(itemized))
  return itemized_outputs


def GetManifestProtoDump(manifest):
  proto_outputs = []
  for path in manifest.GetPaths():
    proto_outputs.append(str(manifest.GetPathInfo(path).ToProto()))
  return proto_outputs


def DoApply(src_checkpoint_path, dest_root, dry_run=False, expected_output=[]):
  args = []
  if dry_run:
    args.append('--dry-run')
  args.extend(['apply-checkpoint',
               '--checksum-all',
               '--src-checkpoint-path', src_checkpoint_path,
               '--dest-root', dest_root])
  output = io.StringIO()
  AssertEquals(backups_main.Main(args, output), True)
  output_lines = []
  for line in output.getvalue().strip().split('\n'):
    if not line:
      continue
    output_lines.append(line)
  output.close()
  AssertLinesEqual(output_lines, expected_output)


def DoStrip(checkpoint_path, defragment=True, defragment_iterations=None,
            dry_run=False, expected_output=[]):
  cmd_args = ['strip-checkpoint',
              '--checkpoint-path', checkpoint_path]
  if not defragment:
    cmd_args.append('--no-defragment')
  if defragment_iterations is not None:
    cmd_args.extend(['--defragment-iterations', str(defragment_iterations)])
  output_lines = DoBackupsMain(cmd_args, dry_run=dry_run, expected_output=None)
  output_lines = CollapseApfsOperationsInOutput(output_lines)
  AssertLinesEqual(output_lines, expected_output)


class CreateDryRunTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      with ApplyFakeDiskImageHelperLevel() as should_run:
        if should_run:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')
    file1 = CreateFile(parent1, 'f_\r', contents='small contents')
    file2 = CreateFile(parent1, 'f2')
    file3 = CreateFile(parent1, 'f3')
    SetMTime(parent1)
    SetMTime(src_root)

    DoCreate(
      src_root, checkpoints_dir, '1', dry_run=True,
      expected_output=['>d+++++++ .',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f2',
                       '>f+++++++ par!/f3',
                       '>f+++++++ par!/f_\\r',
                       'Transferring 5 paths (14b)'])
    AssertLinesEqual(os.listdir(checkpoints_dir), [])

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f2',
                       '>f+++++++ par!/f3',
                       '>f+++++++ par!/f_\\r',
                       'Transferring 5 paths (14b)'])
    try:
      VerifyCheckpointContents(manifest1, checkpoint1.GetContentRootPath())
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f3',
                        '.f....... par!/f_\\r'])
      AssertEmptyRsync(src_root, checkpoint1.GetContentRootPath())
    finally:
      checkpoint1.Close()
    if platform.system() == lib.PLATFORM_LINUX:
      AssertCheckpointsList(checkpoints_dir, ['1.img'])
    else:
      AssertCheckpointsList(checkpoints_dir, ['1.sparseimage'])

    SetMTime(file1, None)
    file2 = CreateFile(parent1, 'f2', contents='abc')

    DoCreate(
      src_root, checkpoints_dir, '2', dry_run=True,
      last_checkpoint_path=checkpoint1.GetImagePath(),
    expected_output=['>fcs..... par!/f2',
                     '.f..t.... par!/f_\\r',
                     'Transferring 2 of 5 paths (17b of 17b)'])
    if platform.system() == lib.PLATFORM_LINUX:
      AssertCheckpointsList(checkpoints_dir, ['1.img'])
    else:
      AssertCheckpointsList(checkpoints_dir, ['1.sparseimage'])


class CreateTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_HIGH, test_case=self) as should_run:
      if should_run:
        with TempDir() as test_dir:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')
    file1 = CreateFile(parent1, 'f_\r')
    file2 = CreateFile(parent1, 'f2')
    file3 = CreateFile(parent1, 'f3')
    file6_from = CreateFile(parent1, 'file6_from', contents='file6_contents')

    file_skip1 = CreateFile(src_root, 'SKIP1')
    file_skip1 = CreateFile(parent1, '2.skp')
    CreateFile(src_root, checkpoint_lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
               contents=['exclude /SKIP1',
                         'exclude *.skp'])

    checkpoint_manifest_only, manifest_only = DoCreate(
      src_root, checkpoints_dir, 'manifest_only',
      manifest_only=True,
      expected_output=['>d+++++++ .',
                       '>f+++++++ .staged_backup_filter',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f2',
                       '>f+++++++ par!/f3',
                       '>f+++++++ par!/f_\\r',
                       '>f+++++++ par!/file6_from',
                       'Transferring 7 paths (43b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest_only),
                       ['.d....... .',
                        '.f....... .staged_backup_filter',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f3',
                        '.f....... par!/f_\\r',
                        '.f....... par!/file6_from'])
    finally:
      checkpoint_manifest_only.Close()

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .',
                       '>f+++++++ .staged_backup_filter',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f2',
                       '>f+++++++ par!/f3',
                       '>f+++++++ par!/f_\\r',
                       '>f+++++++ par!/file6_from',
                       'Transferring 7 paths (43b)'])
    try:
      VerifyCheckpointContents(manifest1, checkpoint1.GetContentRootPath())
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.f....... .staged_backup_filter',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f3',
                        '.f....... par!/f_\\r',
                        '.f....... par!/file6_from'])
      AssertEmptyRsync(src_root, checkpoint1.GetContentRootPath())
      AssertBasisInfoFileEquals(checkpoint1.GetMetadataPath(), None)
    finally:
      checkpoint1.Close()

    checkpoint2, manifest2 = DoCreate(src_root, checkpoints_dir, '2',
                                      last_checkpoint_path=checkpoint1.GetImagePath(),
                                      readonly=False)
    try:
      VerifyCheckpointContents(manifest2, checkpoint2.GetContentRootPath(), prev_manifest=manifest1)
      AssertLinesEqual(GetManifestDiffItemized(manifest1, manifest2), [])
      AssertRsyncLinesEqual(RsyncPaths(src_root, checkpoint2.GetContentRootPath()),
                            ['.d..t....... ./',
                             '>f++++++++++ .staged_backup_filter',
                             'cd++++++++++ par!/',
                             '>f++++++++++ par!/f2',
                             '>f++++++++++ par!/f3',
                             '>f++++++++++ par!/f_\r',
                             '>f++++++++++ par!/file6_from'])
      AssertBasisInfoFileEquals(checkpoint2.GetMetadataPath(), checkpoint1.GetImagePath())
      DoVerifyManifest(src_root, manifest2.GetPath(),
                       expected_success=False,
                       expected_output=['*f.delete SKIP1',
                                        '*f.delete par!/2.skp'])
      DoVerifyManifest(checkpoint2.GetContentRootPath(), manifest2.GetPath())
    finally:
      checkpoint2.Close()

    SetXattr(src_root, 'example', b'example_value')
    SetXattr(src_root, 'example2', b'example_value2')
    SetMTime(file1, None)
    file2 = CreateFile(parent1, 'f2', contents='abc')

    checkpoint3, manifest3 = DoCreate(
      src_root, checkpoints_dir, '3',
      last_checkpoint_path=checkpoint2.GetImagePath(),
      expected_output=['.d......x .',
                       '>fcs..... par!/f2',
                       '.f..t.... par!/f_\\r',
                       'Transferring 3 of 7 paths (3b of 46b)'],
      readonly=False)
    try:
      VerifyCheckpointContents(manifest3, checkpoint3.GetContentRootPath(), prev_manifest=manifest2)
      AssertLinesEqual(GetManifestItemized(manifest3),
                       GetManifestItemized(manifest1))
      AssertLinesEqual(GetManifestDiffItemized(manifest2, manifest3),
                       ['.d......x .',
                        '>fcs..... par!/f2',
                        '.f..t.... par!/f_\\r'])
      AssertBasisInfoFileEquals(checkpoint3.GetMetadataPath(), checkpoint2.GetImagePath())
      DoVerifyManifest(checkpoint3.GetContentRootPath(), manifest3.GetPath(),
                       expected_success=False,
                       expected_output=['>f+++++++ .staged_backup_filter',
                                        '>f+++++++ par!/f3',
                                        '>f+++++++ par!/file6_from'])
      checkpoint2 = checkpoint_lib.Checkpoint.Open(checkpoint2.GetImagePath(), readonly=False)
      try:
        AssertRsyncLinesEqual(RsyncPaths(src_root, checkpoint2.GetContentRootPath()),
                              ['.d........x. ./',
                               '>fcs........ par!/f2',
                               '.f..t....... par!/f_\r'])
      finally:
        checkpoint2.Close()
      AssertRsyncLinesEqual(RsyncPaths(src_root, checkpoint3.GetContentRootPath()),
                            ['>f++++++++++ .staged_backup_filter',
                             '>f++++++++++ par!/f3',
                             '>f++++++++++ par!/file6_from'])
    finally:
      checkpoint3.Close()

    file2 = CreateFile(parent1, 'f2', contents='def')
    SetMTime(parent1, 1510000000)
    parent2 = CreateDir(src_root, 'par2')
    file2b = CreateFile(parent2, 'f2b', contents='def')
    DeleteFileOrDir(file6_from)
    file6_to = CreateFile(parent1, 'file6_to', contents='file6_contents')
    file6_to2 = CreateFile(parent1, 'file6_to2', contents='file6_contents')
    file6_to3 = CreateFile(parent1, 'file6_to3', contents='file6_contents_notmatch')

    def PreSyncContentsTestHook(checkpoint_creator):
      CreateFile(parent1, 'f2', contents='ghi')
      SetXattr(parent1, 'example', b'example_value_5')
      SetMTime(parent1, 1520000000)
      CreateFile(parent2, 'f2b', contents='jkl')
      SetMTime(parent2, 1520000000)
      SetMTime(file6_to2, 1520000000)
      file6_to3 = CreateFile(parent1, 'file6_to3', contents='file6_contents')

    checkpoint_lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = PreSyncContentsTestHook
    try:
      checkpoint4, manifest4 = DoCreate(
        src_root, checkpoints_dir, '4',
        last_checkpoint_path=checkpoint3.GetImagePath(),
        readonly=False,
        expected_output=['.d..t.... par!',
                         '>fc...... par!/f2',
                         '*f.delete par!/file6_from',
                         '  replaced by duplicate: .f....... par!/file6_to',
                         '  replaced by duplicate: .f....... par!/file6_to2',
                         '>f+++++++ par!/file6_to',
                         '  replacing duplicate: .f....... par!/file6_from',
                         '>f+++++++ par!/file6_to2',
                         '  replacing duplicate: .f....... par!/file6_from',
                         '>f+++++++ par!/file6_to3',
                         '>d+++++++ par2',
                         '>f+++++++ par2/f2b',
                         '*** Warning: Paths changed since syncing, checking...',
                         '.d..t...x par!',
                         '>fc...... par!/f2',
                         '>f+++++++ par!/file6_to2',
                         '  replacing similar: .f..t.... par!/file6_from',
                         '>f+++++++ par!/file6_to3',
                         '  replacing duplicate: .f....... par!/file6_from',
                         '>d+++++++ par2',
                         '>f+++++++ par2/f2b',
                         'Transferring 13 of 17 paths (91b of 120b)'])
      try:
        VerifyCheckpointContents(manifest4, checkpoint4.GetContentRootPath(), prev_manifest=manifest3)
        AssertLinesEqual(GetManifestDiffItemized(manifest3, manifest4),
                         ['.d..t...x par!',
                          '>fc...... par!/f2',
                          '*f.delete par!/file6_from',
                          '>f+++++++ par!/file6_to',
                          '>f+++++++ par!/file6_to2',
                          '>f+++++++ par!/file6_to3',
                          '>d+++++++ par2',
                          '>f+++++++ par2/f2b'])
        AssertRsyncLinesEqual(RsyncPaths(src_root, checkpoint4.GetContentRootPath()),
                              ['>f++++++++++ .staged_backup_filter',
                               '>f++++++++++ par!/f3',
                               '>f++++++++++ par!/f_\r'])
        AssertBasisInfoFileEquals(checkpoint4.GetMetadataPath(), checkpoint3.GetImagePath())
        DoVerifyManifest(checkpoint4.GetContentRootPath(), manifest4.GetPath())
      finally:
        checkpoint4.Close()
    finally:
      checkpoint_lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = None

    file4 = CreateFile(parent1, 'f4')
    SetMTime(parent1, 1510000000)
    DeleteFileOrDir(file6_to2)
    DeleteFileOrDir(file6_to3)

    def PreSyncContentsTestHook(checkpoint_creator):
      file4_stat = os.lstat(os.path.join(parent1, 'f4'))
      if file4_stat.st_mtime == 1500000000:
        CreateFile(parent1, 'f4', mtime=1520000000)
      elif file4_stat.st_mtime == 1520000000:
        CreateFile(parent1, 'f4', mtime=1530000000)
        SetMTime(parent1, 1530000000)

    checkpoint_lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = PreSyncContentsTestHook
    try:
      checkpoint5, manifest5 = DoCreate(
        src_root, checkpoints_dir, '5',
        last_checkpoint_path=checkpoint4.GetImagePath(),
        readonly=False,
        expected_output=['.d..t.... par!',
                         '>f+++++++ par!/f4',
                         '*f.delete par!/file6_to2',
                         '  replaced by similar: .f..t.... par!/file6_to',
                         '*f.delete par!/file6_to3',
                         '  replaced by duplicate: .f....... par!/file6_to',
                         '*** Warning: Paths changed since syncing, checking...',
                         '>f+++++++ par!/f4',
                         '*** Warning: Paths changed since syncing, checking...',
                         '.d..t.... par!',
                         '>f+++++++ par!/f4',
                         'Transferring 5 of 13 paths (0b of 49b)'])
      try:
        VerifyCheckpointContents(manifest5, checkpoint5.GetContentRootPath(), prev_manifest=manifest4)
        AssertLinesEqual(GetManifestDiffItemized(manifest4, manifest5),
                         ['.d..t.... par!',
                          '>f+++++++ par!/f4',
                          '*f.delete par!/file6_to2',
                          '*f.delete par!/file6_to3'])
        AssertRsyncLinesEqual(RsyncPaths(src_root, checkpoint5.GetContentRootPath()),
                              ['>f++++++++++ .staged_backup_filter',
                               '>f++++++++++ par!/f2',
                               '>f++++++++++ par!/f3',
                               '>f++++++++++ par!/f_\r',
                               '>f++++++++++ par!/file6_to',
                               'cd++++++++++ par2/',
                               '>f++++++++++ par2/f2b'])
        AssertBasisInfoFileEquals(checkpoint5.GetMetadataPath(), checkpoint4.GetImagePath())
        DoVerifyManifest(checkpoint5.GetContentRootPath(), manifest5.GetPath())
      finally:
        checkpoint5.Close()
    finally:
      checkpoint_lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = None

    file5 = CreateFile(src_root, 'f5')
    SetMTime(src_root, 1510000000)


class CreateWithFilterMergeTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      with ApplyFakeDiskImageHelperLevel() as should_run:
        if should_run:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par')
    parent_skip1 = CreateDir(src_root, 'par_skip')
    file1 = CreateFile(parent1, 'f1')
    file2 = CreateFile(parent1, 'f2')
    file3 = CreateFile(parent_skip1, 'f3')

    filter_merge_path = CreateFile(
      test_dir, 'filter_merge',
      contents=['exclude *.skp',
                'include /par',
                'include /par/**',
                'exclude *'])

    CreateFile(parent1, 'SKIP1')
    CreateFile(parent1, '2.skp')
    CreateFile(parent1, checkpoint_lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
               contents=['exclude /SKIP1'])

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      filter_merge_path=filter_merge_path,
      expected_output=['>d+++++++ .',
                       '>d+++++++ par',
                       '>f+++++++ par/.staged_backup_filter',
                       '>f+++++++ par/f1',
                       '>f+++++++ par/f2',
                       'Transferring 5 paths (15b)'])
    try:
      VerifyCheckpointContents(manifest1, checkpoint1.GetContentRootPath())
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.d....... par',
                        '.f....... par/.staged_backup_filter',
                        '.f....... par/f1',
                        '.f....... par/f2'])
    finally:
      checkpoint1.Close()


class CreateFromGoogleDriveTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      with ApplyFakeDiskImageHelperLevel() as should_run:
        if should_run:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par')

    file1 = CreateGoogleDriveRemoteFile(parent1, 'f1.gdoc', contents='mydoc1')

    file2 = CreateFile(parent1, 'f2', contents='abc')

    with HandleGoogleDriveRemoteFiles([file1]):
     checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1',
        expected_output=['>d+++++++ .',
                         '>d+++++++ par',
                         '>f+++++++ par/f1.gdoc',
                         '>f+++++++ par/f2',
                         'Transferring 4 paths (9b)'])

    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.d....... par',
                        '.f....... par/f1.gdoc',
                        '.f....... par/f2'])
      f1_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'par/f1.gdoc')
      AssertEquals(['com.google.drivefs.item-id#S'], lib.Xattr(f1_checkpoint).keys())
      AssertEquals(b'FAKE_ID', lib.Xattr(f1_checkpoint)[lib.GOOGLE_DRIVE_FILE_XATTR_KEY])
      f2_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'par/f2')
      AssertFileContents('abc', f2_checkpoint)
    finally:
      checkpoint1.Close()


class CreateWithFollowSymlinksTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      with TempDir() as test_dir2:
        with ApplyFakeDiskImageHelperLevel() as should_run:
          if should_run:
            self.RunTest(test_dir, test_dir2)

  def RunTest(self, test_dir, test_dir2):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')

    file1 = CreateFile(src_root, 'f1')
    ln1 = CreateSymlink(src_root, 'ln1', 'INVALID')

    ref_dir1 = CreateDir(test_dir2, 'd1')
    ref_file2 = CreateFile(ref_dir1, 'f2', contents='abc')
    ln2 = CreateSymlink(src_root, 'ln2', test_dir2)
    ln3 = CreateSymlink(src_root, 'ln3', test_dir2)

    ln4 = CreateSymlink(test_dir2, 'ln4', 'd1/f2')
    ln5 = CreateSymlink(test_dir2, 'ln5', 'd1/f2')

    ln6 = CreateSymlink(test_dir2, 'ln6', 'd1')
    ln7 = CreateSymlink(test_dir2, 'ln7', 'd1')

    DoCreate(
      src_root, checkpoints_dir, '1', dry_run=True,
      expected_output=['>d+++++++ .',
                       '>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> %s' % test_dir2,
                       '>L+++++++ ln3 -> %s' % test_dir2,
                       'Transferring 5 paths (0b)'])

    CreateFile(src_root, checkpoint_lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
               contents=['follow-symlinks /ln2/',
                         'follow-symlinks /ln2/ln4',
                         'follow-symlinks /ln2/ln6'])

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .',
                       '>f+++++++ .staged_backup_filter',
                       '>f+++++++ f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>d+++++++ ln2',
                       '>d+++++++ ln2/d1',
                       '>f+++++++ ln2/d1/f2',
                       '>f+++++++ ln2/ln4',
                       '>L+++++++ ln2/ln5 -> d1/f2',
                       '>d+++++++ ln2/ln6',
                       '>f+++++++ ln2/ln6/f2',
                       '>L+++++++ ln2/ln7 -> d1',
                       '>L+++++++ ln3 -> %s' % test_dir2,
                       'Transferring 13 paths (81b)'])

    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.f....... .staged_backup_filter',
                        '.f....... f1',
                        '.L....... ln1 -> INVALID',
                        '.d....... ln2',
                        '.d....... ln2/d1',
                        '.f....... ln2/d1/f2',
                        '.f....... ln2/ln4',
                        '.L....... ln2/ln5 -> d1/f2',
                        '.d....... ln2/ln6',
                        '.f....... ln2/ln6/f2',
                        '.L....... ln2/ln7 -> d1',
                        '.L....... ln3 -> %s' % test_dir2])
      VerifyCheckpointContents(manifest1, checkpoint1.GetContentRootPath())
      f1_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'par/f1')
      f2_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'ln2/d1/f2')
      AssertFileContents('abc', f2_checkpoint)
      ln2_ln4_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'ln2/ln4')
      AssertFileContents('abc', ln2_ln4_checkpoint)
      ln6_f2_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'ln2/ln6/f2')
      AssertFileContents('abc', ln6_f2_checkpoint)
    finally:
      checkpoint1.Close()

    SetXattr(test_dir2, 'example', b'example_value')
    ref_dir2 = CreateDir(test_dir2, 'd2')
    ref_file3 = CreateFile(ref_dir2, 'f3', contents='def')

    checkpoint2, manifest2 = DoCreate(
      src_root, checkpoints_dir, '2',
      last_checkpoint_path=checkpoint1.GetImagePath(),
      expected_output=['.d......x ln2',
                       '>d+++++++ ln2/d2',
                       '>f+++++++ ln2/d2/f3',
                       'Transferring 3 of 15 paths (3b of 84b)'])
    try:
      VerifyCheckpointContents(manifest2, checkpoint2.GetContentRootPath(), prev_manifest=manifest1)
      ln2_checkpoint = os.path.join(checkpoint2.GetContentRootPath(), 'ln2')
      AssertEquals(b'example_value', lib.Xattr(ln2_checkpoint)['example'])
    finally:
      checkpoint2.Close()

    ref_file3 = CreateFile(ref_dir2, 'f3', contents='ghi')

    checkpoint3, manifest3 = DoCreate(
      src_root, checkpoints_dir, '3',
      last_checkpoint_path=checkpoint2.GetImagePath(),
      expected_output=['>fc...... ln2/d2/f3',
                       'Transferring 1 of 15 paths (3b of 84b)'])
    try:
      VerifyCheckpointContents(manifest3, checkpoint3.GetContentRootPath(), prev_manifest=manifest2)
      ref_file3_checkpoint = os.path.join(checkpoint3.GetContentRootPath(), 'ln2/d2/f3')
      AssertFileContents('ghi', ref_file3_checkpoint)
      ln2_checkpoint = os.path.join(checkpoint3.GetContentRootPath(), 'ln2')
      AssertEquals(b'example_value', lib.Xattr(ln2_checkpoint)['example'])
    finally:
      checkpoint3.Close()


class ApplyDryRunTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      with ApplyFakeDiskImageHelperLevel() as should_run:
        if should_run:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')
    file1 = CreateFile(parent1, 'f_\r')
    SetMTime(parent1)
    SetMTime(src_root)
    SetXattr(src_root, 'example', b'example_value')

    dest_root = CreateDir(test_dir, 'dest')
    dest_parent1 = CreateDir(dest_root, 'del_par!')
    deleted_file1 = CreateFile(dest_parent1, 'del')
    SetMTime(dest_root)
    SetXattr(dest_root, 'example', b'example_value')

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r',
                       'Transferring 3 paths (0b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.d....... par!',
                        '.f....... par!/f_\\r'])
    finally:
      checkpoint1.Close()

    DoApply(checkpoint1.GetImagePath(), dest_root, dry_run=True,
            expected_output=['*d.delete del_par!',
                             '*f.delete del_par!/del',
                             '>d+++++++ par!',
                             '>f+++++++ par!/f_\\r'])
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root),
                          ['*deleting del_par!/',
                           '*deleting del_par!/del',
                           'cd++++++++++ par!/',
                           '>f++++++++++ par!/f_\r'])


class ApplyTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_HIGH, test_case=self) as should_run:
      if should_run:
        with TempDir() as test_dir:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    SetXattr(src_root, 'example', b'example_value')
    parent1 = CreateDir(src_root, 'par!')
    file1 = CreateFile(parent1, 'f_\r', mtime=-2082844800)
    ln2 = CreateSymlink(parent1, 'ln2', 'f_\r')
    ln1_dir = CreateSymlink(src_root, 'ln1_dir', 'par!')
    ln3 = CreateSymlink(src_root, 'ln3', 'INVALID')
    assert os.path.isdir(ln1_dir)

    dest_root = CreateDir(test_dir, 'dest')
    dest_parent1 = CreateDir(dest_root, 'del_par!')
    SetXattr(dest_root, 'example', b'example_value')
    deleted_file1 = CreateFile(dest_parent1, 'del')

    # Initial sync

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .',
                       '>L+++++++ ln1_dir -> par!',
                       '>L+++++++ ln3 -> INVALID',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r',
                       '>L+++++++ par!/ln2 -> f_\\r',
                       'Transferring 6 paths (0b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.L....... ln1_dir -> par!',
                        '.L....... ln3 -> INVALID',
                        '.d....... par!',
                        '.f....... par!/f_\\r',
                        '.L....... par!/ln2 -> f_\\r'])
    finally:
      checkpoint1.Close()

    DoApply(checkpoint1.GetImagePath(), dest_root,
            expected_output=['*d.delete del_par!',
                             '*f.delete del_par!/del',
                             '>L+++++++ ln1_dir -> par!',
                             '>L+++++++ ln3 -> INVALID',
                             '>d+++++++ par!',
                             '>f+++++++ par!/f_\\r',
                             '>L+++++++ par!/ln2 -> f_\\r'])
    AssertEmptyRsync(src_root, dest_root)

    # Create new files
    file2 = CreateFile(parent1, 'f2')
    # One with ignored xattr
    file3 = CreateFile(src_root, 'f3')
    SetXattr(file3, 'com.apple.lastuseddate#PS', b'Initial')
    SetXattr(file3, 'example', b'example_value_initial')

    checkpoint2, manifest2 = DoCreate(
      src_root, checkpoints_dir, '2', last_checkpoint_path=checkpoint1.GetImagePath(),
      expected_output=['>f+++++++ f3',
                       '>f+++++++ par!/f2',
                       'Transferring 2 of 8 paths (0b of 0b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest2),
                       ['.d....... .',
                        '.f....... f3',
                        '.L....... ln1_dir -> par!',
                        '.L....... ln3 -> INVALID',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f_\\r',
                        '.L....... par!/ln2 -> f_\\r'])
      AssertEquals(sorted(lib.Xattr(os.path.join(checkpoint2.GetContentRootPath(), 'f3')).keys()),
                   ['com.apple.lastuseddate#PS', 'example'])
    finally:
      checkpoint2.Close()

    DoApply(checkpoint2.GetImagePath(), dest_root,
            expected_output=['>f+++++++ f3',
                             '>f+++++++ par!/f2'])
    AssertEmptyRsync(src_root, dest_root)

    # Set xattr of root dir
    SetXattr(src_root, 'example', b'example_value_new')
    # And adjust an ignored xattr
    SetXattr(file3, 'com.apple.lastuseddate#PS', b'Modified')

    checkpoint3, manifest3 = DoCreate(
      src_root, checkpoints_dir, '3', last_checkpoint_path=checkpoint2.GetImagePath(),
      expected_output=['.d......x .',
                       'Transferring 1 of 8 paths (0b of 0b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest3),
                       ['.d....... .',
                        '.f....... f3',
                        '.L....... ln1_dir -> par!',
                        '.L....... ln3 -> INVALID',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f_\\r',
                        '.L....... par!/ln2 -> f_\\r'])
    finally:
      checkpoint3.Close()

    DoApply(checkpoint3.GetImagePath(), dest_root,
            expected_output=['.d......x .'])
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
                          ['.f........x. f3'])

    # No modifications

    checkpoint4, manifest4 = DoCreate(
      src_root, checkpoints_dir, '4', last_checkpoint_path=checkpoint3.GetImagePath(),
      expected_output=[])
    try:
      AssertLinesEqual(GetManifestItemized(manifest4),
                       ['.d....... .',
                        '.f....... f3',
                        '.L....... ln1_dir -> par!',
                        '.L....... ln3 -> INVALID',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f_\\r',
                        '.L....... par!/ln2 -> f_\\r'])
    finally:
      checkpoint4.Close()

    DoApply(checkpoint4.GetImagePath(), dest_root,
            expected_output=[])
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
                          ['.f........x. f3'])

    # Modify some existing files
    file2 = CreateFile(parent1, 'f2', contents='abc')
    ln2 = CreateSymlink(parent1, 'ln2', 'INVALID')
    ln1_dir = CreateSymlink(src_root, 'ln1_dir', 'par!/f2')
    DeleteFileOrDir(ln3)
    SetXattr(file3, 'example', b'example_value_modified')

    checkpoint5, manifest5 = DoCreate(
      src_root, checkpoints_dir, '5', last_checkpoint_path=checkpoint4.GetImagePath(),
      expected_output=['.f......x f3',
                       '.Lc...... ln1_dir -> par!/f2',
                       '*L.delete ln3',
                       '>fcs..... par!/f2',
                       '.Lc...... par!/ln2 -> INVALID',
                       'Transferring 4 of 7 paths (3b of 3b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest5),
                       ['.d....... .',
                        '.f....... f3',
                        '.L....... ln1_dir -> par!/f2',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f_\\r',
                        '.L....... par!/ln2 -> INVALID'])
      AssertEquals(sorted(lib.Xattr(os.path.join(checkpoint5.GetContentRootPath(), 'f3')).keys()),
                   ['com.apple.lastuseddate#PS', 'example'])
    finally:
      checkpoint5.Close()

    DoApply(checkpoint5.GetImagePath(), dest_root,
            expected_output=['.f......x f3',
                             '.Lc...... ln1_dir -> par!/f2',
                             '*L.delete ln3',
                             '>fcs..... par!/f2',
                             '.Lc...... par!/ln2 -> INVALID'])
    AssertEmptyRsync(src_root, dest_root)

    # Modify an existing file's contents, leaving size and time the same
    file2 = CreateFile(parent1, 'f2', contents='def')

    checkpoint6, manifest6 = DoCreate(
      src_root, checkpoints_dir, '6', last_checkpoint_path=checkpoint5.GetImagePath(),
      checksum_all=False)
    try:
      DoVerifyManifest(src_root, manifest6.GetPath(),
                       expected_success=False,
                       expected_output=['>fc...... par!/f2'])
      DoVerifyManifest(dest_root, manifest6.GetPath())
    finally:
      checkpoint6.Close()

    DoApply(checkpoint6.GetImagePath(), dest_root)
    AssertEmptyRsync(src_root, dest_root, checksum=False)
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root, checksum=True, dry_run=True),
                          ['>fc......... par!/f2'])

    # Now do a sync with checksum all and verify the diffing file gets transferred

    checkpoint7, manifest7 = DoCreate(
      src_root, checkpoints_dir, '7', last_checkpoint_path=checkpoint6.GetImagePath(),
      expected_output=['>fc...... par!/f2',
                       'Transferring 1 of 7 paths (3b of 3b)'])
    try:
      DoVerifyManifest(src_root, manifest7.GetPath())
      DoVerifyManifest(dest_root, manifest7.GetPath(),
                       expected_success=False,
                       expected_output=['>fc...... par!/f2'] )
    finally:
      checkpoint7.Close()

    DoApply(checkpoint7.GetImagePath(), dest_root,
            expected_output=['>fc...... par!/f2'])
    AssertEmptyRsync(src_root, dest_root)

    DoVerifyManifest(dest_root, checkpoint7.GetImagePath())


class ApplyFromGoogleDriveTestCase(BaseTestCase):
  def test(self):
    with OverrideUmask(0o022):
      with TempDir() as test_dir:
        with ApplyFakeDiskImageHelperLevel() as should_run:
          if should_run:
            self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')

    dest_root = CreateDir(test_dir, 'dest')

    gdrf1 = CreateGoogleDriveRemoteFile(parent1, 'g1.gdoc', contents='mydoc1')

    file2 = CreateFile(parent1, 'f2', contents='abc')

    with HandleGoogleDriveRemoteFiles([gdrf1]) as handler:
      checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1',
        expected_output=['>d+++++++ .',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f2',
                         '>f+++++++ par!/g1.gdoc',
                         'Transferring 4 paths (9b)'])
      AssertEquals([gdrf1], handler.GetPathsWithStatOverrides())
    try:
      DoDumpManifest(
        checkpoint1.GetManifestPath(),
        expected_output=[
          'dir path=., mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          'dir path=par!, mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          "file path=par!/f2, mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=3, sha256='ba7816'",
          ("file path=par!/g1.gdoc, mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=6, " +
           "sha256='c73ef4', xattr-hash='38514d', xattr-keys=['com.google.drivefs.item-id#S']")])
    finally:
      checkpoint1.Close()

    DoApply(checkpoint1.GetImagePath(), dest_root,
            expected_output=['>d+++++++ par!',
                             '>f+++++++ par!/f2',
                             '>f+++++++ par!/g1.gdoc'])
    DoVerifyManifest(dest_root, checkpoint1.GetImagePath())
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True), [])

    gdrf2 = CreateGoogleDriveRemoteFile(parent1, 'g2.gsheet', contents='mysheet1')

    with HandleGoogleDriveRemoteFiles([gdrf1, gdrf2]) as handler:
      checkpoint2, manifest2 = DoCreate(
        src_root, checkpoints_dir, '2', last_checkpoint_path=checkpoint1.GetImagePath(),
        expected_output=['>f+++++++ par!/g2.gsheet',
                         'Transferring 1 of 5 paths (8b of 17b)'])
      AssertEquals([gdrf1, gdrf2], handler.GetPathsWithStatOverrides())
    try:
      AssertLinesEqual(GetManifestItemized(manifest2),
                       ['.d....... .',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/g1.gdoc',
                        '.f....... par!/g2.gsheet'])
    finally:
      checkpoint2.Close()

    DoApply(checkpoint2.GetImagePath(), dest_root,
            expected_output=['>f+++++++ par!/g2.gsheet'])
    DoVerifyManifest(dest_root, checkpoint2.GetImagePath())
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True), [])

    SetMTime(gdrf1, 1510000000)
    SetMTime(file2, 1510000000)

    with HandleGoogleDriveRemoteFiles([gdrf1, gdrf2]) as handler:
      checkpoint3, manifest3 = DoCreate(
        src_root, checkpoints_dir, '3', last_checkpoint_path=checkpoint2.GetImagePath(),
        expected_output=['.f..t.... par!/f2',
                         '.f..t.... par!/g1.gdoc',
                         'Transferring 2 of 5 paths (9b of 17b)'])
      AssertEquals([gdrf1, gdrf2], handler.GetPathsWithStatOverrides())
    try:
      AssertLinesEqual(GetManifestItemized(manifest3),
                       ['.d....... .',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/g1.gdoc',
                        '.f....... par!/g2.gsheet'])
    finally:
      checkpoint3.Close()

    DoApply(checkpoint3.GetImagePath(), dest_root,
            expected_output=['.f..t.... par!/f2',
                             '.f..t.... par!/g1.gdoc'])
    DoVerifyManifest(dest_root, checkpoint3.GetImagePath())
    AssertRsyncLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True), [])


class ApplyWithEncryptionTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_NONE, test_case=self) as should_run:
      if should_run:
        with TempDir() as test_dir:
          self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')

    dest_root = CreateDir(test_dir, 'dest')
    file2 = CreateFile(parent1, 'f2', contents='abc')

    image_ext = '.sparseimage'
    if platform.system() == lib.PLATFORM_LINUX:
      image_ext = '.luks.img'

    try:
      with HandleGetPass(
          expected_prompts=['Enter a new password to secure "1%s": ' % image_ext,
                            'Re-enter new password: '],
          returned_passwords=['abc',
                              'DIFFERENT']):
        DoCreate(
          src_root, checkpoints_dir, '1', encrypt=True)
        raise Exception('Expected a password mismatch exception')
    except lib.PasswordsDidNotMatchError as e:
      pass

    with HandleGetPass(
        expected_prompts=['Enter a new password to secure "1%s": ' % image_ext,
                          'Re-enter new password: ',
                          'Enter password to access "1%s": ' % image_ext],
        returned_passwords=['abc', 'abc', 'abc']):
      checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1', encrypt=True,
        expected_output=['>d+++++++ .',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f2',
                         'Transferring 3 paths (3b)'])

    try:
      DoDumpManifest(
        checkpoint1.GetManifestPath(),
        expected_output=[
          'dir path=., mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          'dir path=par!, mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          "file path=par!/f2, mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=3, sha256='ba7816'"
        ])
    finally:
      checkpoint1.Close()

    with HandleGetPass(
        expected_prompts=['Enter password to access "1%s": ' % image_ext],
        returned_passwords=['abc']):
      DoApply(checkpoint1.GetImagePath(), dest_root,
              expected_output=['>d+++++++ par!',
                               '>f+++++++ par!/f2'])
    with HandleGetPass(
        expected_prompts=['Enter password to access "1%s": ' % image_ext],
        returned_passwords=['abc']):
      DoVerifyManifest(dest_root, checkpoint1.GetImagePath())
    AssertEmptyRsync(src_root, dest_root)

    file3 = CreateFile(parent1, 'f3', contents='def')

    with InteractiveCheckerReadyResults(
        lib.EncryptionManager.INTERACTIVE_CHECKER) as interactive_checker:
      interactive_checker.AddReadyResult(True)
      with HandleGetPass(
          expected_prompts=['Enter password to access "1%s": ' % image_ext,
                            'Enter password to access "1%s": ' % image_ext,
                            'Enter a new password to secure "2%s": ' % image_ext,
                            'Re-enter new password: ',
                            'Enter password to access "2%s": ' % image_ext,
                            'Enter password to access "2%s": ' % image_ext],
          returned_passwords=['DIFFERENT', 'abc', 'def', 'def', 'DIFFERENT', 'def']):
        checkpoint2, manifest2 = DoCreate(
          src_root, checkpoints_dir, '2', encrypt=True, last_checkpoint_path=checkpoint1.GetImagePath(),
          expected_output=['New password does not match any previous passwords, continue? (y/N): y',
                           '>f+++++++ par!/f3',
                           'Transferring 1 of 4 paths (3b of 6b)'])
      checkpoint2.Close()

    with HandleGetPass(
        expected_prompts=['Enter password to access "2%s": ' % image_ext,
                          'Enter password to access "2%s": ' % image_ext],
        returned_passwords=['DIFFERENT', 'def']):
      DoApply(checkpoint2.GetImagePath(), dest_root,
              expected_output=['>f+++++++ par!/f3'])
    with HandleGetPass(
        expected_prompts=['Enter password to access "2%s": ' % image_ext,
                          'Enter password to access "2%s": ' % image_ext],
        returned_passwords=['DIFFERENT', 'def']):
      DoVerifyManifest(dest_root, checkpoint2.GetImagePath())
    AssertEmptyRsync(src_root, dest_root)


class StripTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_NONE, test_case=self) as should_run:
      if should_run:
        with SetHdiutilCompactOnBatteryAllowed(True):
          with TempDir() as test_dir:
            self.RunTest(test_dir)

  def RunTest(self, test_dir):
    def AssertCheckpointStripState(image_path, stripped_expected):
      checkpoint = checkpoint_lib.Checkpoint.Open(image_path)
      try:
        AssertEquals(True, os.path.exists(checkpoint.GetMetadataPath()))
        AssertEquals(not stripped_expected, os.path.exists(checkpoint.GetContentRootPath()))
      finally:
        checkpoint.Close()

    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    file1 = CreateFile(src_root, 'f1', contents='1' * (1024 * 1024 * 20))

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .', '>f+++++++ f1', 'Transferring 2 paths (20mb)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.f....... f1'])
    finally:
      checkpoint1.Close()
    checkpoint1_path_parts = checkpoint_lib.CheckpointPathParts(checkpoint1.GetImagePath())
    AssertCheckpointStripState(checkpoint1.GetImagePath(), False)

    checkpoint2_path = os.path.join(checkpoints_dir, '2.sparseimage')
    checkpoint2_path_parts = checkpoint_lib.CheckpointPathParts(checkpoint2_path)
    shutil.copy(checkpoint1.GetImagePath(), checkpoint2_path)

    if platform.system() == lib.PLATFORM_DARWIN:
      AssertFileSizeInRange(os.lstat(checkpoint1.GetImagePath()).st_size, '34mb', '35.1mb')

      DoStrip(checkpoint1.GetImagePath(), defragment=False, dry_run=True,
              expected_output=['Checkpoint stripped',
                               re.compile('^Image size 3[45]mb -> 3[45]mb$')])
      DoStrip(checkpoint1.GetImagePath(), defragment=False,
              expected_output=['Checkpoint stripped',
                               'Starting to compact…',
                               'Reclaiming free space…',
                               'Finishing compaction…',
                               'Reclaimed 4 MB out of 1023.6 GB possible.',
                               re.compile('^Image size 3[45]mb -> 3[01]mb$')])
      checkpoint1_path_parts.SetIsManifestOnly(True)
      AssertFileSizeInRange(os.lstat(checkpoint1_path_parts.GetPath()).st_size, '30mb', '31.1mb')
      AssertCheckpointStripState(checkpoint1_path_parts.GetPath(), True)
    else:
      AssertEquals(1073741824, os.lstat(checkpoint1.GetImagePath()).st_size)
      DoStrip(checkpoint1.GetImagePath(), defragment=False, dry_run=True,
              expected_output=['Checkpoint stripped',
                               'Image size 1gb -> 1gb'])
      checkpoint1_path_parts.SetIsManifestOnly(True)
      DoStrip(checkpoint1.GetImagePath(), defragment=False,
              expected_output=[
                'Checkpoint stripped',
                re.compile('^e2fsck .*$'),
                'Pass 1: Checking inodes, blocks, and sizes',
                'Pass 2: Checking directory structure',
                'Pass 3: Checking directory connectivity',
                'Pass 4: Checking reference counts',
                'Pass 5: Checking group summary information',
                '1: 13/65536 files (0.0% non-contiguous), 12957/262144 blocks',
                re.compile('^resize2fs .*$'),
                'Resizing the filesystem on %s to 12982 (4k) blocks.' % checkpoint1_path_parts.GetPath(),
                'The filesystem on %s is now 12982 (4k) blocks long.' % checkpoint1_path_parts.GetPath(),
                re.compile('^e2fsck .*$'),
                'Pass 1: Checking inodes, blocks, and sizes',
                'Pass 2: Checking directory structure',
                'Pass 3: Checking directory connectivity',
                'Pass 4: Checking reference counts',
                'Pass 5: Checking group summary information',
                '1: 13/8192 files (0.0% non-contiguous), 8843/12982 blocks',
                'Image size 1gb -> 50.7mb'])
      AssertEquals(53174272, os.lstat(checkpoint1_path_parts.GetPath()).st_size)
      AssertCheckpointStripState(checkpoint1_path_parts.GetPath(), True)

    if platform.system() == lib.PLATFORM_DARWIN:
      DoStrip(checkpoint2_path, defragment_iterations=2, dry_run=True,
              expected_output=[
                'Checkpoint stripped',
                'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...' % checkpoint2_path,
                re.compile('^Image size 3[45]mb -> 3[45]mb$')])
      checkpoint2_path_parts.SetIsManifestOnly(True)
      DoStrip(checkpoint2_path, defragment_iterations=2,
              expected_output=[
                'Checkpoint stripped',
                'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...' % checkpoint2_path_parts.GetPath(),
                '<... snip APFS operation ...>',
                re.compile('^Iteration 2, new apfs min size 1[.][23]gb[.][.][.]$'),
                '<... snip APFS operation ...>',
                'Starting to compact…',
                'Reclaiming free space…',
                'Finishing compaction…',
                'Reclaimed 13 MB out of 1.2 GB possible.',
                'Restoring apfs container size to 1023.8gb...',
                '<... snip APFS operation ...>',
                'Starting to compact…',
                'Reclaiming free space…',
                'Finishing compaction…',
                re.compile('^Reclaimed [45] MB out of 1023[.]6 GB possible[.]$'),
                re.compile('^Image size 3[45]mb -> 20mb$')])
      AssertEquals(20975616, os.lstat(checkpoint2_path_parts.GetPath()).st_size)
      AssertCheckpointStripState(checkpoint2_path_parts.GetPath(), True)


class StripWithEncryptionTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_NONE, test_case=self) as should_run:
      if should_run:
        with SetHdiutilCompactOnBatteryAllowed(True):
          with TempDir() as test_dir:
            self.RunTest(test_dir)

  def RunTest(self, test_dir):
    def AssertCheckpointStripState(image_path, stripped_expected):
      with HandleGetPass(
          expected_prompts=['Enter password to access "%s": ' % os.path.basename(image_path)],
          returned_passwords=['abc']):
        checkpoint = checkpoint_lib.Checkpoint.Open(image_path, encryption_manager=lib.EncryptionManager(output=None))
        try:
          AssertEquals(True, os.path.exists(checkpoint.GetMetadataPath()))
          AssertEquals(not stripped_expected, os.path.exists(checkpoint.GetContentRootPath()))
        finally:
          checkpoint.Close()

    image_ext = '.sparseimage'
    if platform.system() == lib.PLATFORM_LINUX:
      image_ext = '.luks.img'

    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    file1 = CreateFile(src_root, 'f1', contents='1' * (1024 * 1024 * 20))

    with HandleGetPass(
        expected_prompts=['Enter a new password to secure "1%s": ' % image_ext,
                          'Re-enter new password: ',
                          'Enter password to access "1%s": ' % image_ext],
        returned_passwords=['abc', 'abc', 'abc']):
      checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1', encrypt=True,
        expected_output=['>d+++++++ .',
                         '>f+++++++ f1',
                         'Transferring 2 paths (20mb)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.f....... f1'])
    finally:
      checkpoint1.Close()
    checkpoint1_path_parts = checkpoint_lib.CheckpointPathParts(checkpoint1.GetImagePath())
    AssertCheckpointStripState(checkpoint1.GetImagePath(), False)

    checkpoint2_path = os.path.join(checkpoints_dir, '2.sparseimage')
    checkpoint2_path_parts = checkpoint_lib.CheckpointPathParts(checkpoint2_path)
    shutil.copy(checkpoint1.GetImagePath(), checkpoint2_path)

    if platform.system() == lib.PLATFORM_DARWIN:
      AssertFileSizeInRange(os.lstat(checkpoint1.GetImagePath()).st_size, '34mb', '35.2mb')

      with HandleGetPass(
          expected_prompts=['Enter password to access "1%s": ' % image_ext],
          returned_passwords=['abc']):
        DoStrip(checkpoint1.GetImagePath(), defragment=False, dry_run=True,
                expected_output=['Checkpoint stripped',
                                 re.compile('^Image size 3[45]([.]1)?mb -> 3[45]([.]1)?mb$')])
      with HandleGetPass(
          expected_prompts=['Enter password to access "1%s": ' % image_ext],
          returned_passwords=['abc']):
        DoStrip(checkpoint1.GetImagePath(), defragment=False,
                expected_output=['Checkpoint stripped',
                                 'Starting to compact…',
                                 'Reclaiming free space…',
                                 'Finishing compaction…',
                                 'Reclaimed 4 MB out of 1023.6 GB possible.',
                                 re.compile('^Image size 3[45]([.]1)?mb -> 3[01]([.]1)?mb$')])
      checkpoint1_path_parts.SetIsManifestOnly(True)
      AssertFileSizeInRange(os.lstat(checkpoint1_path_parts.GetPath()).st_size, '30mb', '31.2mb')
      AssertCheckpointStripState(checkpoint1_path_parts.GetPath(), True)
    else:
      AssertEquals(1073741824, os.lstat(checkpoint1.GetImagePath()).st_size)
      with HandleGetPass(
          expected_prompts=['Enter password to access "1%s": ' % image_ext],
          returned_passwords=['abc']):
        DoStrip(checkpoint1.GetImagePath(), defragment=False, dry_run=True,
                expected_output=['Checkpoint stripped',
                                 'Image size 1gb -> 1gb'])
      checkpoint1_path_parts.SetIsManifestOnly(True)
      with HandleGetPass(
          expected_prompts=['Enter password to access "1%s": ' % image_ext],
          returned_passwords=['abc']):
        DoStrip(checkpoint1.GetImagePath(), defragment=False,
                expected_output=[
                  'Checkpoint stripped',
                  re.compile('^e2fsck .*$'),
                  'Pass 1: Checking inodes, blocks, and sizes',
                  'Pass 2: Checking directory structure',
                  'Pass 3: Checking directory connectivity',
                  'Pass 4: Checking reference counts',
                  'Pass 5: Checking group summary information',
                  '1: 13/64512 files (0.0% non-contiguous), 8787/258048 blocks',
                  re.compile('^resize2fs .*$'),
                  re.compile('^Resizing the filesystem on /dev/mapper/[^ ]+ to 8800 [(]4k[)] blocks[.]$'),
                  re.compile('^The filesystem on /dev/mapper/[^ ]+ is now 8800 [(]4k[)] blocks long[.]$'),
                  re.compile('^e2fsck .*$'),
                  'Pass 1: Checking inodes, blocks, and sizes',
                  'Pass 2: Checking directory structure',
                  'Pass 3: Checking directory connectivity',
                  'Pass 4: Checking reference counts',
                  'Pass 5: Checking group summary information',
                  '1: 13/8064 files (0.0% non-contiguous), 4737/8800 blocks',
                  'Image size 1gb -> 50.4mb'])
      AssertEquals(52822016, os.lstat(checkpoint1_path_parts.GetPath()).st_size)
      AssertCheckpointStripState(checkpoint1_path_parts.GetPath(), True)

    if platform.system() == lib.PLATFORM_DARWIN:
      with HandleGetPass(
          expected_prompts=['Enter password to access "2%s": ' % image_ext],
          returned_passwords=['abc']):
        DoStrip(checkpoint2_path, defragment_iterations=2, dry_run=True,
                expected_output=[
                  'Checkpoint stripped',
                  'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...' % checkpoint2_path,
                  re.compile('^Image size 3[45]([.]1)?mb -> 3[45]([.]1)?mb$')])
      checkpoint2_path_parts.SetIsManifestOnly(True)
      with HandleGetPass(
          expected_prompts=['Enter password to access "2%s": ' % image_ext],
          returned_passwords=['abc']):
        DoStrip(checkpoint2_path, defragment_iterations=2,
                expected_output=[
                  'Checkpoint stripped',
                  'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...' % checkpoint2_path_parts.GetPath(),
                  '<... snip APFS operation ...>',
                  re.compile('^Iteration 2, new apfs min size 1[.][23]gb[.][.][.]$'),
                  '<... snip APFS operation ...>',
                  'Starting to compact…',
                  'Reclaiming free space…',
                  'Finishing compaction…',
                  'Reclaimed 13 MB out of 1.2 GB possible.',
                  'Restoring apfs container size to 1023.8gb...',
                  '<... snip APFS operation ...>',
                  'Starting to compact…',
                  'Reclaiming free space…',
                  'Finishing compaction…',
                  re.compile('^Reclaimed [45] MB out of 1023[.]6 GB possible[.]$'),
                  re.compile('^Image size 3[45]([.]1)?mb -> 20([.]1)?mb$')])
      AssertEquals(21097984, os.lstat(checkpoint2_path_parts.GetPath()).st_size)
      AssertCheckpointStripState(checkpoint2_path_parts.GetPath(), True)


class CheckpointPathPartsTestCase(BaseTestCase):
  def test(self):
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('1.sparseimage'))
    AssertEquals(False, checkpoint_lib.CheckpointPathParts.IsMatchingPath('1.sparsebundle'))
    AssertEquals(False, checkpoint_lib.CheckpointPathParts.IsMatchingPath('1.dmg'))
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('1.img'))
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('1.luks.img'))
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('2022-01-01-000000.luks.img'))
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('2022-01-01-000000.sparseimage'))
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('2022-01-01-000000-manifest.luks.img'))
    AssertEquals(True, checkpoint_lib.CheckpointPathParts.IsMatchingPath('2022-01-01-000000-manifest.sparseimage'))

    cpp = checkpoint_lib.CheckpointPathParts('2022-01-01-000000.luks.img')
    AssertEquals('2022-01-01-000000.luks.img', cpp.GetPath())
    AssertEquals(False, cpp.IsManifestOnly())
    AssertEquals('2022-01-01-000000-manifest.luks.img', cpp.SetIsManifestOnly(True).GetPath())

    cpp = checkpoint_lib.CheckpointPathParts('2022-01-01-000000-manifest.luks.img')
    AssertEquals('2022-01-01-000000-manifest.luks.img', cpp.GetPath())
    AssertEquals(True, cpp.IsManifestOnly())
    AssertEquals('2022-01-01-000000.luks.img', cpp.SetIsManifestOnly(False).GetPath())

    cpp = checkpoint_lib.CheckpointPathParts('2022-01-01-000000.sparseimage')
    AssertEquals('2022-01-01-000000.sparseimage', cpp.GetPath())
    AssertEquals(False, cpp.IsManifestOnly())
    AssertEquals('2022-01-01-000000-manifest.sparseimage', cpp.SetIsManifestOnly(True).GetPath())

    cpp = checkpoint_lib.CheckpointPathParts('2022-01-01-000000-manifest.sparseimage')
    AssertEquals('2022-01-01-000000-manifest.sparseimage', cpp.GetPath())
    AssertEquals(True, cpp.IsManifestOnly())
    AssertEquals('2022-01-01-000000.sparseimage', cpp.SetIsManifestOnly(False).GetPath())

    cpp = checkpoint_lib.CheckpointPathParts('2022-01-01-000000.img')
    AssertEquals('2022-01-01-000000.img', cpp.GetPath())
    AssertEquals(False, cpp.IsManifestOnly())
    AssertEquals('2022-01-01-000000-manifest.img', cpp.SetIsManifestOnly(True).GetPath())

    cpp = checkpoint_lib.CheckpointPathParts('2022-01-01-000000-manifest.img')
    AssertEquals('2022-01-01-000000-manifest.img', cpp.GetPath())
    AssertEquals(True, cpp.IsManifestOnly())
    AssertEquals('2022-01-01-000000.img', cpp.SetIsManifestOnly(False).GetPath())


if __name__ == '__main__':
  test_main.RunCurrentFileUnitTests()
