#!/usr/bin/env python3 -u -B

import argparse
import contextlib
import errno
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir))
import backups_lib
__package__ = backups_lib.__package__

from . import lib
from . import backups_main

from .test_util import AssertEquals
from .test_util import AssertLinesEqual
from .test_util import AssertNotEquals
from .test_util import CreateDir
from .test_util import CreateFile
from .test_util import CreateSymlink
from .test_util import DeleteFileOrDir
from .test_util import DoBackupsMain
from .test_util import SetMTime
from .test_util import SetPacificTimezone
from .test_util import SetXattr
from .test_util import TempDir
from .test_util import Xattr

from .lib_test_util import GetManifestItemized
from .lib_test_util import SetHdiutilCompactOnBatteryAllowed
from .lib_test_util import SetOmitUidAndGidInPathInfoToString


def RsyncPaths(from_path, to_path, checksum=True, dry_run=False, filters=lib.STAGED_BACKUP_DEFAULT_FILTERS):
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


def AssertFileSizeInRange(actual_size, min_expected, max_expected):
  if type(actual_size) == str:
    actual_size = lib.FileSizeStringToBytes(actual_size)
  if type(min_expected) == str:
    min_expected = lib.FileSizeStringToBytes(min_expected)
  if type(max_expected) == str:
    max_expected = lib.FileSizeStringToBytes(max_expected)
  if actual_size < min_expected or actual_size > max_expected:
    raise Exception('File size %s outside of range [%s, %s]' % (
      lib.FileSizeToString(actual_size), lib.FileSizeToString(min_expected),
      lib.FileSizeToString(max_expected)))


def GetCheckpointData(checkpoint_path, readonly=True, manifest_only=False):
  checkpoint = lib.Checkpoint.Open(checkpoint_path, readonly=readonly)
  try:
    manifest_path = os.path.join(checkpoint.GetMetadataPath(), lib.MANIFEST_FILENAME)
    if manifest_only:
      assert not os.path.lexists(checkpoint.GetContentRootPath())
    else:
      assert os.path.isdir(checkpoint.GetContentRootPath())
    manifest = lib.Manifest.Load(manifest_path)
    return (checkpoint, manifest)
  except:
    if checkpoint:
      checkpoint.Close()
    raise


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


def CollapseApfsOperationsInOutput(output_lines):
  new_output_lines = []
  in_apfs_operation = False
  for line in output_lines:
    if line == 'Started APFS operation':
      assert not in_apfs_operation
      in_apfs_operation = True
      new_output_lines.append('<... snip APFS operation ...>')
      continue
    elif line == 'Finished APFS operation':
      assert in_apfs_operation
      in_apfs_operation = False
      continue
    elif in_apfs_operation:
      continue
    new_output_lines.append(line)
  assert not in_apfs_operation
  return new_output_lines


def CreateGoogleDriveRemoteFile(parent_dir, filename):
  path = CreateFile(parent_dir, filename, contents='IGNORE')
  xattr_data = Xattr(path)
  xattr_data[lib.GOOGLE_DRIVE_MIME_TYPE_XATTR_KEY] = (
    ('%sdocument' % lib.GOOGLE_DRIVE_REMOTE_FILE_MIME_TYPE_PREFIX).encode('ascii'))
  return path


@contextlib.contextmanager
def HandleGoogleDriveRemoteFiles(paths):
  class ErroringFile:
    def __enter__(self):
      return self
    def __exit__(self, exc_type, exc, exc_traceback):
      pass
    def read(self, size=-1):
      raise OSError(errno.ENOTSUP, 'Operation not supported')
    def close(self):
      pass

  def OpenContentOverride(path, mode='r'):
    if path in paths:
      return ErroringFile()
    return open(path, mode)

  old_value = lib.OPEN_CONTENT_FUNCTION
  lib.OPEN_CONTENT_FUNCTION = OpenContentOverride
  try:
    yield
  finally:
    lib.OPEN_CONTENT_FUNCTION = old_value


def DoCreate(src_root, checkpoints_dir, checkpoint_name, expected_success=True, expected_output=[],
             last_checkpoint_path=None, manifest_only=False, checksum_all=True, filter_merge_path=None,
             dry_run=False, readonly=True):
  args = []
  if dry_run:
    args.append('--dry-run')
  args.extend(['create-checkpoint',
               '--no-encrypt',
               '--src-root', src_root,
               '--checkpoints-dir', checkpoints_dir,
               '--checkpoint-name', checkpoint_name])
  if manifest_only:
    args.append('--manifest-only')
  if last_checkpoint_path is not None:
    args.extend(['--last-checkpoint', last_checkpoint_path])
  if checksum_all:
    args.append('--checksum-all')
  if filter_merge_path:
    args.extend(['--filter-merge-path', filter_merge_path])
  output = io.StringIO()
  AssertEquals(backups_main.Main(args, output), expected_success)
  output_lines = []
  checkpoint_path = None
  for line in output.getvalue().strip().split('\n'):
    m = re.match('^Created checkpoint at (.+[.]sparseimage)$', line)
    if m:
      checkpoint_path = m.group(1)
      continue
    output_lines.append(line)
  output.close()
  AssertLinesEqual(output_lines, expected_output)
  if not dry_run:
    assert checkpoint_path
    checkpoint, manifest = GetCheckpointData(
      checkpoint_path, readonly=readonly, manifest_only=manifest_only)
    try:
      return checkpoint, manifest
    except:
      if checkpoint:
        checkpoint.Close()
      raise


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


def DoDumpManifest(manifest_path, ignore_matching_renames=False,
                   expected_success=True, expected_output=[]):
  cmd_args = ['dump-manifest',  manifest_path]
  with SetOmitUidAndGidInPathInfoToString():
    DoBackupsMain(cmd_args, expected_success=expected_success, expected_output=expected_output)


def DoDiffManifests(manifest1_path, manifest2_path, ignore_matching_renames=False,
                    expected_success=True, expected_output=[]):
  cmd_args = ['diff-manifests',
              manifest1_path,
              manifest2_path]
  if ignore_matching_renames:
    cmd_args.append('--ignore-matching-renames')
  DoBackupsMain(cmd_args, expected_success=expected_success, expected_output=expected_output)


def DoVerify(manifest_path, src_root, expected_success=True, expected_output=[]):
  args = []
  args.extend(['verify-manifest',
               '--checksum-all',
               '--src-root', src_root,
               manifest_path])
  output = io.StringIO()
  AssertEquals(backups_main.Main(args, output), expected_success)
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


def DoCompact(checkpoint_path, defragment=True, defragment_iterations=None,
              dry_run=False, expected_output=[]):
  cmd_args = ['compact-image',
              '--image-path', checkpoint_path]
  if not defragment:
    cmd_args.append('--no-defragment')
  if defragment_iterations is not None:
    cmd_args.extend(['--defragment-iterations', str(defragment_iterations)])
  output_lines = DoBackupsMain(cmd_args, dry_run=dry_run, expected_output=None)
  output_lines = CollapseApfsOperationsInOutput(output_lines)
  AssertLinesEqual(output_lines, expected_output)


def PathInfoTest():
  with TempDir() as test_dir:
    try:
      lib.PathInfo.FromPath('DOES_NOT_EXIST', os.path.join(test_dir, 'DOES_NOT_EXIST'))
      raise Exception('Expected OSError')
    except OSError:
      pass

    file1 = CreateFile(test_dir, 'file1')
    dir1 = CreateDir(test_dir, 'dir1')
    ln1 = CreateSymlink(test_dir, 'ln1', 'INVALID')
    file1_path_info = lib.PathInfo.FromPath(os.path.basename(file1), file1)
    dir1_path_info = lib.PathInfo.FromPath(os.path.basename(dir1), dir1)
    ln1_path_info = lib.PathInfo.FromPath(os.path.basename(ln1), ln1)

    gdrf1 = CreateGoogleDriveRemoteFile(test_dir, 'gdrf1')
    with HandleGoogleDriveRemoteFiles([gdrf1]):
      gdrf1_path_info = lib.PathInfo.FromPath(os.path.basename(gdrf1), gdrf1)

    AssertEquals('.f....... file1', str(file1_path_info.GetItemized()))
    AssertEquals('.d....... dir1', str(dir1_path_info.GetItemized()))
    AssertEquals('.L....... ln1 -> INVALID', str(ln1_path_info.GetItemized()))
    AssertEquals('.f....... gdrf1', str(gdrf1_path_info.GetItemized()))

    AssertEquals('.f....... file1', str(lib.PathInfo.GetItemizedDiff(file1_path_info, file1_path_info)))
    AssertEquals('>fcs.p... file1', str(lib.PathInfo.GetItemizedDiff(file1_path_info, dir1_path_info, ignore_paths=True)))
    AssertEquals('>fcs.p... file1', str(lib.PathInfo.GetItemizedDiff(file1_path_info, ln1_path_info, ignore_paths=True)))

    AssertEquals('>dcs.p... dir1', str(lib.PathInfo.GetItemizedDiff(dir1_path_info, file1_path_info, ignore_paths=True)))
    AssertEquals('.d....... dir1', str(lib.PathInfo.GetItemizedDiff(dir1_path_info, dir1_path_info)))
    AssertEquals('>dc...... dir1', str(lib.PathInfo.GetItemizedDiff(dir1_path_info, ln1_path_info, ignore_paths=True)))

    AssertEquals('>Lcs.p... ln1 -> INVALID', str(lib.PathInfo.GetItemizedDiff(ln1_path_info, file1_path_info, ignore_paths=True)))
    AssertEquals('>Lc...... ln1 -> INVALID', str(lib.PathInfo.GetItemizedDiff(ln1_path_info, dir1_path_info, ignore_paths=True)))
    AssertEquals('.L....... ln1 -> INVALID', str(lib.PathInfo.GetItemizedDiff(ln1_path_info, ln1_path_info)))

    AssertEquals('.f.s....x gdrf1', str(lib.PathInfo.GetItemizedDiff(gdrf1_path_info, file1_path_info, ignore_paths=True)))
    AssertEquals('>fcs.p..x gdrf1', str(lib.PathInfo.GetItemizedDiff(gdrf1_path_info, dir1_path_info, ignore_paths=True)))
    AssertEquals('>fcs.p..x gdrf1', str(lib.PathInfo.GetItemizedDiff(gdrf1_path_info, ln1_path_info, ignore_paths=True)))
    AssertEquals('.f....... gdrf1', str(lib.PathInfo.GetItemizedDiff(gdrf1_path_info, gdrf1_path_info)))

    AssertEquals(False, file1_path_info.google_drive_remote_file)
    AssertEquals(False, dir1_path_info.google_drive_remote_file)
    AssertEquals(False, ln1_path_info.google_drive_remote_file)
    AssertEquals(True, gdrf1_path_info.google_drive_remote_file)

    AssertEquals(True, file1_path_info.HasFileContents())
    AssertEquals(False, dir1_path_info.HasFileContents())
    AssertEquals(False, ln1_path_info.HasFileContents())
    AssertEquals(True, gdrf1_path_info.HasFileContents())
    AssertEquals(64, gdrf1_path_info.size)

  class PathInfoLike:
    def __init__(self, path):
      self.path = path

  def RunTest(path, paths, expected_paths):
    path_infos = [ PathInfoLike(p) for p in paths ]
    sorted_path_infos = lib.PathInfo.SortedByPathSimilarity(path, path_infos)
    sorted_paths = [ p.path for p in sorted_path_infos ]

    AssertEquals(expected_paths, sorted_paths)

  RunTest('/tmp/thepath',
          paths=[
            '/tmp/to/something',
            '/tmp/from/something',
            '/tmp/other/thepath',
            '/tmp/other_longer/thepath'],
          expected_paths=[
            '/tmp/other/thepath',
            '/tmp/other_longer/thepath',
            '/tmp/to/something',
            '/tmp/from/something'])

  RunTest('/tmp/a',
          paths=[
            '/tmp/d',
            '/tmp/c',
            '/tmp/b'],
          expected_paths=[
            '/tmp/b',
            '/tmp/c',
            '/tmp/d'])


def ItemizedPathChangeTest():
  AssertEquals(
    '.f....... path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE)))
  AssertEquals(
    '>d....... path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, replace_path=True)))
  AssertEquals(
    '*deleting path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, delete_path=True)))
  AssertEquals(
    '>fc...... path',
    str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, replace_path=True, checksum_diff=True)))
  AssertEquals(
    '.f.s..... path -> dest',
    str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, size_diff=True, link_dest='dest')))
  AssertEquals(
    '.L..t.... path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_SYMLINK, time_diff=True)))
  AssertEquals(
    '.f...p... path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, permission_diff=True)))
  AssertEquals(
    '.d....o.. path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, uid_diff=True)))
  AssertEquals(
    '.d.....g. path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, gid_diff=True)))
  AssertEquals(
    '.d......x path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, xattr_diff=True)))


def CreateDryRunTest():
  with TempDir() as test_dir:
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
    AssertLinesEqual(os.listdir(checkpoints_dir), ['1.sparseimage'])

    SetMTime(file1, None)
    file2 = CreateFile(parent1, 'f2', contents='abc')

    DoCreate(
      src_root, checkpoints_dir, '2', dry_run=True,
      last_checkpoint_path=checkpoint1.GetImagePath(),
    expected_output=['>fcs..... par!/f2',
                     '.f..t.... par!/f_\\r',
                     'Transferring 2 of 5 paths (17b of 17b)'])
    AssertLinesEqual(os.listdir(checkpoints_dir), ['1.sparseimage'])


def CreateTest():
  with TempDir() as test_dir:
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')
    file1 = CreateFile(parent1, 'f_\r')
    file2 = CreateFile(parent1, 'f2')
    file3 = CreateFile(parent1, 'f3')

    file_skip1 = CreateFile(src_root, 'SKIP1')
    file_skip1 = CreateFile(parent1, '2.skp')
    CreateFile(src_root, lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
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
                       'Transferring 6 paths (29b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest_only),
                       ['.d....... .',
                        '.f....... .staged_backup_filter',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f3',
                        '.f....... par!/f_\\r'])
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
                       'Transferring 6 paths (29b)'])
    try:
      VerifyCheckpointContents(manifest1, checkpoint1.GetContentRootPath())
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.f....... .staged_backup_filter',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/f3',
                        '.f....... par!/f_\\r'])
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
      AssertLinesEqual(RsyncPaths(src_root, checkpoint2.GetContentRootPath()),
                       ['.d..t....... ./',
                        '>f++++++++++ .staged_backup_filter',
                        'cd++++++++++ par!/',
                        '>f++++++++++ par!/f2',
                        '>f++++++++++ par!/f3',
                        '>f++++++++++ par!/f_\r'])
      AssertBasisInfoFileEquals(checkpoint2.GetMetadataPath(), checkpoint1.GetImagePath())
      DoVerify(manifest2.GetPath(), src_root,
               expected_success=False,
               expected_output=['*deleting SKIP1',
                                '*deleting par!/2.skp'])
      DoVerify(manifest2.GetPath(), checkpoint2.GetContentRootPath())
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
                       'Transferring 3 of 6 paths (3b of 32b)'],
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
      DoVerify(manifest3.GetPath(), checkpoint3.GetContentRootPath(),
               expected_success=False,
               expected_output=['>f+++++++ .staged_backup_filter',
                                '>f+++++++ par!/f3'])
      checkpoint2 = lib.Checkpoint.Open(checkpoint2.GetImagePath(), readonly=False)
      try:
        AssertLinesEqual(RsyncPaths(src_root, checkpoint2.GetContentRootPath()),
                         ['.d........x. ./',
                          '>fcs........ par!/f2',
                          '.f..t....... par!/f_\r'])
      finally:
        checkpoint2.Close()
      AssertLinesEqual(RsyncPaths(src_root, checkpoint3.GetContentRootPath()),
                       ['>f++++++++++ .staged_backup_filter',
                        '>f++++++++++ par!/f3'])
    finally:
      checkpoint3.Close()

    file2 = CreateFile(parent1, 'f2', contents='def')
    SetMTime(parent1, 1510000000)
    parent2 = CreateDir(src_root, 'par2')
    file2b = CreateFile(parent2, 'f2b', contents='def')

    def PreSyncContentsTestHook(checkpoint_creator):
      CreateFile(parent1, 'f2', contents='ghi')
      SetXattr(parent1, 'example', b'example_value_5')
      SetMTime(parent1, 1520000000)
      CreateFile(parent2, 'f2b', contents='jkl')
      SetMTime(parent2, 1520000000)

    lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = PreSyncContentsTestHook
    try:
      checkpoint4, manifest4 = DoCreate(
        src_root, checkpoints_dir, '4',
        last_checkpoint_path=checkpoint3.GetImagePath(),
        readonly=False,
        expected_output=['.d..t.... par!',
                         '>fc...... par!/f2',
                         '>d+++++++ par2',
                         '>f+++++++ par2/f2b',
                         '*** Warning: Paths changed since syncing, checking...',
                         '.d..t...x par!',
                         '>fc...... par!/f2',
                         '>d+++++++ par2',
                         '>f+++++++ par2/f2b',
                         'Transferring 8 of 12 paths (12b of 41b)'])
      try:
        VerifyCheckpointContents(manifest4, checkpoint4.GetContentRootPath(), prev_manifest=manifest3)
        AssertLinesEqual(GetManifestDiffItemized(manifest3, manifest4),
                         ['.d..t...x par!',
                          '>fc...... par!/f2',
                          '>d+++++++ par2',
                          '>f+++++++ par2/f2b'])
        AssertLinesEqual(RsyncPaths(src_root, checkpoint4.GetContentRootPath()),
                         ['.d..t.....x. ./',
                          '>f++++++++++ .staged_backup_filter',
                          '>f++++++++++ par!/f3',
                          '>f++++++++++ par!/f_\r'])
        AssertBasisInfoFileEquals(checkpoint4.GetMetadataPath(), checkpoint3.GetImagePath())
        DoVerify(manifest4.GetPath(), checkpoint4.GetContentRootPath())
      finally:
        checkpoint4.Close()
    finally:
      lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = None

    file4 = CreateFile(parent1, 'f4')
    SetMTime(parent1, 1510000000)

    def PreSyncContentsTestHook(checkpoint_creator):
      file4_stat = os.lstat(os.path.join(parent1, 'f4'))
      if file4_stat.st_mtime == 1500000000:
        CreateFile(parent1, 'f4', mtime=1520000000)
      elif file4_stat.st_mtime == 1520000000:
        CreateFile(parent1, 'f4', mtime=1530000000)
        SetMTime(parent1, 1530000000)

    lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = PreSyncContentsTestHook
    try:
      checkpoint5, manifest5 = DoCreate(
        src_root, checkpoints_dir, '5',
        last_checkpoint_path=checkpoint4.GetImagePath(),
        readonly=False,
        expected_output=['.d..t.... par!',
                         '>f+++++++ par!/f4',
                         '*** Warning: Paths changed since syncing, checking...',
                         '>f+++++++ par!/f4',
                         '*** Warning: Paths changed since syncing, checking...',
                         '.d..t.... par!',
                         '>f+++++++ par!/f4',
                         'Transferring 5 of 12 paths (0b of 35b)'])
      try:
        VerifyCheckpointContents(manifest5, checkpoint5.GetContentRootPath(), prev_manifest=manifest4)
        AssertLinesEqual(GetManifestDiffItemized(manifest4, manifest5),
                         ['.d..t.... par!',
                          '>f+++++++ par!/f4'])
        AssertLinesEqual(RsyncPaths(src_root, checkpoint5.GetContentRootPath()),
                         ['.d..t.....x. ./',
                          '>f++++++++++ .staged_backup_filter',
                          '>f++++++++++ par!/f2',
                          '>f++++++++++ par!/f3',
                          '>f++++++++++ par!/f_\r',
                          'cd++++++++++ par2/',
                          '>f++++++++++ par2/f2b'])
        AssertBasisInfoFileEquals(checkpoint5.GetMetadataPath(), checkpoint4.GetImagePath())
        DoVerify(manifest5.GetPath(), checkpoint5.GetContentRootPath())
      finally:
        checkpoint5.Close()
    finally:
      lib.CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK = None

    file5 = CreateFile(src_root, 'f5')
    SetMTime(src_root, 1510000000)


def CreateWithFilterMergeTest():
  with TempDir() as test_dir:
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
    CreateFile(parent1, lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
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


def CreateFromGoogleDriveTest():
  with TempDir() as test_dir:
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par')

    file1 = CreateGoogleDriveRemoteFile(parent1, 'f1')
    Xattr(file1)['user.drive.id'] = 'gdrive_id1'.encode('utf8')

    file2 = CreateFile(parent1, 'f2', contents='abc')
    Xattr(file2)[lib.GOOGLE_DRIVE_MIME_TYPE_XATTR_KEY] = 'text/plain'.encode('utf8')

    with HandleGoogleDriveRemoteFiles([file1]):
     checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1',
        expected_output=['>d+++++++ .',
                         '>d+++++++ par',
                         '>f+++++++ par/f1',
                         '>f+++++++ par/f2',
                         'Transferring 4 paths (98b)'])

    try:
      AssertLinesEqual(GetManifestItemized(manifest1),
                       ['.d....... .',
                        '.d....... par',
                        '.f....... par/f1',
                        '.f....... par/f2'])
      f1_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'par/f1')
      AssertEquals('{"user.drive.id": "gdrive_id1", "user.drive.mime_type": "application/vnd.google-apps.document"}',
                   open(f1_checkpoint, 'r').read())
      AssertEquals(['user.drive.id', 'user.drive.mime_type'], Xattr(f1_checkpoint).keys())
      AssertEquals(b'application/vnd.google-apps.document', Xattr(f1_checkpoint)['user.drive.mime_type'])
      AssertEquals(b'gdrive_id1', Xattr(f1_checkpoint)['user.drive.id'])
      f2_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'par/f2')
      AssertEquals('abc', open(f2_checkpoint, 'r').read())
    finally:
      checkpoint1.Close()


def CreateWithFollowSymlinksTest():
  with TempDir() as test_dir2:
    with TempDir() as test_dir:
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

      CreateFile(src_root, lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
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
        AssertEquals('abc', open(f2_checkpoint, 'r').read())
        ln2_ln4_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'ln2/ln4')
        AssertEquals('abc', open(ln2_ln4_checkpoint, 'r').read())
        ln6_f2_checkpoint = os.path.join(checkpoint1.GetContentRootPath(), 'ln2/ln6/f2')
        AssertEquals('abc', open(ln6_f2_checkpoint, 'r').read())
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
        AssertEquals(b'example_value', Xattr(ln2_checkpoint)['example'])
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
        AssertEquals('ghi', open(ref_file3_checkpoint, 'r').read())
        ln2_checkpoint = os.path.join(checkpoint3.GetContentRootPath(), 'ln2')
        AssertEquals(b'example_value', Xattr(ln2_checkpoint)['example'])
      finally:
        checkpoint3.Close()


def ApplyDryRunTest():
  with TempDir() as test_dir:
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
            expected_output=['*deleting del_par!',
                             '*deleting del_par!/del',
                             '>d+++++++ par!',
                             '>f+++++++ par!/f_\\r'])
    AssertLinesEqual(RsyncPaths(src_root, dest_root),
                     ['*deleting del_par!/',
                      '*deleting del_par!/del',
                      'cd++++++++++ par!/',
                      '>f++++++++++ par!/f_\r'])


def ApplyTest():
  with TempDir() as test_dir:
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
            expected_output=['*deleting del_par!',
                             '*deleting del_par!/del',
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
      AssertEquals(sorted(Xattr(os.path.join(checkpoint2.GetContentRootPath(), 'f3')).keys()),
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
    AssertLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
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
    AssertLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
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
                       '*deleting ln3',
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
      AssertEquals(sorted(Xattr(os.path.join(checkpoint5.GetContentRootPath(), 'f3')).keys()),
                   ['com.apple.lastuseddate#PS', 'example'])
    finally:
      checkpoint5.Close()

    DoApply(checkpoint5.GetImagePath(), dest_root,
            expected_output=['.f......x f3',
                             '.Lc...... ln1_dir -> par!/f2',
                             '*deleting ln3',
                             '>fcs..... par!/f2',
                             '.Lc...... par!/ln2 -> INVALID'])
    AssertEmptyRsync(src_root, dest_root)

    # Modify an existing file's contents, leaving size and time the same
    file2 = CreateFile(parent1, 'f2', contents='def')

    checkpoint6, manifest6 = DoCreate(
      src_root, checkpoints_dir, '6', last_checkpoint_path=checkpoint5.GetImagePath(),
      checksum_all=False)
    try:
      DoVerify(manifest6.GetPath(), src_root,
               expected_success=False,
               expected_output=['>fc...... par!/f2'])
      DoVerify(manifest6.GetPath(), dest_root)
    finally:
      checkpoint6.Close()

    DoApply(checkpoint6.GetImagePath(), dest_root)
    AssertEmptyRsync(src_root, dest_root, checksum=False)
    AssertLinesEqual(RsyncPaths(src_root, dest_root, checksum=True, dry_run=True),
                     ['>fc......... par!/f2'])

    # Now do a sync with checksum all and verify the diffing file gets transferred

    checkpoint7, manifest7 = DoCreate(
      src_root, checkpoints_dir, '7', last_checkpoint_path=checkpoint6.GetImagePath(),
      expected_output=['>fc...... par!/f2',
                       'Transferring 1 of 7 paths (3b of 3b)'])
    try:
      DoVerify(manifest7.GetPath(), src_root)
      DoVerify(manifest7.GetPath(), dest_root,
               expected_success=False,
               expected_output=['>fc...... par!/f2'] )
    finally:
      checkpoint7.Close()

    DoApply(checkpoint7.GetImagePath(), dest_root,
            expected_output=['>fc...... par!/f2'])
    AssertEmptyRsync(src_root, dest_root)

    DoVerify(checkpoint7.GetImagePath(), dest_root)


def ApplyFromGoogleDriveTest():
  with TempDir() as test_dir:
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    parent1 = CreateDir(src_root, 'par!')

    dest_root = CreateDir(test_dir, 'dest')

    gdrf1 = CreateGoogleDriveRemoteFile(parent1, 'g1')
    Xattr(gdrf1)['user.drive.id'] = 'gdrive_id1'.encode('utf8')

    file2 = CreateFile(parent1, 'f2', contents='abc')
    Xattr(file2)[lib.GOOGLE_DRIVE_MIME_TYPE_XATTR_KEY] = 'text/plain'.encode('utf8')

    with HandleGoogleDriveRemoteFiles([gdrf1]):
      checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1',
        expected_output=['>d+++++++ .',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f2',
                         '>f+++++++ par!/g1',
                         'Transferring 4 paths (98b)'])
    try:
      DoDumpManifest(
        checkpoint1.GetManifestPath(),
        expected_output=[
          'dir path=., mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          'dir path=par!, mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          ("file path=par!/f2, mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=3, sha256='ba7816', " +
           "xattr-hash='c5e4da', xattr-keys=['user.drive.mime_type']"),
          ("file path=par!/g1, mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=95, sha256='3c4d7b', " +
           "xattr-hash='794b59', xattr-keys=['user.drive.id', 'user.drive.mime_type'], google_drive_remote_file")
        ])
    finally:
      checkpoint1.Close()

    DoApply(checkpoint1.GetImagePath(), dest_root,
            expected_output=['>d+++++++ par!',
                             '>f+++++++ par!/f2',
                             '>f+++++++ par!/g1'])
    DoVerify(checkpoint1.GetImagePath(), dest_root)
    AssertLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
                     ['>fcs........ par!/g1'])

    gdrf2 = CreateGoogleDriveRemoteFile(parent1, 'g2')
    Xattr(gdrf2)['user.drive.id'] = 'gdrive_id2'.encode('utf8')

    with HandleGoogleDriveRemoteFiles([gdrf1, gdrf2]):
      checkpoint2, manifest2 = DoCreate(
        src_root, checkpoints_dir, '2', last_checkpoint_path=checkpoint1.GetImagePath(),
        expected_output=['>f+++++++ par!/g2',
                         'Transferring 1 of 5 paths (95b of 193b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest2),
                       ['.d....... .',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/g1',
                        '.f....... par!/g2'])
    finally:
      checkpoint2.Close()

    DoApply(checkpoint2.GetImagePath(), dest_root,
            expected_output=['>f+++++++ par!/g2'])
    DoVerify(checkpoint2.GetImagePath(), dest_root)
    AssertLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
                     ['>fcs........ par!/g1',
                      '>fcs........ par!/g2'])

    SetMTime(gdrf1, 1510000000)
    SetMTime(file2, 1510000000)

    with HandleGoogleDriveRemoteFiles([gdrf1, gdrf2]):
      checkpoint3, manifest3 = DoCreate(
        src_root, checkpoints_dir, '3', last_checkpoint_path=checkpoint2.GetImagePath(),
        expected_output=['.f..t.... par!/f2',
                         '.f..t.... par!/g1',
                         'Transferring 2 of 5 paths (98b of 193b)'])
    try:
      AssertLinesEqual(GetManifestItemized(manifest3),
                       ['.d....... .',
                        '.d....... par!',
                        '.f....... par!/f2',
                        '.f....... par!/g1',
                        '.f....... par!/g2'])
    finally:
      checkpoint3.Close()

    DoApply(checkpoint3.GetImagePath(), dest_root,
            expected_output=['.f..t.... par!/f2',
                             '.f..t.... par!/g1'])
    DoVerify(checkpoint3.GetImagePath(), dest_root)
    AssertLinesEqual(RsyncPaths(src_root, dest_root, dry_run=True),
                     ['>fcs........ par!/g1',
                      '>fcs........ par!/g2'])


def StripTest():
  def AssertCheckpointStripState(image_path, stripped_expected):
    checkpoint = lib.Checkpoint.Open(image_path)
    try:
      AssertEquals(True, os.path.exists(checkpoint.GetMetadataPath()))
      AssertEquals(not stripped_expected, os.path.exists(checkpoint.GetContentRootPath()))
    finally:
      checkpoint.Close()

  with SetHdiutilCompactOnBatteryAllowed(True):
    with TempDir() as test_dir:
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
      checkpoint1_path_parts = lib.CheckpointPathParts(checkpoint1.GetImagePath())
      AssertCheckpointStripState(checkpoint1.GetImagePath(), False)

      checkpoint2_path = os.path.join(checkpoints_dir, '2.sparseimage')
      checkpoint2_path_parts = lib.CheckpointPathParts(checkpoint2_path)
      shutil.copy(checkpoint1.GetImagePath(), checkpoint2_path)

      AssertEquals(35655680, os.lstat(checkpoint1.GetImagePath()).st_size)
      DoStrip(checkpoint1.GetImagePath(), defragment=False, dry_run=True,
              expected_output=['Checkpoint stripped',
                               'Image size 34mb -> 34mb'])
      DoStrip(checkpoint1.GetImagePath(), defragment=False,
              expected_output=['Checkpoint stripped',
                               'Starting to compact…',
                               'Reclaiming free space…',
                               'Finishing compaction…',
                               'Reclaimed 4 MB out of 1023.6 GB possible.',
                               'Image size 34mb -> 30mb'])
      checkpoint1_path_parts.SetIsManifestOnly(True)
      AssertEquals(31461376, os.lstat(checkpoint1_path_parts.GetPath()).st_size)
      AssertCheckpointStripState(checkpoint1_path_parts.GetPath(), True)

      DoStrip(checkpoint2_path, defragment_iterations=2, dry_run=True,
              expected_output=[
                'Checkpoint stripped',
                'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...' % checkpoint2_path,
                'Image size 34mb -> 34mb'])
      checkpoint2_path_parts.SetIsManifestOnly(True)
      DoStrip(checkpoint2_path, defragment_iterations=2,
              expected_output=[
                'Checkpoint stripped',
                'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...' % checkpoint2_path_parts.GetPath(),
                '<... snip APFS operation ...>',
                'Iteration 2, new apfs min size 1.2gb...',
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
                'Reclaimed 4 MB out of 1023.6 GB possible.',
                'Image size 34mb -> 20mb'])
      AssertEquals(20975616, os.lstat(checkpoint2_path_parts.GetPath()).st_size)
      AssertCheckpointStripState(checkpoint2_path_parts.GetPath(), True)


def CompactTest():
  with SetHdiutilCompactOnBatteryAllowed(True):
    with TempDir() as test_dir:
      checkpoints_dir = CreateDir(test_dir, 'checkpoints')
      src_root = CreateDir(test_dir, 'src')
      file1 = CreateFile(src_root, 'f1', contents='1' * (1024 * 1024 * 20))

      checkpoint1, manifest1 = DoCreate(
        src_root, checkpoints_dir, '1',
        expected_output=['>d+++++++ .', '>f+++++++ f1', 'Transferring 2 paths (20mb)'])
      checkpoint1.Close()

      checkpoint1 = lib.Checkpoint.Open(checkpoint1.GetImagePath(), readonly=False)
      try:
        shutil.rmtree(checkpoint1.GetContentRootPath())
      finally:
        checkpoint1.Close()

      AssertEquals(35655680, lib.GetPathTreeSize(checkpoint1.GetImagePath()))

      DoCompact(checkpoint1.GetImagePath(), defragment=False, dry_run=True,
                expected_output=['Image size 34mb -> 34mb'])
      DoCompact(checkpoint1.GetImagePath(), defragment=False,
                expected_output=['Starting to compact…',
                                 'Reclaiming free space…',
                                 'Finishing compaction…',
                                 'Reclaimed 4 MB out of 1023.6 GB possible.',
                                 'Image size 34mb -> 30mb'])
      AssertEquals(31461376, lib.GetPathTreeSize(checkpoint1.GetImagePath()))

      DoCompact(checkpoint1.GetImagePath(), dry_run=True,
                expected_output=[
                  'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...'
                  % checkpoint1.GetImagePath(),
                  'Image size 30mb -> 30mb'])
      DoCompact(checkpoint1.GetImagePath(),
                defragment_iterations=1,
                expected_output=[
                  'Defragmenting %s; apfs min size 1.7gb, current size 1023.8gb...'
                  % checkpoint1.GetImagePath(),
                  '<... snip APFS operation ...>',
                  'Starting to compact…',
                  'Reclaiming free space…',
                  'Finishing compaction…',
                  'Reclaimed 12 MB out of 1.5 GB possible.',
                  'Restoring apfs container size to 1023.8gb...',
                  '<... snip APFS operation ...>',
                  'Starting to compact…',
                  'Reclaiming free space…',
                  'Finishing compaction…',
                  'Reclaimed 0 bytes out of 1023.6 GB possible.',
                  'Image size 30mb -> 20mb'])
      AssertEquals(20975616, lib.GetPathTreeSize(checkpoint1.GetImagePath()))

      image_path2 = os.path.join(test_dir, 'image2.sparsebundle')
      lib.CreateDiskImage(image_path2, volume_name='2')
      AssertEquals('29.4mb', lib.FileSizeToString(lib.GetPathTreeSize(image_path2)))

      with lib.ImageAttacher(image_path2, readonly=False, browseable=False) as attacher:
        file2 = CreateFile(attacher.GetMountPoint(), 'f2', contents='1' * (1024 * 1024 * 200))
      with lib.ImageAttacher(image_path2, readonly=False, browseable=False) as attacher:
        DeleteFileOrDir(os.path.join(attacher.GetMountPoint(), 'f2'))
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path2), '229.4mb', '229.6mb')

      DoCompact(image_path2, defragment=False,
                expected_output=['Starting to compact…',
                                 'Reclaiming free space…',
                                 'Finishing compaction…',
                                 'Reclaimed 4.0 MB out of 1023.4 GB possible.',
                                 re.compile('^Image size 229[.]5mb -> 225[.]5mb$')])
      AssertEquals('225.5mb', lib.FileSizeToString(lib.GetPathTreeSize(image_path2)))

      DoCompact(image_path2, defragment_iterations=5, dry_run=True,
                expected_output=[
                  'Defragmenting %s; apfs min size 1.9gb, current size 1023.8gb...' % image_path2,
                  'Image size 225.5mb -> 225.5mb'])
      DoCompact(image_path2, defragment_iterations=5,
                expected_output=[
                  'Defragmenting %s; apfs min size 1.9gb, current size 1023.8gb...' % image_path2,
                  '<... snip APFS operation ...>',
                  'Iteration 2, new apfs min size 1.2gb...',
                  '<... snip APFS operation ...>',
                  'Iteration 3, new apfs min size 1gb...',
                  '<... snip APFS operation ...>',
                  'Iteration 4, new apfs min size 1gb has low savings',
                  'Starting to compact…',
                  'Reclaiming free space…',
                  'Finishing compaction…',
                  'Reclaimed 205.9 MB out of 1.0 GB possible.',
                  'Restoring apfs container size to 1023.8gb...',
                  '<... snip APFS operation ...>',
                  'Starting to compact…',
                  'Reclaiming free space…',
                  'Finishing compaction…',
                  'Reclaimed 0 bytes out of 1023.6 GB possible.',
                  re.compile('^Image size 225[.]5mb -> 42[.][67]mb$')])
      AssertFileSizeInRange(lib.GetPathTreeSize(image_path2), '42.6mb', '42.7mb')


def DiffManifestsTest():
  with TempDir() as test_dir:
    manifest1 = lib.Manifest(os.path.join(test_dir, 'manifest1.pbdata'))
    manifest1.Write()
    manifest2 = lib.Manifest(os.path.join(test_dir, 'manifest2.pbdata'))
    manifest2.Write()
    DoDiffManifests(manifest1.path, manifest2.path)

    file1 = CreateFile(test_dir, 'file1', contents='1' * 1025)
    dir1 = CreateDir(test_dir, 'dir1')
    ln1 = CreateSymlink(test_dir, 'ln1', 'INVALID')
    file1_path_info = lib.PathInfo.FromPath(os.path.basename(file1), file1)
    file1_path_info.sha256 = lib.Sha256(file1)
    dir1_path_info = lib.PathInfo.FromPath(os.path.basename(dir1), dir1)
    ln1_path_info = lib.PathInfo.FromPath(os.path.basename(ln1), ln1)

    manifest1.AddPathInfo(file1_path_info)
    manifest1.AddPathInfo(dir1_path_info)
    manifest1.Write()
    manifest2.AddPathInfo(dir1_path_info)
    manifest2.AddPathInfo(ln1_path_info)
    manifest2.Write()
    DoDiffManifests(manifest1.path, manifest2.path,
                    expected_output=['*deleting file1',
                                     '>L+++++++ ln1 -> INVALID'])
    DoDiffManifests(manifest1.path, manifest2.path,
                    ignore_matching_renames=True,
                    expected_output=['*deleting file1',
                                     '>L+++++++ ln1 -> INVALID'])
    DoDiffManifests(manifest2.path, manifest1.path,
                    expected_output=['>f+++++++ file1',
                                     '*deleting ln1'])
    DoDiffManifests(manifest2.path, manifest1.path,
                    ignore_matching_renames=True,
                    expected_output=['>f+++++++ file1',
                                     '*deleting ln1'])

    file2 = CreateFile(test_dir, 'file2', contents='1' * 1025)
    file2_path_info = lib.PathInfo.FromPath(os.path.basename(file2), file2)
    file2_path_info.sha256 = lib.Sha256(file2)

    manifest2.AddPathInfo(file2_path_info)
    manifest2.Write()
    DoDiffManifests(manifest1.path, manifest2.path,
                    expected_output=['*deleting file1',
                                     '  replaced by duplicate: .f....... file2',
                                     '>f+++++++ file2',
                                     '  replacing duplicate: .f....... file1',
                                     '>L+++++++ ln1 -> INVALID'])
    DoDiffManifests(manifest1.path, manifest2.path,
                    ignore_matching_renames=True,
                    expected_output=['>L+++++++ ln1 -> INVALID'])


def FileSizeToStringTest():
  AssertEquals(lib.FileSizeToString(10), '10b')
  AssertEquals(lib.FileSizeToString(1024 * 50), '50kb')
  AssertEquals(lib.FileSizeToString(1024 * 1024 * 1.45), '1.4mb')
  AssertEquals(lib.FileSizeToString(int(1024 * 1024 * 1.45)), '1.4mb')
  AssertEquals(lib.FileSizeToString(1024 * 1024 * 1024 * 999), '999gb')
  AssertEquals(lib.FileSizeToString(-10), '-10b')
  AssertEquals(lib.FileSizeToString(-1024 * 50), '-50kb')
  AssertEquals(lib.FileSizeToString(-1024 * 1024 * 1.45), '-1.4mb')
  AssertEquals(lib.FileSizeToString(int(-1024 * 1024 * 1.45)), '-1.4mb')
  AssertEquals(lib.FileSizeToString(-1024 * 1024 * 1024 * 999), '-999gb')

  AssertEquals(lib.FileSizeStringToBytes('10b'), 10)
  AssertEquals(lib.FileSizeStringToBytes('50kb'), 1024 * 50)
  AssertEquals(lib.FileSizeStringToBytes('1.4mb'), 1468006)
  AssertEquals(lib.FileSizeStringToBytes('999gb'), 1024 * 1024 * 1024 * 999)
  AssertEquals(lib.FileSizeStringToBytes('-10b'), -10)
  AssertEquals(lib.FileSizeStringToBytes('-50kb'), -1024 * 50)
  AssertEquals(lib.FileSizeStringToBytes('-1.4mb'), -1468006)
  AssertEquals(lib.FileSizeStringToBytes('-999gb'), -1024 * 1024 * 1024 * 999)


def EscapeKeyDetectorTest():
  escape_detector = lib.EscapeKeyDetector()
  try:
    AssertEquals(False, escape_detector.WasEscapePressed())
    time.sleep(.1)
    AssertEquals(False, escape_detector.WasEscapePressed())
  finally:
    escape_detector.Shutdown()
  AssertEquals(False, escape_detector.WasEscapePressed())


def MtimePreserverTest():
  with TempDir() as test_dir:
    dir1 = CreateDir(test_dir, 'dir1')
    dir2 = CreateDir(dir1, 'dir2')
    with lib.MtimePreserver() as preserver:
      file1 = os.path.join(dir1, 'file1')
      file2 = CreateFile(dir1, 'file2')
      preserver.PreserveParentMtime(file1)
      AssertEquals(1500000000.0, os.lstat(dir1).st_mtime)
      subprocess.check_call(['touch', file1])
      AssertNotEquals(1500000000.0, os.lstat(dir1).st_mtime)
      AssertEquals({dir1: 1500000000.0}, preserver.preserved_path_mtimes)
      preserver.PreserveParentMtime(file1)
      AssertEquals({dir1: 1500000000.0}, preserver.preserved_path_mtimes)
      preserver.PreserveMtime(file2)
      AssertEquals({dir1: 1500000000.0, file2: 1500000000.0}, preserver.preserved_path_mtimes)
      subprocess.check_call(['touch', file2])
    AssertEquals(1500000000.0, os.lstat(dir1).st_mtime)
    AssertNotEquals(1500000000.0, os.lstat(file1).st_mtime)
    AssertEquals(1500000000.0, os.lstat(file2).st_mtime)

    with lib.MtimePreserver() as preserver:
      preserver.PreserveMtime(dir2)
      file3 = CreateFile(dir1, 'file3')

      preserver.PreserveMtime(file3)
      subprocess.check_call(['touch', file3])
      AssertNotEquals(1500000000.0, os.lstat(file3).st_mtime)

      file4 = CreateFile(dir1, 'file4')
      preserver.PreserveMtime(file4)

      AssertEquals({dir2: 1500000000.0, file3: 1500000000.0, file4: 1500000000.0}, preserver.preserved_path_mtimes)
      DeleteFileOrDir(dir2)
      DeleteFileOrDir(file4)
    AssertEquals(1500000000.0, os.lstat(file3).st_mtime)


def PathMatcherPathsAndPrefixTest():
  matcher = lib.PathMatcherPathsAndPrefix([])
  AssertEquals(False, matcher.Matches('a'))
  AssertEquals(False, matcher.Matches('a/b'))
  AssertEquals(False, matcher.Matches(''))

  matcher = lib.PathMatcherPathsAndPrefix(['a'])
  AssertEquals(True, matcher.Matches('a'))
  AssertEquals(True, matcher.Matches('a/b'))
  AssertEquals(False, matcher.Matches('/a'))
  AssertEquals(False, matcher.Matches(''))
  AssertEquals(False, matcher.Matches('ab'))
  AssertEquals(False, matcher.Matches('b'))
  AssertEquals(False, matcher.Matches('b/a'))

  matcher = lib.PathMatcherPathsAndPrefix(['a/b'])
  AssertEquals(False, matcher.Matches('a'))
  AssertEquals(True, matcher.Matches('a/b'))
  AssertEquals(True, matcher.Matches('a/b/c'))
  AssertEquals(False, matcher.Matches('a/bc'))
  AssertEquals(False, matcher.Matches('a/bc/d'))

  matcher = lib.PathMatcherPathsAndPrefix(['a/b', 'a'])
  AssertEquals(True, matcher.Matches('a'))
  AssertEquals(False, matcher.Matches('ab'))
  AssertEquals(True, matcher.Matches('a/b'))
  AssertEquals(True, matcher.Matches('a/b/c'))
  AssertEquals(True, matcher.Matches('a/bc'))
  AssertEquals(True, matcher.Matches('a/bc/d'))
  AssertEquals(False, matcher.Matches('b'))


def PathsFromArgsTest():
  def DoPathsFromArgsTest(expected_paths, args, required=True, expected_success=True):
    parser = argparse.ArgumentParser()
    lib.AddPathsArgs(parser)
    try:
      paths = lib.GetPathsFromArgs(parser.parse_args(args), required=required)
      success = True
    except:
      paths = []
      success = False
      if expected_success:
        raise
    AssertEquals(expected_success, success)
    AssertEquals(expected_paths, paths)

  with TempDir() as test_dir:
    DoPathsFromArgsTest([], [], expected_success=False)
    DoPathsFromArgsTest([], [], required=False)
    DoPathsFromArgsTest(['a'], ['--path', 'a'])
    DoPathsFromArgsTest(['a', 'b\' '], ['--path', 'a', '--path', 'b\' '])

    paths_file = CreateFile(test_dir, 'paths_file', contents='b\na')
    DoPathsFromArgsTest(['a', 'b'], ['--paths-from', paths_file])
    DoPathsFromArgsTest(['a', 'b', 'c'], ['--path', 'c', '--paths-from', paths_file])

    paths_file = CreateFile(test_dir, 'paths_file', contents='\n'.join(
      [lib.EscapePath(s) for s in ['a', 'b\' ', 'f_\r \xc2\xa9', '']]))
    DoPathsFromArgsTest(['a', 'b\' ', 'f_\r \xc2\xa9'], ['--paths-from', paths_file])


def PathEnumeratorTest():
  def GetEnumeratePathInfos(root_dir, filters, use_rsync):
    paths = []
    for enumerated_path in lib.PathEnumerator(
        root_dir, output=sys.stdout, filters=filters, use_rsync=use_rsync).Scan():
      path_info = enumerated_path.GetPath()
      if enumerated_path.GetFollowSymlinks():
        path_info += ';follow-symlinks'
      paths.append(path_info)
    return paths

  def DoEnumeratePathsTest(root_dir, filters=[], expected_paths=[], verify_rsync=True):
    if verify_rsync:
      rsync_paths = GetEnumeratePathInfos(test_dir, filters=filters, use_rsync=True)
      AssertLinesEqual(expected_paths, rsync_paths)
    non_rsync_paths = GetEnumeratePathInfos(test_dir, filters=filters, use_rsync=False)
    AssertLinesEqual(expected_paths, non_rsync_paths)

  with TempDir() as test_dir:
    file1 = CreateFile(test_dir, 'f1')

    DoEnumeratePathsTest(test_dir, expected_paths=['.', 'f1'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('f2')],
                         expected_paths=['.', 'f1'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('f1')],
                         expected_paths=['.'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('/f1')],
                         expected_paths=['.'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('f1/')],
                         expected_paths=['.', 'f1'])

    dir2 = CreateDir(test_dir, 'd2')
    file3 = CreateFile(dir2, 'f3')

    DoEnumeratePathsTest(test_dir, expected_paths=['.', 'd2', 'd2/f3', 'f1'])

    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('d2')],
                         expected_paths=['.', 'f1'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('d2/')],
                         expected_paths=['.', 'f1'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('f3')],
                         expected_paths=['.', 'd2', 'f1'])

    file1_in_dir2 = CreateFile(dir2, 'f1')
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('f1')],
                         expected_paths=['.', 'd2', 'd2/f3'])
    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('/f1')],
                         expected_paths=['.', 'd2', 'd2/f1', 'd2/f3'])

    DoEnumeratePathsTest(test_dir, filters=[lib.FilterRuleExclude('*')],
                         expected_paths=['.'])
    DoEnumeratePathsTest(test_dir,
                         filters=[lib.FilterRuleInclude('d2/'),
                                  lib.FilterRuleExclude('*')],
                         expected_paths=['.', 'd2'])
    DoEnumeratePathsTest(test_dir,
                         filters=[lib.FilterRuleInclude('d2/'),
                                  lib.FilterRuleInclude('d2/**'),
                                  lib.FilterRuleExclude('*')],
                         expected_paths=['.', 'd2', 'd2/f1', 'd2/f3'])

    CreateFile(test_dir, 'SKIP1')
    CreateFile(test_dir, '1.skp')
    CreateFile(dir2, '2.skp')

    DoEnumeratePathsTest(test_dir,
                         expected_paths=[
                           '.',
                           '1.skp',
                           'SKIP1',
                           'd2',
                           'd2/2.skp',
                           'd2/f1',
                           'd2/f3',
                           'f1'])

    DoEnumeratePathsTest(test_dir,
                         filters=[lib.FilterRuleExclude('/d2/'),
                                  lib.FilterRuleInclude('/**'),
                                  lib.FilterRuleExclude('*')],
                         expected_paths=[
                           '.',
                           '1.skp',
                           'SKIP1',
                           'f1'])

    CreateFile(test_dir, lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
               contents=['exclude /SKIP1',
                         'exclude *.skp'])

    DoEnumeratePathsTest(test_dir,
                         expected_paths=[
                           '.',
                           '.staged_backup_filter',
                           '1.skp',
                           'SKIP1',
                           'd2',
                           'd2/2.skp',
                           'd2/f1',
                           'd2/f3',
                           'f1'])
    DoEnumeratePathsTest(test_dir, filters=lib.STAGED_BACKUP_DEFAULT_FILTERS,
                         expected_paths=[
                           '.',
                           '.staged_backup_filter',
                           'd2',
                           'd2/f1',
                           'd2/f3',
                           'f1'])

    dir3 = CreateDir(dir2, 'd3')
    CreateFile(dir2, 'mayskip')
    CreateFile(dir3, 'mayskip')
    CreateFile(test_dir, '1.skp')
    CreateFile(dir2, lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
               contents=['exclude /mayskip'])

    DoEnumeratePathsTest(test_dir, filters=lib.STAGED_BACKUP_DEFAULT_FILTERS,
                         expected_paths=[
                           '.',
                           '.staged_backup_filter',
                           'd2',
                           'd2/.staged_backup_filter',
                           'd2/d3',
                           'd2/d3/mayskip',
                           'd2/f1',
                           'd2/f3',
                           'f1'])

  with TempDir() as test_dir2:
    with TempDir() as test_dir:
      file1 = CreateFile(test_dir, 'f1')
      ln1 = CreateSymlink(test_dir, 'ln1', 'INVALID')

      dir1 = CreateDir(test_dir2, 'd1')
      file2 = CreateFile(dir1, 'f2')
      ln2 = CreateSymlink(test_dir, 'ln2', test_dir2)

      ln3 = CreateSymlink(test_dir2, 'ln3', 'd1/f2')
      ln4 = CreateSymlink(test_dir2, 'ln4', 'd1/f2')
      ln5 = CreateSymlink(test_dir2, 'ln5', 'd1')

      CreateFile(test_dir, lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
                 contents=['follow-symlinks /ln2/',
                           'follow-symlinks /ln2/ln3',
                           'follow-symlinks /ln2/ln5'])

      DoEnumeratePathsTest(test_dir,
                           expected_paths=[
                             '.',
                             '.staged_backup_filter',
                             'f1',
                             'ln1',
                             'ln2'])
      DoEnumeratePathsTest(test_dir, filters=lib.STAGED_BACKUP_DEFAULT_FILTERS,
                           verify_rsync=False,
                           expected_paths=[
                             '.',
                             '.staged_backup_filter',
                             'f1',
                             'ln1',
                             'ln2;follow-symlinks',
                             'ln2/d1',
                             'ln2/d1/f2',
                             'ln2/ln3;follow-symlinks',
                             'ln2/ln4',
                             'ln2/ln5;follow-symlinks',
                             'ln2/ln5/f2'])


def FilterRuleTest():
  def DoFilterRuleTest(expected_match, matcher, path, is_dir=False, expect_matcher_exception=False):
    class FakeStat:
      def __init__(self, is_dir=False):
        self.st_mode = is_dir and 16877 or 33188

    try:
      regex = lib.FilterRule.CompileRegex(matcher)
    except lib.UnsupportedMatcherError as e:
      AssertEquals(True, expect_matcher_exception)
    else:
      AssertEquals(False, expect_matcher_exception)
      AssertEquals(expected_match, lib.FilterRule.MatchesPath(
        regex, path, path_stat=FakeStat(is_dir=is_dir)))

  DoFilterRuleTest(True, 'a', 'a')
  DoFilterRuleTest(True, '/a', 'a')
  DoFilterRuleTest(False, 'a', 'b')
  DoFilterRuleTest(True, 'a', 'b/a')
  DoFilterRuleTest(False, '/a', 'b/a')
  DoFilterRuleTest(True, 'a', 'a', is_dir=True)
  DoFilterRuleTest(True, 'a/', 'a', is_dir=True)
  DoFilterRuleTest(False, 'a/', 'a')
  DoFilterRuleTest(True, '/a/b', 'a/b')

  DoFilterRuleTest(True, '*', 'a')
  DoFilterRuleTest(True, '*', 'b/a')
  DoFilterRuleTest(False, 'a/*', 'b/a')
  DoFilterRuleTest(True, 'b/*', 'b/a')
  DoFilterRuleTest(False, 'a/*/', 'a/b')
  DoFilterRuleTest(True, 'a/*/', 'a/b', is_dir=True)
  DoFilterRuleTest(True, 'b/*', 'c/b/a')
  DoFilterRuleTest(False, 'c/*', 'c/b/a')
  DoFilterRuleTest(True, 'c/**', 'c/b/a')
  DoFilterRuleTest(True, '/c/**', 'c/b/a')
  DoFilterRuleTest(False, '/b/*', 'c/b/a')
  DoFilterRuleTest(True, '*/b/*', 'c/b/a')
  DoFilterRuleTest(True, '/*/b/*', 'c/b/a')
  DoFilterRuleTest(False, 'c/**/', 'c/b/a')
  DoFilterRuleTest(True, 'c/**/', 'c/b/a', is_dir=True)

  DoFilterRuleTest(True, 'c?', 'a',  expect_matcher_exception=True)
  DoFilterRuleTest(True, 'c\\', 'a',  expect_matcher_exception=True)
  DoFilterRuleTest(True, '[a-b]', 'a',  expect_matcher_exception=True)


def Test(tests=[]):
  if not tests or 'PathInfoTest' in tests:
    PathInfoTest()
  if not tests or 'ItemizedPathChangeTest' in tests:
    ItemizedPathChangeTest()
  if not tests or 'CreateDryRunTest' in tests:
    CreateDryRunTest()
  if not tests or 'CreateTest' in tests:
    CreateTest()
  if not tests or 'CreateWithFilterMergeTest' in tests:
    CreateWithFilterMergeTest()
  if not tests or 'CreateFromGoogleDriveTest' in tests:
    CreateFromGoogleDriveTest()
  if not tests or 'CreateWithFollowSymlinksTest' in tests:
    CreateWithFollowSymlinksTest()
  if not tests or 'ApplyDryRunTest' in tests:
    ApplyDryRunTest()
  if not tests or 'ApplyTest' in tests:
    ApplyTest()
  if not tests or 'ApplyFromGoogleDriveTest' in tests:
    ApplyFromGoogleDriveTest()
  if not tests or 'StripTest' in tests:
    StripTest()
  if not tests or 'CompactTest' in tests:
    CompactTest()
  if not tests or 'DiffManifestsTest' in tests:
    DiffManifestsTest()
  if not tests or 'FileSizeToStringTest' in tests:
    FileSizeToStringTest()
  if not tests or 'EscapeKeyDetectorTest' in tests:
    EscapeKeyDetectorTest()
  if not tests or 'MtimePreserverTest' in tests:
    MtimePreserverTest()
  if not tests or 'PathMatcherPathsAndPrefixTest' in tests:
    PathMatcherPathsAndPrefixTest()
  if not tests or 'PathsFromArgsTest' in tests:
    PathsFromArgsTest()
  if not tests or 'PathEnumeratorTest' in tests:
    PathEnumeratorTest()
  if not tests or 'FilterRuleTest' in tests:
    FilterRuleTest()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  SetPacificTimezone()

  Test(tests=args.tests)
