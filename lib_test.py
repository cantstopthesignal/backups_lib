#!/usr/bin/env python3 -u -B

import argparse
import os
import pty
import re
import shutil
import subprocess
import sys
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
from .test_util import SetMTime
from .test_util import SetPacificTimezone
from .test_util import SetXattr
from .test_util import TempDir
from .test_util import Xattr

from .lib_test_util import ApplyFakeDiskImageHelperLevel
from .lib_test_util import CollapseApfsOperationsInOutput
from .lib_test_util import CreateGoogleDriveRemoteFile
from .lib_test_util import GetManifestItemized
from .lib_test_util import HandleGoogleDriveRemoteFiles
from .lib_test_util import SetHdiutilCompactOnBatteryAllowed
from .lib_test_util import SetOmitUidAndGidInPathInfoToString

from .checkpoint_lib_test_util import DoCreate


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


def DoDiffManifests(manifest1_path, manifest2_path, ignore_matching_renames=False,
                    expected_success=True, expected_output=[]):
  cmd_args = ['diff-manifests',
              manifest1_path,
              manifest2_path]
  if ignore_matching_renames:
    cmd_args.append('--ignore-matching-renames')
  DoBackupsMain(cmd_args, expected_success=expected_success, expected_output=expected_output)


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


class PathInfoTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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

    def DoTest(path, paths, expected_paths):
      path_infos = [ PathInfoLike(p) for p in paths ]
      sorted_path_infos = lib.PathInfo.SortedByPathSimilarity(path, path_infos)
      sorted_paths = [ p.path for p in sorted_path_infos ]

      AssertEquals(expected_paths, sorted_paths)

    DoTest('/tmp/thepath',
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

    DoTest('/tmp/a',
           paths=[
             '/tmp/d',
             '/tmp/c',
             '/tmp/b'],
           expected_paths=[
             '/tmp/b',
             '/tmp/c',
             '/tmp/d'])


class ItemizedPathChangeTestCase(BaseTestCase):
  def test(self):
    def ReadItemizedTty(itemized, found_matching_rename=False, warn_for_new_path=False):
      tty_master, tty_slave = pty.openpty()
      try:
        with os.fdopen(tty_slave, 'w') as tty_output:
          itemized.Print(output=tty_output, found_matching_rename=found_matching_rename,
                         warn_for_new_path=warn_for_new_path)
          tty_output.flush()
          return os.read(tty_master, 1024).rstrip()
      finally:
        os.close(tty_master)

    AssertEquals(
      '.f....... path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE)))
    AssertEquals(
      '>d....... path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, replace_path=True)))
    AssertEquals(
      '*f.delete path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, delete_path=True)))
    AssertEquals(
      '*d.delete path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, delete_path=True)))
    AssertEquals(
      '*L.delete path', str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_SYMLINK, delete_path=True)))
    AssertEquals(
      '>fc...... path',
      str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, replace_path=True, checksum_diff=True)))
    AssertEquals(
      '.L.s..... path -> dest',
      str(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_SYMLINK, size_diff=True, link_dest='dest')))
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

    AssertEquals(b'\x1b[1;m.f.......\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE)))
    AssertEquals(b'\x1b[1;32m>f+++++++\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, new_path=True)))
    AssertEquals(b'\x1b[1;31m>f+++++++\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, new_path=True), warn_for_new_path=True))
    AssertEquals(b'\x1b[1;35m>f+++++++\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, new_path=True),
                                 warn_for_new_path=True, found_matching_rename=True))
    AssertEquals(b'\x1b[1;m.f.......\x1b[1;m \x1b[1;36mpar/\x1b[1;mpath',
                 ReadItemizedTty(lib.ItemizedPathChange('par/path', lib.PathInfo.TYPE_FILE)))
    AssertEquals(b'\x1b[1;m.d.......\x1b[1;m \x1b[1;36mpath\x1b[1;m',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR)))
    AssertEquals(b'\x1b[1;m.L.......\x1b[1;m \x1b[1;35mpath\x1b[1;m -> dest',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_SYMLINK, link_dest='dest')))
    AssertEquals(b'\x1b[1;31m*f.delete\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, delete_path=True)))
    AssertEquals(b'\x1b[1;35m*f.delete\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, delete_path=True), found_matching_rename=True))
    AssertEquals(b'\x1b[1;35m*d.delete\x1b[1;m \x1b[1;36mpath\x1b[1;m',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_DIR, delete_path=True)))
    AssertEquals(b'\x1b[1;35m.fc......\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, checksum_diff=True)))
    AssertEquals(b'\x1b[1;33m.f..t....\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, time_diff=True)))
    AssertEquals(b'\x1b[1;33m.f...p...\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, permission_diff=True)))
    AssertEquals(b'\x1b[1;35m.f......x\x1b[1;m path',
                 ReadItemizedTty(lib.ItemizedPathChange('path', lib.PathInfo.TYPE_FILE, xattr_diff=True)))


class CompactTestCase(BaseTestCase):
  def test(self):
    with ApplyFakeDiskImageHelperLevel(
        min_fake_disk_image_level=lib_test_util.FAKE_DISK_IMAGE_LEVEL_NONE, test_case=self) as should_run:
      if should_run:
        with SetHdiutilCompactOnBatteryAllowed(True):
          with TempDir() as test_dir:
            self.RunTest(test_dir)

  def RunTest(self, test_dir):
    checkpoints_dir = CreateDir(test_dir, 'checkpoints')
    src_root = CreateDir(test_dir, 'src')
    file1 = CreateFile(src_root, 'f1', contents='1' * (1024 * 1024 * 20))

    checkpoint1, manifest1 = DoCreate(
      src_root, checkpoints_dir, '1',
      expected_output=['>d+++++++ .', '>f+++++++ f1', 'Transferring 2 paths (20mb)'])
    checkpoint1.Close()

    checkpoint1 = checkpoint_lib.Checkpoint.Open(checkpoint1.GetImagePath(), readonly=False)
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
                re.compile('^Iteration 2, new apfs min size 1[.][23]gb[.][.][.]$'),
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
                re.compile('^Image size 225[.]5mb -> (42[.][67]|34[.]8)mb$')])
    AssertFileSizeInRange(lib.GetPathTreeSize(image_path2), '34.7mb', '42.7mb')


class DiffManifestsTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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
                    expected_output=['*f.delete file1',
                                     '>L+++++++ ln1 -> INVALID'])
    DoDiffManifests(manifest1.path, manifest2.path,
                    ignore_matching_renames=True,
                    expected_output=['*f.delete file1',
                                     '>L+++++++ ln1 -> INVALID'])
    DoDiffManifests(manifest2.path, manifest1.path,
                    expected_output=['>f+++++++ file1',
                                     '*L.delete ln1'])
    DoDiffManifests(manifest2.path, manifest1.path,
                    ignore_matching_renames=True,
                    expected_output=['>f+++++++ file1',
                                     '*L.delete ln1'])

    file2 = CreateFile(test_dir, 'file2', contents='1' * 1025)
    file2_path_info = lib.PathInfo.FromPath(os.path.basename(file2), file2)
    file2_path_info.sha256 = lib.Sha256(file2)

    manifest2.AddPathInfo(file2_path_info)
    manifest2.Write()
    DoDiffManifests(manifest1.path, manifest2.path,
                    expected_output=['*f.delete file1',
                                     '  replaced by duplicate: .f....... file2',
                                     '>f+++++++ file2',
                                     '  replacing duplicate: .f....... file1',
                                     '>L+++++++ ln1 -> INVALID'])
    DoDiffManifests(manifest1.path, manifest2.path,
                    ignore_matching_renames=True,
                    expected_output=['>L+++++++ ln1 -> INVALID'])


class FileSizeToStringTestCase(BaseTestCase):
  def test(self):
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


class EscapeKeyDetectorTestCase(BaseTestCase):
  def test(self):
    escape_detector = lib.EscapeKeyDetector()
    try:
      AssertEquals(False, escape_detector.WasEscapePressed())
      time.sleep(.1)
      AssertEquals(False, escape_detector.WasEscapePressed())
    finally:
      escape_detector.Shutdown()
    AssertEquals(False, escape_detector.WasEscapePressed())


class MtimePreserverTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def RunTest(self, test_dir):
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

      AssertEquals({dir2: 1500000000.0, file3: 1500000000.0, file4: 1500000000.0},
                   preserver.preserved_path_mtimes)
      DeleteFileOrDir(dir2)
      DeleteFileOrDir(file4)
    AssertEquals(1500000000.0, os.lstat(file3).st_mtime)


class PathMatcherPathsAndPrefixTestCase(BaseTestCase):
  def test(self):
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


class PathsFromArgsTestCase(BaseTestCase):
  def test(self):
    with TempDir() as test_dir:
      self.RunTest(test_dir)

  def DoPathsFromArgsTest(self, expected_paths, args, required=True, expected_success=True):
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

  def RunTest(self, test_dir):
    self.DoPathsFromArgsTest([], [], expected_success=False)
    self.DoPathsFromArgsTest([], [], required=False)
    self.DoPathsFromArgsTest(['a'], ['--path', 'a'])
    self.DoPathsFromArgsTest(['a', 'b\' '], ['--path', 'a', '--path', 'b\' '])

    paths_file = CreateFile(test_dir, 'paths_file', contents='b\na')
    self.DoPathsFromArgsTest(['a', 'b'], ['--paths-from', paths_file])
    self.DoPathsFromArgsTest(['a', 'b', 'c'], ['--path', 'c', '--paths-from', paths_file])

    paths_file = CreateFile(test_dir, 'paths_file', contents='\n'.join(
      [lib.EscapePath(s) for s in ['a', 'b\' ', 'f_\r \xc2\xa9', '']]))
    self.DoPathsFromArgsTest(['a', 'b\' ', 'f_\r \xc2\xa9'], ['--paths-from', paths_file])


class PathEnumeratorTestCase(BaseTestCase):
  def test(self):
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

      CreateFile(test_dir, checkpoint_lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
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
      DoEnumeratePathsTest(test_dir, filters=checkpoint_lib.STAGED_BACKUP_DEFAULT_FILTERS,
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
      CreateFile(dir2, checkpoint_lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
                 contents=['exclude /mayskip'])

      DoEnumeratePathsTest(test_dir, filters=checkpoint_lib.STAGED_BACKUP_DEFAULT_FILTERS,
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

        CreateFile(test_dir, checkpoint_lib.STAGED_BACKUP_DIR_MERGE_FILENAME,
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
        DoEnumeratePathsTest(test_dir, filters=checkpoint_lib.STAGED_BACKUP_DEFAULT_FILTERS,
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


class FilterRuleTestCase(BaseTestCase):
  def test(self):
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
    DoFilterRuleTest(True, 'c/a\\r', 'c/a\r')

    DoFilterRuleTest(True, 'c?', 'a',  expect_matcher_exception=True)
    DoFilterRuleTest(True, 'c\\\\', 'a',  expect_matcher_exception=True)
    DoFilterRuleTest(True, '[a-b]', 'a',  expect_matcher_exception=True)


if __name__ == '__main__':
  test_main.RunCurrentFileUnitTests()
