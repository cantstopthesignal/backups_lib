#!/usr/bin/python -u -B

import StringIO
import argparse
import contextlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import xattr

import backups_lib
import backups_oneoff_lib
import lib

from test_util import AssertEquals
from test_util import AssertNotEquals
from test_util import CreateDir
from test_util import CreateDirs
from test_util import CreateFile
from test_util import CreateSymlink
from test_util import DeleteFileOrDir
from test_util import DoBackupsMain
from test_util import SetMTime
from test_util import SetPacificTimezone
from test_util import TempDir

from lib_test_util import GetManifestItemized
from lib_test_util import DoVerifyManifest

from backups_lib_test_util import CreateConfig
from backups_lib_test_util import CreateBackupsBundle
from backups_lib_test_util import CreateLatestManifestCheckpoint
from backups_lib_test_util import DoApplyToBackups
from backups_lib_test_util import DoCreateBackup
from backups_lib_test_util import DoCreateCheckpoint
from backups_lib_test_util import DoDeduplicateBackups
from backups_lib_test_util import DoDeleteBackup
from backups_lib_test_util import DoVerifyBackups


@contextlib.contextmanager
def ReplaceIgnoredXattrKeys(new_value=[]):
  old_ignored_xattr_keys = lib.IGNORED_XATTR_KEYS
  lib.IGNORED_XATTR_KEYS = new_value
  try:
    yield
  finally:
    lib.IGNORED_XATTR_KEYS = old_ignored_xattr_keys


@contextlib.contextmanager
def InstallReplaceIgnoredXattrKeys(new_value=[]):
  MAYBE_CHANGE_PATH_TEST_HOOK
  old_ignored_xattr_keys = lib.IGNORED_XATTR_KEYS
  lib.IGNORED_XATTR_KEYS = new_value
  try:
    yield
  finally:
    lib.IGNORED_XATTR_KEYS = old_ignored_xattr_keys


def DoOneoffUpdateIgnoredXattrsTest(
    config, dry_run=False, min_backup=None, max_backup=None,
    old_ignored_xattrs=[], new_ignored_xattrs=[],
    expected_success=True, expected_output=[]):
  cmd_args = ['oneoff-update-ignored-xattrs',
              '--backups-config', config.path]
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  for xattr_key in old_ignored_xattrs:
    cmd_args.extend(['--old-ignored-xattr', xattr_key])
  for xattr_key in new_ignored_xattrs:
    cmd_args.extend(['--new-ignored-xattr', xattr_key])
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoOneoffUpdateSomeFiles(
    config, dry_run=False, min_backup=None, max_backup=None,
    expected_success=True, expected_output=[]):
  cmd_args = ['oneoff-update-some-files',
              '--backups-config', config.path]
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def OneoffUpdateIgnoredXattrsTest():
  old_ignored_xattr_keys = ['com.apple.lastuseddate#PS']
  new_ignored_xattr_keys = ['com.apple.lastuseddate#PS',
                            'com.apple.quarantine']

  with TempDir() as test_dir:
    with ReplaceIgnoredXattrKeys(old_ignored_xattr_keys):
      config = CreateConfig(test_dir)
      CreateBackupsBundle(config)
      latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

      fileX = CreateFile(config.src_path, 'fX')
      xattr.setxattr(fileX, 'example', 'example_value')
      xattr.setxattr(fileX, 'com.apple.quarantine', 'quarantine1')

      fileT = CreateFile(config.src_path, 'fT')
      xattr.setxattr(fileT, 'example', 'example_value2')
      xattr.setxattr(fileT, 'com.apple.quarantine', 'quarantine4')

      parent1 = CreateDir(config.src_path, 'par!')
      file3 = CreateFile(parent1, 'f3')
      file4 = CreateFile(parent1, 'f4')
      xattr.setxattr(file4, 'example', 'example_value3')

      DoCreateCheckpoint(
        config.src_path, config.checkpoints_dir, '2020-01-02-120000',
        last_checkpoint_path=latest_checkpoint_path,
        expected_output=['*deleting f1',
                         '.f......x fT',
                         '.f......x fX',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f3',
                         '>f+++++++ par!/f4',
                         'Transferring 5 of 6 paths (0b of 0b)'])

      xattr.setxattr(fileX, 'com.apple.quarantine', 'quarantine2')
      xattr.setxattr(file3, 'com.apple.quarantine', 'quarantine3')
      xattr.removexattr(fileT, 'com.apple.quarantine')
      xattr.setxattr(file4, 'example', 'example_value4')

      checkpoint_path2 = DoCreateBackup(
        config, backup_name='2020-01-03-120000',
        expected_output=['.f......x fT',
                         '.f......x fX',
                         '.f......x par!/f3',
                         '.f......x par!/f4',
                         'Transferring 4 of 6 paths (0b of 0b)'])

      DoApplyToBackups(
        config,
        expected_output=['Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                         '*deleting f1',
                         '.f......x fT',
                         '.f......x fX',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f3',
                         '>f+++++++ par!/f4',
                         'Copying paths: 6 to copy, 6 total in source, 6 total in result...',
                         'Verifying 2020-01-02-120000...',
                         'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                         '.f......x fT',
                         '.f......x fX',
                         '.f......x par!/f3',
                         '.f......x par!/f4',
                         'Copying paths: 6 to copy, 6 total in source, 6 total in result...',
                         'Verifying 2020-01-03-120000...'])

      DoVerifyBackups(
        config,
        expected_output=['Verifying 2020-01-01-120000...',
                         'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                         'Verifying 2020-01-02-120000...',
                         'Paths: 6 total, 0 inode hits, 4 checksummed (0b)',
                         'Verifying 2020-01-03-120000...',
                         'Paths: 6 total, 0 inode hits, 4 checksummed (0b)'])

      do_oneoff_expected_output = [
        'Old ignored xattrs: com.apple.lastuseddate#PS',
        'New ignored xattrs: com.apple.lastuseddate#PS, com.apple.quarantine',
        'Applying to backup 2020-01-01-120000...',
        'Paths: 0 paths with xattrs, 0 xattrs changed, 4 paths',
        'Applying to backup 2020-01-02-120000...',
        'Updated xattr for fT from 4eecd3 to 94b18a',
        'Updated xattr for fX from a0d837 to 5cac1a',
        'Paths: 3 paths with xattrs, 2 xattrs changed, 6 paths',
        'Applying to backup 2020-01-03-120000...',
        'Updated xattr for fX from deae88 to 5cac1a',
        'Updated xattr for par!/f3 from 60b5ab to None',
        'Paths: 4 paths with xattrs, 2 xattrs changed, 6 paths']

      DoOneoffUpdateIgnoredXattrsTest(
        config, dry_run=True,
        old_ignored_xattrs=old_ignored_xattr_keys,
        new_ignored_xattrs=new_ignored_xattr_keys,
        expected_output=do_oneoff_expected_output)
      DoOneoffUpdateIgnoredXattrsTest(
        config,
        old_ignored_xattrs=old_ignored_xattr_keys,
        new_ignored_xattrs=new_ignored_xattr_keys,
        expected_output=do_oneoff_expected_output)

      backups_manager = backups_lib.BackupsManager.Open(
        config, readonly=True, browseable=False)
      try:
        backup1 = backups_manager.GetBackup('2020-01-01-120000')
        AssertEquals(False, os.path.exists(lib.GetManifestBackupPath(
          backup1.GetManifestPath())))

        backup2 = backups_manager.GetBackup('2020-01-02-120000')
        DoVerifyManifest(
          backup2.GetContentRootPath(),
          lib.GetManifestBackupPath(backup2.GetManifestPath()))

        backup3 = backups_manager.GetBackup('2020-01-03-120000')
        DoVerifyManifest(
          backup3.GetContentRootPath(),
          lib.GetManifestBackupPath(backup3.GetManifestPath()))
      finally:
        backups_manager.Close()

      DoVerifyBackups(
        config, continue_on_error=True,
        expected_success=False,
        expected_output=['Verifying 2020-01-01-120000...',
                         'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                         'Verifying 2020-01-02-120000...',
                         'Paths: 6 total, 0 inode hits, 4 checksummed (0b)',
                         '.f......x fT',
                         '.f......x fX',
                         '*** Error: Failed to verify backup Backup<2020-01-02-120000,DONE>',
                         'Verifying 2020-01-03-120000...',
                         'Paths: 6 total, 0 inode hits, 4 checksummed (0b)',
                         '.f......x fX',
                         '.f......x par!/f3',
                         '*** Error: Failed to verify backup Backup<2020-01-03-120000,DONE>'])

    with ReplaceIgnoredXattrKeys(new_ignored_xattr_keys):
      DoVerifyBackups(
        config,
        expected_output=['Verifying 2020-01-01-120000...',
                         'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                         'Verifying 2020-01-02-120000...',
                         'Paths: 6 total, 0 inode hits, 4 checksummed (0b)',
                         'Verifying 2020-01-03-120000...',
                         'Paths: 6 total, 0 inode hits, 4 checksummed (0b)'])


def OneoffUpdateSomeFilesTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')

    fileT = CreateFile(config.src_path, 'fT')

    parent1 = CreateDir(config.src_path, 'par!')
    file3 = CreateFile(parent1, 'f3')
    file4 = CreateFile(parent1, 'f4', contents='2'*1025)
    os.chmod(file4, 0700)
    file5 = CreateFile(parent1, 'f5', contents='1'*1025)
    os.chmod(file5, 0700)

    DoCreateCheckpoint(
      config.src_path, config.checkpoints_dir, '2020-01-02-120000',
      last_checkpoint_path=latest_checkpoint_path,
      expected_output=['*deleting f1',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f3',
                       '>f+++++++ par!/f4',
                       '>f+++++++ par!/f5',
                       'Transferring 4 of 7 paths (2kb of 2kb)'])

    xattr.setxattr(fileX, 'example', 'example_value4')
    SetMTime(fileX, mtime=1510000000)
    SetMTime(file3, mtime=1510000000)

    DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['.f..t...x fX',
                       '.f..t.... par!/f3',
                       'Transferring 2 of 7 paths (0b of 2kb)'])

    os.chmod(file4, 0600)

    DoCreateBackup(
      config, backup_name='2020-01-04-120000',
      expected_output=['.f...p... par!/f4',
                       'Transferring 1 of 7 paths (1kb of 2kb)'])

    DoApplyToBackups(
      config,
      expected_output=None)
    DoVerifyBackups(
      config,
      expected_output=None)

    DoDeduplicateBackups(
      config,
      expected_output=[
        'De-duplicate Backup<2020-01-02-120000,DONE> onto Backup<2020-01-01-120000,DONE>...',
        'Duplicates: 2 large files',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicates: 2 existing; 2 large files',
        'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
        'Duplicates: 1 existing; 1 similar (size=1kb); 2 large files'])

    def NoopChangePathTestHook(updater, backup, manifest, path, output, dry_run=False):
      return False

    backups_oneoff_lib.OneoffSomeFilesUpdater.MAYBE_CHANGE_PATH_TEST_HOOK = NoopChangePathTestHook
    try:
      do_oneoff_update_some_files_expected_output = [
        'Applying to backup 2020-01-01-120000...',
        'Paths: 0 changed, 4 total',
        'Applying to backup 2020-01-02-120000...',
        'Paths: 0 changed, 7 total',
        'Applying to backup 2020-01-03-120000...',
        'Paths: 0 changed, 7 total',
        'Applying to backup 2020-01-04-120000...',
        'Paths: 0 changed, 7 total',
      ]
      DoOneoffUpdateSomeFiles(
        config, dry_run=True,
        expected_output=do_oneoff_update_some_files_expected_output)
      DoOneoffUpdateSomeFiles(
        config,
        expected_output=do_oneoff_update_some_files_expected_output)
    finally:
      backups_oneoff_lib.OneoffSomeFilesUpdater.MAYBE_CHANGE_PATH_TEST_HOOK = None

    DoVerifyBackups(
      config,
      expected_output=None)

    def ChangePathTestHook(updater, backup, manifest, path, output, dry_run=False):
      path_info = manifest.GetPathInfo(path)

      if backup.GetName() >= '2020-01-02-120000' and path in ['f3', 'fX']:
        incorrect_mtime = 1510000000
        corrected_mtime = 1500000000

        if updater._MaybeUpdateMtimeIfMatching(backup, path_info, incorrect_mtime, corrected_mtime):
          return True

      if backup.GetName() <= '2020-01-03-120000' and path in ['par!/f4', 'par!/f5']:
        incorrect_mode = 0700
        corrected_mode = 0600

        if updater._MaybeUpdatePermissionModeIfMatching(backup, path_info, incorrect_mode, corrected_mode):
          return True

      return False

    backups_oneoff_lib.OneoffSomeFilesUpdater.MAYBE_CHANGE_PATH_TEST_HOOK = ChangePathTestHook
    try:
      DoOneoffUpdateSomeFiles(
        config, dry_run=True,
        expected_output=['Applying to backup 2020-01-01-120000...',
                         'Paths: 0 changed, 4 total',
                         'Applying to backup 2020-01-02-120000...',
                         'Updating mode from 0700 to 0600 for path par!/f4',
                         'Updating mode from 0700 to 0600 for path par!/f5',
                         'Paths: 2 changed, 7 total',
                         'Applying to backup 2020-01-03-120000...',
                         'Updating mtime from 2017-11-06 12:26:40 to 2017-07-13 19:40:00 for path fX',
                         'Updating mode from 0700 to 0600 for path par!/f4',
                         'Updating mode from 0700 to 0600 for path par!/f5',
                         'Paths: 3 changed, 7 total',
                         'Applying to backup 2020-01-04-120000...',
                         'Updating mtime from 2017-11-06 12:26:40 to 2017-07-13 19:40:00 for path fX',
                         'Paths: 1 changed, 7 total'])
      DoOneoffUpdateSomeFiles(
        config,
        expected_output=['Applying to backup 2020-01-01-120000...',
                         'Paths: 0 changed, 4 total',
                         'Applying to backup 2020-01-02-120000...',
                         'Updating mode from 0700 to 0600 for path par!/f4',
                         'Updating mode from 0700 to 0600 for path par!/f5',
                         'Verifying 2020-01-02-120000...',
                         'Paths: 2 changed, 7 total',
                         'Applying to backup 2020-01-03-120000...',
                         'Updating mtime from 2017-11-06 12:26:40 to 2017-07-13 19:40:00 for path fX',
                         'Updating mode from 0700 to 0600 for path par!/f4',
                         'Updating mode from 0700 to 0600 for path par!/f5',
                         'Verifying 2020-01-03-120000...',
                         'Paths: 3 changed, 7 total',
                         'Applying to backup 2020-01-04-120000...',
                         'Updating mtime from 2017-11-06 12:26:40 to 2017-07-13 19:40:00 for path fX',
                         'Verifying 2020-01-04-120000...',
                         'Paths: 1 changed, 7 total'])
      DoOneoffUpdateSomeFiles(
        config,
        expected_output=['Applying to backup 2020-01-01-120000...',
                         'Paths: 0 changed, 4 total',
                         'Applying to backup 2020-01-02-120000...',
                         'Paths: 0 changed, 7 total',
                         'Applying to backup 2020-01-03-120000...',
                         'Paths: 0 changed, 7 total',
                         'Applying to backup 2020-01-04-120000...',
                         'Paths: 0 changed, 7 total'])
    finally:
      backups_oneoff_lib.OneoffSomeFilesUpdater.MAYBE_CHANGE_PATH_TEST_HOOK = None

    DoDeduplicateBackups(
      config,
      expected_output=[
        'De-duplicate Backup<2020-01-02-120000,DONE> onto Backup<2020-01-01-120000,DONE>...',
        'Duplicates: 2 large files',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicate path par!/f4 (size=1kb) to:',
        '  par!/f4',
        'Duplicate path par!/f5 (size=1kb) to:',
        '  par!/f5',
        'Duplicates: 2 new (size=2kb); 2 large files',
        'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
        'Duplicate path par!/f4 (size=1kb) to:',
        '  par!/f4',
        'Duplicates: 1 new (size=1kb); 1 similar (size=1kb); 2 large files'])

    DoVerifyBackups(
      config,
      expected_output=None)


def Test(tests=[]):
  if not tests or 'OneoffUpdateIgnoredXattrsTest' in tests:
    OneoffUpdateIgnoredXattrsTest()
  if not tests or 'OneoffUpdateSomeFilesTest' in tests:
    OneoffUpdateSomeFilesTest()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  SetPacificTimezone()

  Test(tests=args.tests)
