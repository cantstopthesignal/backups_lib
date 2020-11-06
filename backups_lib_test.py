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

import backups_lib
import lib

from test_util import AssertEquals
from test_util import AssertLinesEqual
from test_util import AssertNotEquals
from test_util import CreateDir
from test_util import CreateDirs
from test_util import CreateFile
from test_util import CreateSymlink
from test_util import DeleteFileOrDir
from test_util import SetMTime
from test_util import SetPacificTimezone
from test_util import TempDir

from lib_test_util import GetFileTreeManifest
from lib_test_util import GetManifestItemized
from lib_test_util import SetHdiutilCompactOnBatteryAllowed
from lib_test_util import SetOmitUidAndGidInPathInfoToString

from backups_lib_test_util import CreateBackupsBundle
from backups_lib_test_util import CreateConfig
from backups_lib_test_util import CreateLatestManifestCheckpoint
from backups_lib_test_util import DoAddMissingManifestsToBackups
from backups_lib_test_util import DoApplyToBackups
from backups_lib_test_util import DoCloneBackup
from backups_lib_test_util import DoCreateBackup
from backups_lib_test_util import DoCreateCheckpoint
from backups_lib_test_util import DoDeduplicateBackups
from backups_lib_test_util import DoDeleteBackup
from backups_lib_test_util import DoDeleteInBackups
from backups_lib_test_util import DoDumpUniqueFilesInBackups
from backups_lib_test_util import DoExtractFromBackups
from backups_lib_test_util import DoListBackups
from backups_lib_test_util import DoMergeIntoBackups
from backups_lib_test_util import DoPruneBackups
from backups_lib_test_util import DoVerifyBackups
from backups_lib_test_util import SetLogThrottlerLogAlways
from backups_lib_test_util import SetUniqueFilesMaxCounts
from backups_lib_test_util import VerifyBackupManifest


def ApplyToBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')
    fileT = CreateFile(config.src_path, 'fT')
    parent1 = CreateDir(config.src_path, 'par!')
    file1 = CreateFile(parent1, 'f_\r \xc2\xa9')

    checkpoint_path1 = DoCreateCheckpoint(
      config.src_path, config.checkpoints_dir, '2020-01-02-120000',
      last_checkpoint_path=latest_checkpoint_path,
      expected_output=['*deleting f1',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Transferring 2 of 5 paths (0b of 0b)'])

    file2 = CreateFile(parent1, 'f2')
    xattr.setxattr(fileX, 'example', 'example_value')
    SetMTime(fileT, None)
    SetMTime(parent1, None)

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['.f..t.... fT',
                       '.f......x fX',
                       '.d..t.... par!',
                       '>f+++++++ par!/f2',
                       'Transferring 4 of 6 paths (0b of 0b)'])

    DoApplyToBackups(
      config,
      dry_run=True,
      expected_success=False,
      expected_output=['Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Applying 2020-01-03-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '.f..t.... fT',
                       '.f......x fX',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f2',
                       '*f.error par!/f_\\r \\xc2\\xa9',
                       '*** Errors encountered before applying checkpoint',
                       '*** Error: Failed to apply 2020-01-03-120000 onto 2020-01-01-120000'])

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Verifying 2020-01-02-120000...',
                       'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
                       'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                       '.f..t.... fT',
                       '.f......x fX',
                       '.d..t.... par!',
                       '>f+++++++ par!/f2',
                       'Verifying 2020-01-03-120000...'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      backup1 = backups_manager.GetBackup('2020-01-01-120000')
      backup2 = backups_manager.GetBackup('2020-01-02-120000')
      backup3 = backups_manager.GetBackup('2020-01-03-120000')
      AssertEquals(os.lstat(os.path.join(backup1.GetDiskPath(), 'fX')).st_ino,
                   os.lstat(os.path.join(backup2.GetDiskPath(), 'fX')).st_ino)
      AssertNotEquals(os.lstat(os.path.join(backup2.GetDiskPath(), 'fX')).st_ino,
                      os.lstat(os.path.join(backup3.GetDiskPath(), 'fX')).st_ino)
      AssertEquals(os.lstat(os.path.join(backup1.GetDiskPath(), 'fT')).st_ino,
                   os.lstat(os.path.join(backup2.GetDiskPath(), 'fT')).st_ino)
      AssertNotEquals(os.lstat(os.path.join(backup2.GetDiskPath(), 'fT')).st_ino,
                      os.lstat(os.path.join(backup3.GetDiskPath(), 'fT')).st_ino)

      VerifyBackupManifest(backup1, path=latest_checkpoint_path)
      VerifyBackupManifest(backup2)
      VerifyBackupManifest(backup3)

      AssertEquals(os.readlink(os.path.join(backups_manager.GetBackupsRootDir(), 'Latest')),
                   '2020-01-03-120000')

    finally:
      backups_manager.Close()

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 5 total, 2 inode hits, 1 checksummed (0b)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 6 total, 1 inode hits, 3 checksummed (0b)'])

    DoVerifyBackups(
      config,
      min_backup='2020-01-02-120000',
      expected_output=['Skipped backup Backup<2020-01-01-120000,DONE>',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 5 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 6 total, 1 inode hits, 3 checksummed (0b)'])

    DoVerifyBackups(
      config,
      max_backup='2020-01-02-120000',
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 5 total, 2 inode hits, 1 checksummed (0b)',
                       'Skipped backup Backup<2020-01-03-120000,DONE>'])


def ApplyToBackupsWithFilterMergeTest():
  with TempDir() as test_dir:
    filter_merge_path = CreateFile(
      test_dir, 'filter_merge',
      contents=['exclude *.skp',
                'include /paryes/',
                'include /paryes/**',
                'exclude *'])
    config = CreateConfig(test_dir, filter_merge_path=filter_merge_path)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    parent_yes1 = CreateDir(config.src_path, 'paryes')
    file1 = CreateFile(parent_yes1, 'f1')
    skip_file1 = CreateFile(parent_yes1, 'f1.skp')
    parent_no1 = CreateDir(config.src_path, 'parno')
    file2 = CreateFile(parent_no1, 'f2')

    checkpoint_path1 = DoCreateCheckpoint(
      config.src_path, config.checkpoints_dir, '2020-01-02-120000',
      last_checkpoint_path=latest_checkpoint_path,
      filter_merge_path=filter_merge_path,
      expected_output=['*deleting f1',
                       '*deleting fT',
                       '*deleting fX',
                       '>d+++++++ paryes',
                       '>f+++++++ paryes/f1',
                       'Transferring 2 of 3 paths (0b of 0b)'])

    skip_file2 = CreateFile(parent_yes1, 'f2.skp')
    file3 = CreateFile(parent_yes1, 'f3')

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['>f+++++++ paryes/f3',
                       'Transferring 1 of 4 paths (0b of 0b)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '*deleting fT',
                       '*deleting fX',
                       '>d+++++++ paryes',
                       '>f+++++++ paryes/f1',
                       'Verifying 2020-01-02-120000...',
                       'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
                       'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                       '>f+++++++ paryes/f3',
                       'Verifying 2020-01-03-120000...'])

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 3 total, 0 inode hits, 1 checksummed (0b)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 4 total, 1 inode hits, 1 checksummed (0b)'])


def ListBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)

    DoListBackups(config, expected_backups=['2020-01-01-120000'])


def VerifyBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')
    fileT = CreateFile(config.src_path, 'fT')
    parent1 = CreateDir(config.src_path, 'par!')
    file1 = CreateFile(parent1, 'f_\r \xc2\xa9')
    file3 = CreateFile(config.src_path, 'f3_original', contents='1' * 1025)

    checkpoint_path1 = DoCreateCheckpoint(
      config.src_path, config.checkpoints_dir, '2020-01-02-120000',
      last_checkpoint_path=latest_checkpoint_path,
      expected_output=['*deleting f1',
                       '>f+++++++ f3_original',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Transferring 3 of 6 paths (1kb of 1kb)'])

    file2 = CreateFile(parent1, 'f2')
    xattr.setxattr(fileX, 'example', 'example_value')
    SetMTime(fileT, None)
    SetMTime(parent1, None)
    DeleteFileOrDir(file3)
    file3 = CreateFile(config.src_path, 'f3_renamed', contents='1' * 1025)

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['*deleting f3_original',
                       '>f+++++++ f3_renamed',
                       '.f..t.... fT',
                       '.f......x fX',
                       '.d..t.... par!',
                       '>f+++++++ par!/f2',
                       'Transferring 5 of 7 paths (1kb of 1kb)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '>f+++++++ f3_original',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Verifying 2020-01-02-120000...',
                       'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
                       'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                       '*deleting f3_original',
                       '>f+++++++ f3_renamed',
                       '.f..t.... fT',
                       '.f......x fX',
                       '.d..t.... par!',
                       '>f+++++++ par!/f2',
                       'Verifying 2020-01-03-120000...'])

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 6 total, 2 inode hits, 2 checksummed (1kb)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 7 total, 1 inode hits, 4 checksummed (1kb)'])

    DoVerifyBackups(
      config, full=False,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 unique, 0 matching, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 3 unique, 3 matching, 2 checksummed (1kb)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 unique, 2 matching, 3 checksummed (0b)'])

    DoDeduplicateBackups(
      config,
      expected_output=[
        'De-duplicate Backup<2020-01-02-120000,DONE> onto Backup<2020-01-01-120000,DONE>...',
        'Duplicates: 1 large files',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicate path f3_renamed (size=1kb) to:',
        '  f3_original', 'Duplicates: 1 new (size=1kb); 1 large files'])

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 6 total, 2 inode hits, 2 checksummed (1kb)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 7 total, 2 inode hits, 3 checksummed (0b)'])

    DoVerifyBackups(
      config, full=False,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 unique, 0 matching, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 3 unique, 3 matching, 2 checksummed (1kb)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 unique, 2 matching, 3 checksummed (0b)'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=False, browseable=False)
    try:
      backup1 = backups_manager.GetBackup('2020-01-01-120000')
      backup1_file4 = CreateFile(backup1.GetDiskPath(), 'f4')

      backup2 = backups_manager.GetBackup('2020-01-02-120000')
      SetMTime(os.path.join(backup2.GetDiskPath(), 'par!'), None)
      xattr.setxattr(os.path.join(backup2.GetDiskPath(), 'fX'), 'example', 'example_value2')
    finally:
      backups_manager.Close()

    DoVerifyBackups(
      config,
      expected_success=False,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 5 total, 0 inode hits, 4 checksummed (0b)',
                       '>f+++++++ f4',
                       '.f......x fX',
                       '*** Error: Failed to verify backup Backup<2020-01-01-120000,DONE>'])
    DoVerifyBackups(
      config, min_backup='2020-01-02-120000',
      expected_success=False,
      expected_output=['Skipped backup Backup<2020-01-01-120000,DONE>',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 6 total, 0 inode hits, 4 checksummed (1kb)',
                       '.f......x fX',
                       '.d..t.... par!',
                       '*** Error: Failed to verify backup Backup<2020-01-02-120000,DONE>'])
    DoVerifyBackups(
      config, min_backup='2020-01-03-120000',
      expected_output=['Skipped 2 backups: Backup<2020-01-01-120000,DONE> to Backup<2020-01-02-120000,DONE>',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 7 total, 0 inode hits, 5 checksummed (1kb)'])

    DoVerifyBackups(
      config, full=False,
      expected_success=False,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 unique, 0 matching, 3 checksummed (0b)',
                       '.f......x fX',
                       '*** Error: Failed to verify backup Backup<2020-01-01-120000,DONE>'])
    DoVerifyBackups(
      config, min_backup='2020-01-02-120000', full=False,
      expected_success=False,
      expected_output=['Skipped backup Backup<2020-01-01-120000,DONE>',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 3 unique, 3 matching, 2 checksummed (1kb)',
                       '.d..t.... par!',
                       '*** Error: Failed to verify backup Backup<2020-01-02-120000,DONE>'])
    DoVerifyBackups(
      config, min_backup='2020-01-03-120000', full=False,
      expected_output=['Skipped 2 backups: Backup<2020-01-01-120000,DONE> to Backup<2020-01-02-120000,DONE>',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 unique, 2 matching, 3 checksummed (0b)'])


def AddMissingManifestsToBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    file1 = CreateFile(config.src_path, 'f1', contents='abc')
    file2 = CreateFile(config.src_path, 'f2', contents='abc')
    fileT = CreateFile(config.src_path, 'fT')

    checkpoint_path1 = DoCreateCheckpoint(
      config.src_path, config.checkpoints_dir, '2020-01-02-120000',
      last_checkpoint_path=latest_checkpoint_path,
      expected_output=['>fcs..... f1',
                       '>f+++++++ f2',
                       '*deleting fX',
                       'Transferring 2 of 4 paths (6b of 6b)'])

    file3 = CreateFile(config.src_path, 'f3', contents='abc')

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['>f+++++++ f3',
                       'Transferring 1 of 5 paths (3b of 9b)'])

    file3 = CreateFile(config.src_path, 'f3', contents='def')

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-04-120000',
      expected_output=['>fc...... f3',
                       'Transferring 1 of 5 paths (3b of 9b)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '>fcs..... f1',
                       '>f+++++++ f2',
                       '*deleting fX',
                       'Verifying 2020-01-02-120000...',
                       'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
                       'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                       '>f+++++++ f3',
                       'Verifying 2020-01-03-120000...',
                       'Cloning 2020-01-03-120000 to 2020-01-04-120000...',
                       'Applying 2020-01-04-120000 onto 2020-01-03-120000...',
                       '>fc...... f3',
                       'Verifying 2020-01-04-120000...'])

    DoAddMissingManifestsToBackups(
      config,
      expected_output=['Manifest already exists for backup Backup<2020-01-01-120000,DONE>',
                       'Manifest already exists for backup Backup<2020-01-02-120000,DONE>',
                       'Manifest already exists for backup Backup<2020-01-03-120000,DONE>',
                       'Manifest already exists for backup Backup<2020-01-04-120000,DONE>'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=False, browseable=False)
    try:
      for backup in backups_manager.GetBackupList():
        os.unlink(backup.GetManifestPath())
    finally:
      backups_manager.Close()

    DoVerifyBackups(
      config,
      expected_success=False,
      expected_output=['Verifying 2020-01-01-120000...',
                       '*** Error: Manifest file missing for Backup<2020-01-01-120000,DONE>',
                       '*** Error: Failed to verify backup Backup<2020-01-01-120000,DONE>'])

    DoAddMissingManifestsToBackups(
      config,
      expected_output=['Add missing manifest for backup Backup<2020-01-01-120000,DONE>...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Add missing manifest for backup Backup<2020-01-02-120000,DONE>...',
                       'Paths: 4 total, 1 inode hits, 2 checksummed (6b)',
                       'Add missing manifest for backup Backup<2020-01-03-120000,DONE>...',
                       'Paths: 5 total, 3 inode hits, 1 checksummed (3b)',
                       'Add missing manifest for backup Backup<2020-01-04-120000,DONE>...',
                       'Paths: 5 total, 3 inode hits, 1 checksummed (3b)'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      for backup in backups_manager.GetBackupList():
        VerifyBackupManifest(backup)
    finally:
      backups_manager.Close()

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 4 total, 1 inode hits, 2 checksummed (6b)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 total, 3 inode hits, 1 checksummed (3b)',
                       'Verifying 2020-01-04-120000...',
                       'Paths: 5 total, 3 inode hits, 1 checksummed (3b)'])


def DeDuplicateBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    file1 = CreateFile(config.src_path, 'f1', contents='1' * 1025)
    file2 = CreateFile(config.src_path, 'f2', contents='1' * 1025)
    fileT = CreateFile(config.src_path, 'fT', contents='2' * 1025)

    checkpoint_path1 = DoCreateCheckpoint(
      config.src_path, config.checkpoints_dir, '2020-01-02-120000',
      last_checkpoint_path=latest_checkpoint_path,
      expected_output=['>fcs..... f1',
                       '>f+++++++ f2',
                       '>fcs..... fT',
                       '*deleting fX',
                       'Transferring 3 of 4 paths (3kb of 3kb)'])

    file3 = CreateFile(config.src_path, 'f3', contents='1' * 1025)

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['>f+++++++ f3',
                       'Transferring 1 of 5 paths (1kb of 4kb)'])

    file3 = CreateFile(config.src_path, 'f3', contents='1' * 1025)
    SetMTime(file3, None)

    file3a = CreateFile(config.src_path, 'f3a', contents='1' * 1025)

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-04-120000',
      expected_output=['.f..t.... f3',
                       '>f+++++++ f3a',
                       'Transferring 2 of 6 paths (2kb of 5kb)'])

    file3b = CreateFile(config.src_path, 'f3b', contents='1' * 1025)

    checkpoint_path2 = DoCreateBackup(
      config, backup_name='2020-01-05-120000',
      expected_output=['>f+++++++ f3b',
                       'Transferring 1 of 7 paths (1kb of 6kb)'])

    DoApplyToBackups(
      config,
      expected_output=[
        'Cloning 2020-01-01-120000 to 2020-01-02-120000...',
        'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
        '>fcs..... f1',
        '>f+++++++ f2',
        '>fcs..... fT',
        '*deleting fX',
        'Verifying 2020-01-02-120000...',
        'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
        'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
        '>f+++++++ f3',
        'Verifying 2020-01-03-120000...',
        'Cloning 2020-01-03-120000 to 2020-01-04-120000...',
        'Applying 2020-01-04-120000 onto 2020-01-03-120000...',
        '.f..t.... f3',
        '>f+++++++ f3a',
        'Verifying 2020-01-04-120000...',
        'Cloning 2020-01-04-120000 to 2020-01-05-120000...',
        'Applying 2020-01-05-120000 onto 2020-01-04-120000...',
        '>f+++++++ f3b',
        'Verifying 2020-01-05-120000...'])

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (3kb)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 total, 3 inode hits, 1 checksummed (1kb)',
                       'Verifying 2020-01-04-120000...',
                       'Paths: 6 total, 3 inode hits, 2 checksummed (2kb)',
                       'Verifying 2020-01-05-120000...',
                       'Paths: 7 total, 5 inode hits, 1 checksummed (1kb)'])

    DoDeduplicateBackups(
      config, dry_run=True, verbose=True, min_backup='2020-01-02-120000', max_backup='2020-01-04-120000',
      expected_output=[
        'Skipped backup Backup<2020-01-01-120000,DONE>',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicate path f3 (size=1kb) to:',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 3 existing; 4 large files',
        'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
        'Similar path f3 (size=1kb) to:',
        '  .f..t.... f3',
        '  .f..t.... f1',
        '  .f..t.... f2',
        'Duplicate path f3a (size=1kb) to:',
        '  f3',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 3 existing; 1 similar (size=1kb); 5 large files',
        'Skipped backup Backup<2020-01-05-120000,DONE>'])

    DoDeduplicateBackups(
      config, dry_run=True,
      expected_output=[
        'De-duplicate Backup<2020-01-02-120000,DONE> onto Backup<2020-01-01-120000,DONE>...',
        'Duplicates: 3 large files',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicate path f3 (size=1kb) to:',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 3 existing; 4 large files',
        'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
        'Duplicate path f3a (size=1kb) to:',
        '  f3',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 3 existing; 1 similar (size=1kb); 5 large files',
        'De-duplicate Backup<2020-01-05-120000,DONE> onto Backup<2020-01-04-120000,DONE>...',
        'Duplicate path f3b (size=1kb) to:',
        '  f3a',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 5 existing; 6 large files'])

    DoDeduplicateBackups(
      config,
      expected_output=[
        'De-duplicate Backup<2020-01-02-120000,DONE> onto Backup<2020-01-01-120000,DONE>...',
        'Duplicates: 3 large files',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicate path f3 (size=1kb) to:',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 3 existing; 4 large files',
        'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
        'Duplicate path f3a (size=1kb) to:',
        '  f3',
        '  f1',
        '  f2',
        'Duplicates: 1 new (size=1kb); 3 existing; 1 similar (size=1kb); 5 large files',
        'De-duplicate Backup<2020-01-05-120000,DONE> onto Backup<2020-01-04-120000,DONE>...',
        'Duplicate path f3a (size=1kb) to:',
        '  f3a',
        '  f1',
        '  f2',
        'Duplicate path f3b (size=1kb) to:',
        '  f3a',
        '  f1',
        '  f2',
        'Duplicates: 2 new (size=2kb); 4 existing; 6 large files'])

    DoDeduplicateBackups(
      config, dry_run=True,
      expected_output=[
        'De-duplicate Backup<2020-01-02-120000,DONE> onto Backup<2020-01-01-120000,DONE>...',
        'Duplicates: 3 large files',
        'De-duplicate Backup<2020-01-03-120000,DONE> onto Backup<2020-01-02-120000,DONE>...',
        'Duplicates: 4 existing; 4 large files',
        'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
        'Duplicates: 4 existing; 1 similar (size=1kb); 5 large files',
        'De-duplicate Backup<2020-01-05-120000,DONE> onto Backup<2020-01-04-120000,DONE>...',
        'Duplicates: 6 existing; 6 large files'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      for backup in backups_manager.GetBackupList():
        VerifyBackupManifest(backup)
    finally:
      backups_manager.Close()

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 4 total, 0 inode hits, 3 checksummed (3kb)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 total, 4 inode hits, 0 checksummed (0b)',
                       'Verifying 2020-01-04-120000...',
                       'Paths: 6 total, 4 inode hits, 1 checksummed (1kb)',
                       'Verifying 2020-01-05-120000...',
                       'Paths: 7 total, 6 inode hits, 0 checksummed (0b)'])


def PruneBackupsTest():
  with SetHdiutilCompactOnBatteryAllowed(True):
    with TempDir() as test_dir:
      config = CreateConfig(test_dir)
      CreateBackupsBundle(config, create_example_content=False)

      DoPruneBackups(config, did_prune=False,
                     expected_output=['No backups needed to be pruned out of 1'])

      backups_manager = backups_lib.BackupsManager.Open(
        config, readonly=False, browseable=False)
      try:
        backups_dir = backups_manager.GetBackupsRootDir()
        for i in range(2, 15):
          backup_dir = CreateDir(backups_dir, '2020-01-%02d-120000' % i)
          metadata_dir = CreateDir(backup_dir, '.metadata')
          CreateFile(metadata_dir, lib.MANIFEST_FILENAME)
          if i in [2, 3]:
            CreateFile(metadata_dir, 'prune.SKIP')
      finally:
        backups_manager.Close()

      DoPruneBackups(
        config,
        dry_run=True,
        expected_output=[
          'Pruning Backup<2020-01-01-120000,DONE>: Backup<2020-01-02-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-04-120000,DONE>: Backup<2020-01-05-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-06-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-07-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-08-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-09-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-10-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-11-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-13-120000,DONE>: Backup<2020-01-14-120000,DONE> supersedes it...'])

      DoPruneBackups(
        config,
        expected_output=[
          'Pruning Backup<2020-01-01-120000,DONE>: Backup<2020-01-02-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-04-120000,DONE>: Backup<2020-01-05-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-06-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-07-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-08-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-09-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-10-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-11-120000,DONE>: Backup<2020-01-12-120000,DONE> supersedes it...',
          'Pruning Backup<2020-01-13-120000,DONE>: Backup<2020-01-14-120000,DONE> supersedes it...'])

      backups_manager = backups_lib.BackupsManager.Open(
        config, readonly=True, browseable=False)
      try:
        AssertLinesEqual(GetManifestItemized(GetFileTreeManifest(backups_manager.GetBackupsRootDir())),
                         ['.d....... .',
                          '.d....... 2020-01-02-120000',
                          '.d....... 2020-01-02-120000/.metadata',
                          '.f....... 2020-01-02-120000/.metadata/manifest.pbdata',
                          '.f....... 2020-01-02-120000/.metadata/prune.SKIP',
                          '.d....... 2020-01-02-120000/.metadata/superseded-2020-01-01-120000',
                          '.d....... 2020-01-03-120000',
                          '.d....... 2020-01-03-120000/.metadata',
                          '.f....... 2020-01-03-120000/.metadata/manifest.pbdata',
                          '.f....... 2020-01-03-120000/.metadata/prune.SKIP',
                          '.d....... 2020-01-05-120000',
                          '.d....... 2020-01-05-120000/.metadata',
                          '.f....... 2020-01-05-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-05-120000/.metadata/superseded-2020-01-04-120000',
                          '.f....... 2020-01-05-120000/.metadata/superseded-2020-01-04-120000/manifest.pbdata',
                          '.d....... 2020-01-12-120000',
                          '.d....... 2020-01-12-120000/.metadata',
                          '.f....... 2020-01-12-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-12-120000/.metadata/superseded-2020-01-06-120000',
                          '.f....... 2020-01-12-120000/.metadata/superseded-2020-01-06-120000/manifest.pbdata',
                          '.d....... 2020-01-12-120000/.metadata/superseded-2020-01-07-120000',
                          '.f....... 2020-01-12-120000/.metadata/superseded-2020-01-07-120000/manifest.pbdata',
                          '.d....... 2020-01-12-120000/.metadata/superseded-2020-01-08-120000',
                          '.f....... 2020-01-12-120000/.metadata/superseded-2020-01-08-120000/manifest.pbdata',
                          '.d....... 2020-01-12-120000/.metadata/superseded-2020-01-09-120000',
                          '.f....... 2020-01-12-120000/.metadata/superseded-2020-01-09-120000/manifest.pbdata',
                          '.d....... 2020-01-12-120000/.metadata/superseded-2020-01-10-120000',
                          '.f....... 2020-01-12-120000/.metadata/superseded-2020-01-10-120000/manifest.pbdata',
                          '.d....... 2020-01-12-120000/.metadata/superseded-2020-01-11-120000',
                          '.f....... 2020-01-12-120000/.metadata/superseded-2020-01-11-120000/manifest.pbdata',
                          '.d....... 2020-01-14-120000',
                          '.d....... 2020-01-14-120000/.metadata',
                          '.f....... 2020-01-14-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-14-120000/.metadata/superseded-2020-01-13-120000',
                          '.f....... 2020-01-14-120000/.metadata/superseded-2020-01-13-120000/manifest.pbdata'])
      finally:
        backups_manager.Close()


def SortedPathInfosByPathSimilarityTest():
  class PathInfoLike:
    def __init__(self, path):
      self.path = path

  def RunTest(path, paths, expected_paths):
    path_infos = [ PathInfoLike(p) for p in paths ]
    sorted_path_infos = backups_lib.SortedPathInfosByPathSimilarity(path, path_infos)
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


def CloneBackupTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')
    fileT = CreateFile(config.src_path, 'fT')
    parent1 = CreateDir(config.src_path, 'par!')
    file1 = CreateFile(parent1, 'f_\r \xc2\xa9')

    DoCreateBackup(
      config, backup_name='2020-01-02-120000',
      expected_output=['*deleting f1',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Transferring 2 of 5 paths (0b of 0b)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Verifying 2020-01-02-120000...'])

    DoCloneBackup(
      config, backup_name='DOES_NOT_EXIST',
      expected_success=False,
      expected_output=[
        re.compile('^[*]+ Error: No backup DOES_NOT_EXIST found for BackupsManager<.*>$')])

    DoCloneBackup(
      config, backup_name='2020-01-02-120000', dry_run=True,
      expected_output=['Cloning Backup<2020-01-02-120000,DONE> to Backup<2020-01-02-120000,CLONE>...'])

    DoCloneBackup(
      config, backup_name='2020-01-02-120000',
      expected_output=['Cloning Backup<2020-01-02-120000,DONE> to Backup<2020-01-02-120000,CLONE>...'])

    DoCloneBackup(
      config, backup_name='2020-01-02-120000',
      expected_success=False,
      expected_output=[
        'Cloning Backup<2020-01-02-120000,DONE> to Backup<2020-01-02-120000,CLONE>...',
        re.compile('^[*]{3} Error: directory .*/2020-01-02-120000.clone already exists$')])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      backup = backups_manager.GetBackup('2020-01-02-120000')
      backup_clone = backups_manager.StartClone(backup)
      AssertEquals(os.lstat(os.path.join(backup.GetDiskPath(), 'fX')).st_ino,
                   os.lstat(os.path.join(backup_clone.GetDiskPath(), 'fX')).st_ino)
      AssertNotEquals(os.lstat(backup.GetManifestPath()).st_ino,
                      os.lstat(backup_clone.GetManifestPath()).st_ino)

      VerifyBackupManifest(backup)
      VerifyBackupManifest(backup_clone)
    finally:
      backups_manager.Close()


def DeleteBackupTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')

    DoCreateBackup(
      config, backup_name='2020-01-02-120000',
      expected_output=['*deleting f1',
                       '*deleting fT'])

    file3 = CreateFile(config.src_path, 'f3')

    DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['>f+++++++ f3',
                       'Transferring 1 of 3 paths (0b of 0b)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '*deleting fT',
                       'Verifying 2020-01-02-120000...',
                       'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
                       'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                       '>f+++++++ f3',
                       'Verifying 2020-01-03-120000...'])

    DoListBackups(config, expected_backups=['2020-01-01-120000',
                                            '2020-01-02-120000',
                                            '2020-01-03-120000'])

    DoDeleteBackup(
      config, backup_name='DOES_NOT_EXIST',
      expected_success=False,
      expected_output=[
        re.compile('^[*]+ Error: No backup DOES_NOT_EXIST found for BackupsManager<.*>$')])

    DoDeleteBackup(
      config, backup_name='2020-01-01-120000',
      expected_output=[
        'Deleting Backup<2020-01-01-120000,DONE>: Backup<2020-01-02-120000,DONE> supersedes it...'])

    DoListBackups(config, expected_backups=['2020-01-02-120000',
                                            '2020-01-03-120000'])

    DoDeleteBackup(
      config, backup_name='2020-01-02-120000',
      expected_output=[
        'Deleting Backup<2020-01-02-120000,DONE>: Backup<2020-01-03-120000,DONE> supersedes it...'])

    DoListBackups(config, expected_backups=['2020-01-03-120000'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      AssertLinesEqual(GetManifestItemized(GetFileTreeManifest(backups_manager.GetBackupsRootDir())),
                       ['.d....... .',
                        '.d....... 2020-01-03-120000',
                        '.d....... 2020-01-03-120000/.metadata',
                        '.f....... 2020-01-03-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-03-120000/.metadata/superseded-2020-01-01-120000',
                        '.f....... 2020-01-03-120000/.metadata/superseded-2020-01-01-120000/manifest.pbdata',
                        '.d....... 2020-01-03-120000/.metadata/superseded-2020-01-02-120000',
                        '.f....... 2020-01-03-120000/.metadata/superseded-2020-01-02-120000/manifest.pbdata',
                        '.d....... 2020-01-03-120000/Root',
                        '.f....... 2020-01-03-120000/Root/f3',
                        '.f....... 2020-01-03-120000/Root/fX',
                        '.L....... Latest -> 2020-01-03-120000'])
    finally:
      backups_manager.Close()

    DoDeleteBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['Deleting Backup<2020-01-03-120000,DONE>...'])

    DoListBackups(config, expected_backups=[])


def DumpUniqueFilesInBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')
    fileT = CreateFile(config.src_path, 'fT')
    parent1 = CreateDir(config.src_path, 'par!')
    fileY = CreateFile(parent1, 'fY')
    file2 = CreateFile(parent1, 'f_\r \xc2\xa9')
    ln1 = CreateSymlink(config.src_path, 'ln1', 'INVALID')
    ln2 = CreateSymlink(config.src_path, 'ln2', 'fX')

    DoCreateBackup(
      config, backup_name='2020-01-02-120000',
      expected_output=['*deleting f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> fX',
                       '>d+++++++ par!',
                       '>f+++++++ par!/fY',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Transferring 5 of 8 paths (0b of 0b)'])

    DeleteFileOrDir(os.path.join(config.src_path, 'fX'))
    DeleteFileOrDir(fileY)
    SetMTime(fileT, None)
    file3 = CreateFile(config.src_path, 'f3')
    parent2 = CreateDir(config.src_path, 'par2')
    file4 = CreateFile(parent1, 'f4')
    file5 = CreateFile(parent2, 'f5')
    ln2 = CreateSymlink(config.src_path, 'ln2', 'fT')
    file6 = CreateFile(config.src_path, 'f6', contents='1' * 1025)
    file7 = CreateFile(config.src_path, 'f7', contents='2' * 1025)
    file8 = CreateFile(parent2, 'f8', contents='5' * 1025)

    DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '*deleting fX',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '*deleting par!/fY',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Transferring 9 of 13 paths (3kb of 3kb)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-01-120000 to 2020-01-02-120000...',
                       'Applying 2020-01-02-120000 onto 2020-01-01-120000...',
                       '*deleting f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> fX',
                       '>d+++++++ par!',
                       '>f+++++++ par!/fY',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Verifying 2020-01-02-120000...',
                       'Cloning 2020-01-02-120000 to 2020-01-03-120000...',
                       'Applying 2020-01-03-120000 onto 2020-01-02-120000...',
                       '>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '*deleting fX',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '*deleting par!/fY',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Verifying 2020-01-03-120000...'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='NAME', min_backup='MIN', max_backup='MAX',
      expected_success=False,
      expected_output=[
        '*** Error: --backup-name arg cannot be used at the same time as --min-backup or --max-backup args'])

    DoDumpUniqueFilesInBackups(
      config,
      expected_output=['Finding unique files in backup Backup<2020-01-01-120000,DONE>...',
                       'Compare to next Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f1',
                       'Paths: 1 unique (0b), 4 total',
                       'Finding unique files in backup Backup<2020-01-02-120000,DONE>...',
                       'Compare to previous Backup<2020-01-01-120000,DONE> and next Backup<2020-01-03-120000,DONE>...',
                       '.Lc...... ln2 -> fX',
                       '>f+++++++ par!/fY',
                       'Paths: 2 unique (0b), 8 total',
                       'Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Paths: 9 unique (3kb), 13 total'])

    with SetOmitUidAndGidInPathInfoToString():
      DoDumpUniqueFilesInBackups(
        config, verbose=True,
        expected_output=[
          'Finding unique files in backup Backup<2020-01-01-120000,DONE>...',
          'Compare to next Backup<2020-01-02-120000,DONE>...',
          '>f+++++++ f1',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '*deleting ln1',
          "  > symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='INVALID'",
          '*deleting ln2',
          "  > symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='fX'",
          '*deleting par!',
          '  > dir mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          '*deleting par!/fY',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '*deleting par!/f_\\r \\xc2\\xa9',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          'Paths: 1 unique (0b), 4 total',
          'Finding unique files in backup Backup<2020-01-02-120000,DONE>...',
          'Compare to previous Backup<2020-01-01-120000,DONE> and next Backup<2020-01-03-120000,DONE>...',
          '*deleting f3',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '*deleting f6',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='4e2677'",
          '*deleting f7',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='096e63'",
          '.Lc...... ln2 -> fX',
          "  = symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='fX'",
          "  > symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='fT'",
          '*deleting par!/f4',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '>f+++++++ par!/fY',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '*deleting par2',
          '  > dir mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          '*deleting par2/f5',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '*deleting par2/f8',
          "  > file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='43ee0e'",
          'Paths: 2 unique (0b), 8 total',
          'Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
          'Compare to previous Backup<2020-01-02-120000,DONE>...',
          '>f+++++++ f3',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '>f+++++++ f6',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='4e2677'",
          '>f+++++++ f7',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='096e63'",
          '.f..t.... fT',
          "  < file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          "  = file mode=33188, mtime=1600000000 (2020-09-13 05:26:40), size=0, sha256='e3b0c4'",
          '*deleting fX',
          "  < file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '.Lc...... ln2 -> fT',
          "  < symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='fX'",
          "  = symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='fT'",
          '>f+++++++ par!/f4',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '*deleting par!/fY',
          "  < file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '>d+++++++ par2',
          '  = dir mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          '>f+++++++ par2/f5',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=0, sha256='e3b0c4'",
          '>f+++++++ par2/f8',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='43ee0e'",
          'Paths: 9 unique (3kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, match_previous_only=True,
      expected_output=['Finding unique files in backup Backup<2020-01-01-120000,DONE>...',
                       '>d+++++++ .',
                       '>f+++++++ f1',
                       '>f+++++++ fT',
                       '>f+++++++ fX',
                       'Paths: 4 unique, 4 total',
                       'Finding unique files in backup Backup<2020-01-02-120000,DONE>...',
                       'Compare to previous Backup<2020-01-01-120000,DONE>...',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> fX',
                       '>d+++++++ par!',
                       '>f+++++++ par!/fY',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Paths: 5 unique (0b), 8 total',
                       'Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Paths: 9 unique (3kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-01-120000',
      expected_output=['Finding unique files in backup Backup<2020-01-01-120000,DONE>...',
                       'Compare to next Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f1',
                       'Paths: 1 unique (0b), 4 total'])

    DoDumpUniqueFilesInBackups(
      config, min_backup='2020-01-02-120000',
      expected_output=['Finding unique files in backup Backup<2020-01-02-120000,DONE>...',
                       'Compare to previous Backup<2020-01-01-120000,DONE> and next Backup<2020-01-03-120000,DONE>...',
                       '.Lc...... ln2 -> fX',
                       '>f+++++++ par!/fY',
                       'Paths: 2 unique (0b), 8 total',
                       'Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Paths: 9 unique (3kb), 13 total'])

    ln1 = CreateSymlink(config.src_path, 'ln1', 'f3')
    DeleteFileOrDir(file6)
    DeleteFileOrDir(file7)
    file6_new_dup = CreateFile(config.src_path, 'f6_new_dup', contents='2' * 1025)
    file7_renamed = CreateFile(config.src_path, 'f7_renamed', contents='2' * 1025)
    SetMTime(parent2, None)
    SetMTime(file6_new_dup, None)
    SetMTime(file7_renamed, None)
    DeleteFileOrDir(file8)
    file8 = CreateFile(parent1, 'f8', contents='5' * 1025)

    DoCreateBackup(
      config, backup_name='2020-01-04-120000',
      expected_output=['*deleting f6',
                       '>f+++++++ f6_new_dup',
                       '*deleting f7',
                       '>f+++++++ f7_renamed',
                       '.Lc...... ln1 -> f3',
                       '>f+++++++ par!/f8',
                       '.d..t.... par2',
                       '*deleting par2/f8',
                       'Transferring 5 of 13 paths (3kb of 3kb)'])

    DoApplyToBackups(
      config,
      expected_output=['Cloning 2020-01-03-120000 to 2020-01-04-120000...',
                       'Applying 2020-01-04-120000 onto 2020-01-03-120000...',
                       '*deleting f6',
                       '>f+++++++ f6_new_dup',
                       '*deleting f7',
                       '>f+++++++ f7_renamed',
                       '.Lc...... ln1 -> f3',
                       '>f+++++++ par!/f8',
                       '.d..t.... par2',
                       '*deleting par2/f8',
                       'Verifying 2020-01-04-120000...'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-03-120000',
      expected_output=['Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE> and next Backup<2020-01-04-120000,DONE>...',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '  replaced by similar: .f..t.... f7_renamed',
                       '  replaced by similar: .f..t.... f6_new_dup',
                       '.d..t.... par2',
                       '>f+++++++ par2/f8',
                       '  replaced by duplicate: .f....... par!/f8',
                       'Paths: 4 unique (3kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-03-120000',
      match_previous_only=True,
      expected_output=['Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Paths: 9 unique (3kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-03-120000',
      ignore_matching_renames=True,
      expected_output=['Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE> and next Backup<2020-01-04-120000,DONE>...',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '  replaced by similar: .f..t.... f7_renamed',
                       '  replaced by similar: .f..t.... f6_new_dup',
                       '.d..t.... par2',
                       'Paths: 3 unique (2kb), 13 total'])

    with SetUniqueFilesMaxCounts(new_max_dup_printout_count=1):
      DoDumpUniqueFilesInBackups(
        config, backup_name='2020-01-03-120000',
        ignore_matching_renames=True,
        expected_output=['Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                         'Compare to previous Backup<2020-01-02-120000,DONE> and next Backup<2020-01-04-120000,DONE>...',
                         '>f+++++++ f6',
                         '>f+++++++ f7',
                         '  replaced by similar: .f..t.... f7_renamed',
                         '  and replaced by 1 other similar',
                         '.d..t.... par2',
                         'Paths: 3 unique (2kb), 13 total'])

    with SetUniqueFilesMaxCounts(new_max_dup_find_count=1):
      DoDumpUniqueFilesInBackups(
        config, backup_name='2020-01-03-120000',
        ignore_matching_renames=True,
        expected_output=['Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                         'Compare to previous Backup<2020-01-02-120000,DONE> and next Backup<2020-01-04-120000,DONE>...',
                         '>f+++++++ f6',
                         '>f+++++++ f7',
                         '  replaced by 2 similar',
                         '.d..t.... par2',
                         'Paths: 3 unique (2kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-03-120000',
      ignore_matching_renames=True, match_previous_only=True,
      expected_output=['Finding unique files in backup Backup<2020-01-03-120000,DONE>...',
                       'Compare to previous Backup<2020-01-02-120000,DONE>...',
                       '>f+++++++ f3',
                       '>f+++++++ f6',
                       '>f+++++++ f7',
                       '.f..t.... fT',
                       '.Lc...... ln2 -> fT',
                       '>f+++++++ par!/f4',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Paths: 9 unique (3kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-04-120000',
      expected_output=['Finding unique files in backup Backup<2020-01-04-120000,DONE>...',
                       'Compare to previous Backup<2020-01-03-120000,DONE>...',
                       '>f+++++++ f6_new_dup',
                       '  replacing similar: .f..t.... f7',
                       '>f+++++++ f7_renamed',
                       '  replacing similar: .f..t.... f7',
                       '.Lc...... ln1 -> f3',
                       '>f+++++++ par!/f8',
                       '  replacing duplicate: .f....... par2/f8',
                       '.d..t.... par2',
                       'Paths: 5 unique (3kb), 13 total'])

    with SetOmitUidAndGidInPathInfoToString():
      DoDumpUniqueFilesInBackups(
        config, backup_name='2020-01-04-120000', verbose=True,
        expected_output=[
          'Finding unique files in backup Backup<2020-01-04-120000,DONE>...',
          'Compare to previous Backup<2020-01-03-120000,DONE>...',
          '*deleting f6',
          "  < file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='4e2677'",
          '>f+++++++ f6_new_dup',
          "  = file mode=33188, mtime=1600000000 (2020-09-13 05:26:40), size=1025, sha256='096e63'",
          '  replacing similar: .f..t.... f7',
          "    file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='096e63'",
          '*deleting f7',
          "  < file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='096e63'",
          '>f+++++++ f7_renamed',
          "  = file mode=33188, mtime=1600000000 (2020-09-13 05:26:40), size=1025, sha256='096e63'",
          '  replacing similar: .f..t.... f7',
          "    file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='096e63'",
          '.Lc...... ln1 -> f3',
          "  < symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='INVALID'",
          "  = symlink mode=41453, mtime=1500000000 (2017-07-13 19:40:00), link-dest='f3'",
          '>f+++++++ par!/f8',
          "  = file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='43ee0e'",
          '  replacing duplicate: .f....... par2/f8',
          "    file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='43ee0e'",
          '.d..t.... par2',
          '  < dir mode=16877, mtime=1500000000 (2017-07-13 19:40:00)',
          '  = dir mode=16877, mtime=1600000000 (2020-09-13 05:26:40)',
          '*deleting par2/f8',
          "  < file mode=33188, mtime=1500000000 (2017-07-13 19:40:00), size=1025, sha256='43ee0e'",
          'Paths: 5 unique (3kb), 13 total'])

    DoDumpUniqueFilesInBackups(
      config, backup_name='2020-01-04-120000',
      ignore_matching_renames=True,
      expected_output=['Finding unique files in backup Backup<2020-01-04-120000,DONE>...',
                       'Compare to previous Backup<2020-01-03-120000,DONE>...',
                       '>f+++++++ f6_new_dup',
                       '  replacing similar: .f..t.... f7',
                       '>f+++++++ f7_renamed',
                       '  replacing similar: .f..t.... f7',
                       '.Lc...... ln1 -> f3',
                       '.d..t.... par2',
                       'Paths: 4 unique (2kb), 13 total'])


def ExtractFromBackupsTest():
  with SetLogThrottlerLogAlways(backups_lib.PathsIntoBackupCopier.HARD_LINK_LOG_THROTTLER):
    with TempDir() as test_dir:
      config = CreateConfig(test_dir)
      CreateBackupsBundle(config)
      latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

      fileX = CreateFile(config.src_path, 'fX')
      fileT = CreateFile(config.src_path, 'fT')
      parent1 = CreateDir(config.src_path, 'par!')
      file2 = CreateFile(parent1, 'f_\r \xc2\xa9')
      ln1 = CreateSymlink(config.src_path, 'ln1', 'INVALID')
      ln2 = CreateSymlink(config.src_path, 'ln2', 'fX')

      DoCreateBackup(
        config, backup_name='2020-01-02-120000',
        expected_output=['*deleting f1',
                         '>L+++++++ ln1 -> INVALID',
                         '>L+++++++ ln2 -> fX',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f_\\r \\xc2\\xa9',
                         'Transferring 4 of 7 paths (0b of 0b)'])

      shutil.rmtree(config.src_path)
      os.mkdir(config.src_path)
      SetMTime(config.src_path)
      fileT = CreateFile(config.src_path, 'fT')

      DoCreateBackup(
        config, backup_name='2020-01-03-120000',
        expected_output=['*deleting fX',
                         '*deleting ln1',
                         '*deleting ln2',
                         '*deleting par!',
                         '*deleting par!/f_\\r \\xc2\\xa9'])

      fileX = CreateFile(config.src_path, 'fX')
      xattr.setxattr(fileX, 'example', 'example_value')
      SetMTime(fileT, None)
      file3 = CreateFile(config.src_path, 'f3')
      parent1 = CreateDir(config.src_path, 'par!')
      xattr.setxattr(parent1, 'example', 'example_value2')
      SetMTime(parent1, None)
      file2 = CreateFile(parent1, 'f_\r \xc2\xa9')
      file4 = CreateFile(parent1, 'f4')
      parent2 = CreateDir(config.src_path, 'par2')
      file5 = CreateFile(parent2, 'f5', contents='5' * 1025)
      ln2 = CreateSymlink(config.src_path, 'ln2', 'fT')
      file6 = CreateFile(config.src_path, 'f6', contents='1' * 1025)
      file7 = CreateFile(config.src_path, 'f7', contents='2' * 1025)
      file8 = CreateFile(parent2, 'f8', contents='5' * 1025)

      DoCreateBackup(
        config, backup_name='2020-01-04-120000',
        expected_output=['>f+++++++ f3',
                         '>f+++++++ f6',
                         '>f+++++++ f7',
                         '.f..t.... fT',
                         '>f+++++++ fX',
                         '>L+++++++ ln2 -> fT',
                         '>d+++++++ par!',
                         '>f+++++++ par!/f4',
                         '>f+++++++ par!/f_\\r \\xc2\\xa9',
                         '>d+++++++ par2',
                         '>f+++++++ par2/f5',
                         '>f+++++++ par2/f8',
                         'Transferring 12 of 13 paths (4kb of 4kb)'])

      xattr.setxattr(parent2, 'example', 'example_value3')
      file7 = CreateFile(config.src_path, 'f7', contents='3' * 1025)
      file9 = CreateFile(parent2, 'f9', contents='2' * 1025)

      DoCreateBackup(
        config, backup_name='2020-01-05-120000',
        expected_output=['>fc...... f7',
                         '.d......x par2',
                         '>f+++++++ par2/f9',
                         'Transferring 3 of 14 paths (2kb of 5kb)'])

      DoApplyToBackups(config, expected_output=None)

      DoExtractFromBackups(
        config,
        paths=['f1', 'fX', 'f7', 'par!', 'par3', 'par2/f5', 'ln1', 'ln2'],
        expected_success=False,
        expected_output=['*** Error: --output-image-path argument required'])

      extracted_config = backups_lib.BackupsConfig()
      extracted_config.image_path = os.path.join(test_dir, 'extracted.sparsebundle')

      DoExtractFromBackups(
        config, dry_run=True,
        paths=['f1', 'fX', 'f7', 'par!', 'par3', 'par2/f5', 'par2/f9', 'ln1', 'ln2'],
        expected_output=[
          'Extracting from 2020-01-01-120000...',
          '>f+++++++ f1',
          '>f+++++++ fX',
          'Copying paths: 3 to copy, 4 total in source, 3 total in result...',
          'Extracting from 2020-01-02-120000...',
          '*deleting f1',
          '.f....... fX',
          '>L+++++++ ln1 -> INVALID',
          '>L+++++++ ln2 -> fX',
          '>d+++++++ par!',
          '>f+++++++ par!/f_\\r \\xc2\\xa9',
          'Copying paths: 6 to copy, 1 to hard link, 7 total in source, 6 total in result...',
          'Extracting from 2020-01-03-120000...',
          'Extracting from 2020-01-04-120000...',
          '>f+++++++ f7',
          '.f......x fX',
          '*deleting ln1',
          '.Lc...... ln2 -> fT',
          '.d..t...x par!',
          '>f+++++++ par!/f4',
          '.f....... par!/f_\\r \\xc2\\xa9',
          '>f+++++++ par2/f5',
          'Copying paths: 9 to copy, 1 to hard link, 13 total in source, 9 total in result...',
          'Extracting from 2020-01-05-120000...',
          '>fc...... f7',
          '.f....... fX',
          '.L....... ln2 -> fT',
          '.d....... par!',
          '.f....... par!/f4',
          '.f....... par!/f_\\r \\xc2\\xa9',
          '.f....... par2/f5',
          '>f+++++++ par2/f9',
          '  duplicate to f7 (size=1kb)',
          'Copying paths: 10 to copy, 5 to hard link, 1 to duplicate, 14 total in source, 10 total in result...'])
      DoExtractFromBackups(
        config,
        output_image_path=extracted_config.image_path,
        paths=['f1', 'fX', 'f7', 'par!', 'par3', 'par2/f5', 'par2/f9', 'ln1', 'ln2'],
        expected_output=[
          'Extracting from 2020-01-01-120000...',
          '>f+++++++ f1',
          '>f+++++++ fX',
          'Copying paths: 3 to copy, 4 total in source, 3 total in result...',
          'Verifying 2020-01-01-120000...',
          'Extracting from 2020-01-02-120000...',
          '*deleting f1',
          '.f....... fX',
          '>L+++++++ ln1 -> INVALID',
          '>L+++++++ ln2 -> fX',
          '>d+++++++ par!',
          '>f+++++++ par!/f_\\r \\xc2\\xa9',
          'Copying paths: 6 to copy, 1 to hard link, 7 total in source, 6 total in result...',
          'Verifying 2020-01-02-120000...',
          'Extracting from 2020-01-03-120000...',
          'Extracting from 2020-01-04-120000...',
          '>f+++++++ f7',
          '.f......x fX',
          '*deleting ln1',
          '.Lc...... ln2 -> fT',
          '.d..t...x par!',
          '>f+++++++ par!/f4',
          '.f....... par!/f_\\r \\xc2\\xa9',
          '>f+++++++ par2/f5',
          'Copying paths: 9 to copy, 1 to hard link, 13 total in source, 9 total in result...',
          'Verifying 2020-01-04-120000...',
          'Extracting from 2020-01-05-120000...',
          '>fc...... f7',
          '.f....... fX',
          '.L....... ln2 -> fT',
          '.d....... par!',
          '.f....... par!/f4',
          '.f....... par!/f_\\r \\xc2\\xa9',
          '.f....... par2/f5',
          '>f+++++++ par2/f9',
          '  duplicate to f7 (size=1kb)',
          'Copying paths: 10 to copy, 5 to hard link, 1 to duplicate, 14 total in source, 10 total in result...',
          '4/5 hard links remaining (20%)...',
          '3/5 hard links remaining (40%)...',
          '2/5 hard links remaining (60%)...',
          '1/5 hard links remaining (80%)...',
          'Verifying 2020-01-05-120000...'])

      extracted_manager = backups_lib.BackupsManager.Open(
        extracted_config, readonly=True, browseable=False)
      try:
        AssertLinesEqual(GetManifestItemized(GetFileTreeManifest(extracted_manager.GetBackupsRootDir())),
                         ['.d....... .',
                          '.d....... 2020-01-01-120000',
                          '.d....... 2020-01-01-120000/.metadata',
                          '.f....... 2020-01-01-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-01-120000/Root',
                          '.f....... 2020-01-01-120000/Root/f1',
                          '.f....... 2020-01-01-120000/Root/fX',
                          '.d....... 2020-01-02-120000',
                          '.d....... 2020-01-02-120000/.metadata',
                          '.f....... 2020-01-02-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-02-120000/Root',
                          '.f....... 2020-01-02-120000/Root/fX',
                          '.L....... 2020-01-02-120000/Root/ln1 -> INVALID',
                          '.L....... 2020-01-02-120000/Root/ln2 -> fX',
                          '.d....... 2020-01-02-120000/Root/par!',
                          '.f....... 2020-01-02-120000/Root/par!/f_\\r \\xc2\\xa9',
                          '.d....... 2020-01-04-120000',
                          '.d....... 2020-01-04-120000/.metadata',
                          '.f....... 2020-01-04-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-04-120000/Root',
                          '.f....... 2020-01-04-120000/Root/f7',
                          '.f....... 2020-01-04-120000/Root/fX',
                          '.L....... 2020-01-04-120000/Root/ln2 -> fT',
                          '.d....... 2020-01-04-120000/Root/par!',
                          '.f....... 2020-01-04-120000/Root/par!/f4',
                          '.f....... 2020-01-04-120000/Root/par!/f_\\r \\xc2\\xa9',
                          '.d....... 2020-01-04-120000/Root/par2',
                          '.f....... 2020-01-04-120000/Root/par2/f5',
                          '.d....... 2020-01-05-120000',
                          '.d....... 2020-01-05-120000/.metadata',
                          '.f....... 2020-01-05-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-05-120000/Root',
                          '.f....... 2020-01-05-120000/Root/f7',
                          '.f....... 2020-01-05-120000/Root/fX',
                          '.L....... 2020-01-05-120000/Root/ln2 -> fT',
                          '.d....... 2020-01-05-120000/Root/par!',
                          '.f....... 2020-01-05-120000/Root/par!/f4',
                          '.f....... 2020-01-05-120000/Root/par!/f_\\r \\xc2\\xa9',
                          '.d....... 2020-01-05-120000/Root/par2',
                          '.f....... 2020-01-05-120000/Root/par2/f5',
                          '.f....... 2020-01-05-120000/Root/par2/f9'])

        backup4 = extracted_manager.GetBackup('2020-01-04-120000')
        backup5 = extracted_manager.GetBackup('2020-01-05-120000')
        AssertEquals(os.lstat(os.path.join(backup4.GetDiskPath(), 'par2/f5')).st_ino,
                     os.lstat(os.path.join(backup5.GetDiskPath(), 'par2/f5')).st_ino)
        AssertNotEquals(os.lstat(os.path.join(backup4.GetDiskPath(), 'f7')).st_ino,
                        os.lstat(os.path.join(backup5.GetDiskPath(), 'f7')).st_ino)
        AssertEquals(os.lstat(os.path.join(backup4.GetDiskPath(), 'f7')).st_ino,
                     os.lstat(os.path.join(backup5.GetDiskPath(), 'par2/f9')).st_ino)
      finally:
        extracted_manager.Close()


def MergeIntoBackupsTest():
  with SetLogThrottlerLogAlways(backups_lib.PathsIntoBackupCopier.HARD_LINK_LOG_THROTTLER):
    with TempDir() as test_dir:
      config = CreateConfig(test_dir)
      CreateBackupsBundle(config)
      CreateLatestManifestCheckpoint(config)

      c1_file1 = CreateFile(config.src_path, 'f1')
      c1_fileX = CreateFile(config.src_path, 'fX')
      c1_parent1 = CreateDir(config.src_path, 'par')
      c1_file2 = CreateFile(c1_parent1, 'f2')
      c1_ln1 = CreateSymlink(config.src_path, 'ln1', 'INVALID')
      c1_ln2 = CreateSymlink(config.src_path, 'ln2', 'fX')

      DoCreateBackup(
        config, backup_name='2020-01-02-120000',
        expected_output=['*deleting fT',
                         '>L+++++++ ln1 -> INVALID',
                         '>L+++++++ ln2 -> fX',
                         '>d+++++++ par',
                         '>f+++++++ par/f2',
                         'Transferring 4 of 7 paths (0b of 0b)'])

      c1_file3_to = CreateFile(c1_parent1, 'f3_to', contents='1'*1025)
      c1_file9_to = CreateFile(c1_parent1, 'f9_to', contents='4'*1025)

      DoCreateBackup(
        config, backup_name='2020-01-04-120000',
        expected_output=['>f+++++++ par/f3_to',
                         '>f+++++++ par/f9_to',
                         'Transferring 2 of 9 paths (2kb of 2kb)'])

      c1_file4_to = CreateFile(c1_parent1, 'f4_to', contents='2'*1025)
      c1_file5_both = CreateFile(c1_parent1, 'f5_both', contents='3'*1025)

      DoCreateBackup(
        config, backup_name='2020-01-05-120000',
        expected_output=['>f+++++++ par/f4_to',
                         '>f+++++++ par/f5_both',
                         'Transferring 2 of 11 paths (2kb of 4kb)'])

      DoApplyToBackups(config, expected_output=None)

      config2 = CreateConfig(test_dir, backups_filename_prefix='backups2')
      CreateBackupsBundle(config2)
      CreateLatestManifestCheckpoint(config2)

      c2_fileX = CreateFile(config2.src_path, 'fX')
      c2_parent1 = CreateDir(config2.src_path, 'par')
      c2_file2 = CreateFile(c2_parent1, 'f2')
      c2_ln1 = CreateSymlink(config2.src_path, 'ln1', 'INVALID')
      c2_ln2 = CreateSymlink(config2.src_path, 'ln2', 'fX')

      c2_file6_from = CreateFile(c2_parent1, 'f6_from', contents='4'*1025)

      DoCreateBackup(
        config2, backup_name='2020-01-03-120000',
        expected_output=['*deleting f1',
                         '*deleting fT',
                         '>L+++++++ ln1 -> INVALID',
                         '>L+++++++ ln2 -> fX',
                         '>d+++++++ par',
                         '>f+++++++ par/f2',
                         '>f+++++++ par/f6_from',
                         'Transferring 5 of 7 paths (1kb of 1kb)'])

      c2_file7_from = CreateFile(c2_parent1, 'f7_from', contents='5'*1025)
      c2_file5_both = CreateFile(c2_parent1, 'f5_both', contents='3'*1025)
      c2_file8_from = CreateFile(c2_parent1, 'f8_from', contents='1'*1025)

      DoCreateBackup(
        config2, backup_name='2020-01-05-120000',
        expected_output=['>f+++++++ par/f5_both',
                         '>f+++++++ par/f7_from',
                         '>f+++++++ par/f8_from',
                         'Transferring 3 of 10 paths (3kb of 4kb)'])

      DoApplyToBackups(config2, expected_output=None)

      backups_manager2 = backups_lib.BackupsManager.Open(config2, readonly=False)
      try:
        backup3 = backups_manager2.GetBackup('2020-01-03-120000')
        c2_metadata3_parent = CreateDir(backup3.GetMetadataPath(), 'metapar')
        CreateFile(c2_metadata3_parent, 'other_metadata.json', contents='meta')
      finally:
        backups_manager2.Close()

      DoMergeIntoBackups(
        config, dry_run=True,
        from_image_path=config2.image_path,
        expected_output=[
          'Backup 2020-01-01-120000: merging...',
          'Backup 2020-01-02-120000: existing retained.',
          'Backup 2020-01-03-120000: importing new...',
          '*deleting f1',
          '>f+++++++ par/f6_from',
          'Copying paths: 7 to copy, 2 to hard link, 7 total in source, 7 total in result...',
          'Backup 2020-01-04-120000: existing retained.',
          'Backup 2020-01-05-120000: merging...',
          '>f+++++++ par/f4_to',
          '>f+++++++ par/f5_both',
          '>f+++++++ par/f6_from',
          '  duplicate to par/f9_to (size=1kb)',
          '>f+++++++ par/f7_from',
          '>f+++++++ par/f8_from',
          '  duplicate to par/f3_to (size=1kb)',
          'Copying paths: 3 to copy, 2 to hard link, 2 to duplicate, 10 total in source, 14 total in result...'])

      DoMergeIntoBackups(
        config,
        from_image_path=config2.image_path,
        expected_output=[
          'Backup 2020-01-01-120000: merging...',
          'Backup 2020-01-02-120000: existing retained.',
          'Backup 2020-01-03-120000: importing new...',
          '*deleting f1',
          '>f+++++++ par/f6_from',
          'Copying paths: 7 to copy, 2 to hard link, 7 total in source, 7 total in result...',
          '1/2 hard links remaining (50%)...',
          'Verifying 2020-01-03-120000...',
          'Backup 2020-01-04-120000: existing retained.',
          'De-duplicate Backup<2020-01-04-120000,DONE> onto Backup<2020-01-03-120000,DONE>...',
          'Duplicate path par/f9_to (size=1kb) to:',
          '  par/f6_from',
          'Duplicates: 1 new (size=1kb); 2 large files',
          'Backup 2020-01-05-120000: merging...',
          '>f+++++++ par/f4_to',
          '>f+++++++ par/f5_both',
          '>f+++++++ par/f6_from',
          '  duplicate to par/f9_to (size=1kb)',
          '>f+++++++ par/f7_from',
          '>f+++++++ par/f8_from',
          '  duplicate to par/f3_to (size=1kb)',
          'Copying paths: 3 to copy, 2 to hard link, 2 to duplicate, 10 total in source, 14 total in result...',
          '1/2 hard links remaining (50%)...',
          'Verifying 2020-01-05-120000...'])
      DoMergeIntoBackups(
        config,
        from_image_path=config2.image_path,
        expected_output=[
          'Backup 2020-01-01-120000: merging...',
          'Backup 2020-01-02-120000: existing retained.',
          'Backup 2020-01-03-120000: merging...',
          'Backup 2020-01-04-120000: existing retained.',
          'Backup 2020-01-05-120000: merging...'])

      DoVerifyBackups(
        config,
        expected_output=None)

      backups_manager = backups_lib.BackupsManager.Open(config, readonly=True, browseable=False)
      try:
        AssertLinesEqual(GetManifestItemized(GetFileTreeManifest(backups_manager.GetBackupsRootDir())),
                         ['.d....... .',
                          '.d....... 2020-01-01-120000',
                          '.d....... 2020-01-01-120000/.metadata',
                          '.f....... 2020-01-01-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-01-120000/Root',
                          '.f....... 2020-01-01-120000/Root/f1',
                          '.f....... 2020-01-01-120000/Root/fT',
                          '.f....... 2020-01-01-120000/Root/fX',
                          '.d....... 2020-01-02-120000',
                          '.d....... 2020-01-02-120000/.metadata',
                          '.f....... 2020-01-02-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-02-120000/Root',
                          '.f....... 2020-01-02-120000/Root/f1',
                          '.f....... 2020-01-02-120000/Root/fX',
                          '.L....... 2020-01-02-120000/Root/ln1 -> INVALID',
                          '.L....... 2020-01-02-120000/Root/ln2 -> fX',
                          '.d....... 2020-01-02-120000/Root/par',
                          '.f....... 2020-01-02-120000/Root/par/f2',
                          '.d....... 2020-01-03-120000',
                          '.d....... 2020-01-03-120000/.metadata',
                          '.f....... 2020-01-03-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-03-120000/.metadata/metapar',
                          '.f....... 2020-01-03-120000/.metadata/metapar/other_metadata.json',
                          '.d....... 2020-01-03-120000/Root',
                          '.f....... 2020-01-03-120000/Root/fX',
                          '.L....... 2020-01-03-120000/Root/ln1 -> INVALID',
                          '.L....... 2020-01-03-120000/Root/ln2 -> fX',
                          '.d....... 2020-01-03-120000/Root/par',
                          '.f....... 2020-01-03-120000/Root/par/f2',
                          '.f....... 2020-01-03-120000/Root/par/f6_from',
                          '.d....... 2020-01-04-120000',
                          '.d....... 2020-01-04-120000/.metadata',
                          '.f....... 2020-01-04-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-04-120000/Root',
                          '.f....... 2020-01-04-120000/Root/f1',
                          '.f....... 2020-01-04-120000/Root/fX',
                          '.L....... 2020-01-04-120000/Root/ln1 -> INVALID',
                          '.L....... 2020-01-04-120000/Root/ln2 -> fX',
                          '.d....... 2020-01-04-120000/Root/par',
                          '.f....... 2020-01-04-120000/Root/par/f2',
                          '.f....... 2020-01-04-120000/Root/par/f3_to',
                          '.f....... 2020-01-04-120000/Root/par/f9_to',
                          '.d....... 2020-01-05-120000',
                          '.d....... 2020-01-05-120000/.metadata',
                          '.f....... 2020-01-05-120000/.metadata/manifest.pbdata',
                          '.d....... 2020-01-05-120000/Root',
                          '.f....... 2020-01-05-120000/Root/f1',
                          '.f....... 2020-01-05-120000/Root/fX',
                          '.L....... 2020-01-05-120000/Root/ln1 -> INVALID',
                          '.L....... 2020-01-05-120000/Root/ln2 -> fX',
                          '.d....... 2020-01-05-120000/Root/par',
                          '.f....... 2020-01-05-120000/Root/par/f2',
                          '.f....... 2020-01-05-120000/Root/par/f3_to',
                          '.f....... 2020-01-05-120000/Root/par/f4_to',
                          '.f....... 2020-01-05-120000/Root/par/f5_both',
                          '.f....... 2020-01-05-120000/Root/par/f6_from',
                          '.f....... 2020-01-05-120000/Root/par/f7_from',
                          '.f....... 2020-01-05-120000/Root/par/f8_from',
                          '.f....... 2020-01-05-120000/Root/par/f9_to',
                          '.L....... Latest -> 2020-01-05-120000'])
      finally:
        backups_manager.Close()

      backups_manager2 = backups_lib.BackupsManager.Open(config2, readonly=False)
      try:
        backup5 = backups_manager2.GetBackup('2020-01-05-120000')
        manifest = lib.Manifest(backup5.GetManifestPath())
        manifest.Read()

        file5_path = 'par/f5_both'
        file5_full_path = os.path.join(backup5.GetDiskPath(), file5_path)
        file7_path = 'par/f7_from'
        file7_full_path = os.path.join(backup5.GetDiskPath(), file7_path)
        xattr.setxattr(file5_full_path, 'example', 'v1')
        xattr.setxattr(file7_full_path, 'example', 'v1')

        manifest.AddPathInfo(
          lib.PathInfo.FromPath(file5_path, file5_full_path), allow_replace=True)
        manifest.AddPathInfo(
          lib.PathInfo.FromPath(file7_path, file7_full_path), allow_replace=True)
        manifest.Write()
      finally:
        backups_manager2.Close()

      DoMergeIntoBackups(
        config,
        from_image_path=config2.image_path,
        expected_success=False,
        expected_output=['Backup 2020-01-01-120000: merging...',
                         'Backup 2020-01-02-120000: existing retained.',
                         'Backup 2020-01-03-120000: merging...',
                         'Backup 2020-01-04-120000: existing retained.',
                         'Backup 2020-01-05-120000: merging...',
                         '*** Error: Failed to copy paths: found mismatched existing paths:',
                         '.f......x par/f5_both',
                         '.f......x par/f7_from'])


def DeleteInBackupsTest():
  with TempDir() as test_dir:
    config = CreateConfig(test_dir)
    CreateBackupsBundle(config)
    latest_checkpoint_path = CreateLatestManifestCheckpoint(config)

    fileX = CreateFile(config.src_path, 'fX')
    fileT = CreateFile(config.src_path, 'fT')
    parent1 = CreateDir(config.src_path, 'par!')
    file2 = CreateFile(parent1, 'f_\r \xc2\xa9')
    ln1 = CreateSymlink(config.src_path, 'ln1', 'INVALID')
    ln2 = CreateSymlink(config.src_path, 'ln2', 'fX')

    DoCreateBackup(
      config, backup_name='2020-01-02-120000',
      expected_output=['*deleting f1',
                       '>L+++++++ ln1 -> INVALID',
                       '>L+++++++ ln2 -> fX',
                       '>d+++++++ par!',
                       '>f+++++++ par!/f_\\r \\xc2\\xa9',
                       'Transferring 4 of 7 paths (0b of 0b)'])

    fileX = CreateFile(config.src_path, 'fX')
    xattr.setxattr(fileX, 'example', 'example_value')
    SetMTime(fileT, None)
    file3 = CreateFile(config.src_path, 'f3')
    xattr.setxattr(parent1, 'example', 'example_value2')
    file4 = CreateFile(parent1, 'f4')
    parent2 = CreateDir(config.src_path, 'par2')
    ln2 = CreateSymlink(config.src_path, 'ln2', 'fT')
    file5 = CreateFile(parent2, 'f5')
    file8 = CreateFile(parent2, 'f8', contents='5' * 1025)

    DoCreateBackup(
      config, backup_name='2020-01-03-120000',
      expected_output=['>f+++++++ f3',
                       '.f..t.... fT',
                       '.f......x fX',
                       '.Lc...... ln2 -> fT',
                       '.d......x par!',
                       '>f+++++++ par!/f4',
                       '>d+++++++ par2',
                       '>f+++++++ par2/f5',
                       '>f+++++++ par2/f8',
                       'Transferring 9 of 12 paths (1kb of 1kb)'])

    xattr.setxattr(parent2, 'example', 'example_value3')

    DoCreateBackup(
      config, backup_name='2020-01-04-120000',
      expected_output=['.d......x par2',
                       'Transferring 1 of 12 paths (0b of 1kb)'])

    DoApplyToBackups(config, expected_output=None)

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      AssertLinesEqual(GetManifestItemized(GetFileTreeManifest(backups_manager.GetBackupsRootDir())),
                       ['.d....... .',
                        '.d....... 2020-01-01-120000',
                        '.d....... 2020-01-01-120000/.metadata',
                        '.f....... 2020-01-01-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-01-120000/Root',
                        '.f....... 2020-01-01-120000/Root/f1',
                        '.f....... 2020-01-01-120000/Root/fT',
                        '.f....... 2020-01-01-120000/Root/fX',
                        '.d....... 2020-01-02-120000',
                        '.d....... 2020-01-02-120000/.metadata',
                        '.f....... 2020-01-02-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-02-120000/Root',
                        '.f....... 2020-01-02-120000/Root/fT',
                        '.f....... 2020-01-02-120000/Root/fX',
                        '.L....... 2020-01-02-120000/Root/ln1 -> INVALID',
                        '.L....... 2020-01-02-120000/Root/ln2 -> fX',
                        '.d....... 2020-01-02-120000/Root/par!',
                        '.f....... 2020-01-02-120000/Root/par!/f_\\r \\xc2\\xa9',
                        '.d....... 2020-01-03-120000',
                        '.d....... 2020-01-03-120000/.metadata',
                        '.f....... 2020-01-03-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-03-120000/Root',
                        '.f....... 2020-01-03-120000/Root/f3',
                        '.f....... 2020-01-03-120000/Root/fT',
                        '.f....... 2020-01-03-120000/Root/fX',
                        '.L....... 2020-01-03-120000/Root/ln1 -> INVALID',
                        '.L....... 2020-01-03-120000/Root/ln2 -> fT',
                        '.d....... 2020-01-03-120000/Root/par!',
                        '.f....... 2020-01-03-120000/Root/par!/f4',
                        '.f....... 2020-01-03-120000/Root/par!/f_\\r \\xc2\\xa9',
                        '.d....... 2020-01-03-120000/Root/par2',
                        '.f....... 2020-01-03-120000/Root/par2/f5',
                        '.f....... 2020-01-03-120000/Root/par2/f8',
                        '.d....... 2020-01-04-120000',
                        '.d....... 2020-01-04-120000/.metadata',
                        '.f....... 2020-01-04-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-04-120000/Root',
                        '.f....... 2020-01-04-120000/Root/f3',
                        '.f....... 2020-01-04-120000/Root/fT',
                        '.f....... 2020-01-04-120000/Root/fX',
                        '.L....... 2020-01-04-120000/Root/ln1 -> INVALID',
                        '.L....... 2020-01-04-120000/Root/ln2 -> fT',
                        '.d....... 2020-01-04-120000/Root/par!',
                        '.f....... 2020-01-04-120000/Root/par!/f4',
                        '.f....... 2020-01-04-120000/Root/par!/f_\\r \\xc2\\xa9',
                        '.d....... 2020-01-04-120000/Root/par2',
                        '.f....... 2020-01-04-120000/Root/par2/f5',
                        '.f....... 2020-01-04-120000/Root/par2/f8',
                        '.L....... Latest -> 2020-01-04-120000'])
    finally:
      backups_manager.Close()

    DoDeleteInBackups(
      config, dry_run=True,
      paths=['f1', 'fX', 'f7', 'par!', 'par3', 'par2/f5', 'ln1', 'ln2'],
      expected_output=['Deleting in 2020-01-01-120000...',
                       '*deleting f1',
                       '*deleting fX',
                       'Paths: 2 deleted, 4 total',
                       'Deleting in 2020-01-02-120000...',
                       '*deleting fX',
                       '*deleting ln1',
                       '*deleting ln2',
                       '*deleting par!',
                       '*deleting par!/f_\\r \\xc2\\xa9',
                       'Paths: 5 deleted, 7 total',
                       'Deleting in 2020-01-03-120000...',
                       '*deleting fX',
                       '*deleting ln1',
                       '*deleting ln2',
                       '*deleting par!',
                       '*deleting par!/f4',
                       '*deleting par!/f_\\r \\xc2\\xa9',
                       '*deleting par2/f5',
                       'Paths: 7 deleted, 12 total',
                       'Deleting in 2020-01-04-120000...',
                       '*deleting fX',
                       '*deleting ln1',
                       '*deleting ln2',
                       '*deleting par!',
                       '*deleting par!/f4',
                       '*deleting par!/f_\\r \\xc2\\xa9',
                       '*deleting par2/f5',
                       'Paths: 7 deleted, 12 total'])
    DoDeleteInBackups(
      config,
      paths=['f1', 'fX', 'f7', 'par!', 'par3', 'par2/f5', 'ln1', 'ln2'],
      expected_output=['Deleting in 2020-01-01-120000...',
                       '*deleting f1',
                       '*deleting fX',
                       'Verifying 2020-01-01-120000...',
                       'Paths: 2 deleted, 4 total',
                       'Deleting in 2020-01-02-120000...',
                       '*deleting fX',
                       '*deleting ln1',
                       '*deleting ln2',
                       '*deleting par!',
                       '*deleting par!/f_\\r \\xc2\\xa9',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 5 deleted, 7 total',
                       'Deleting in 2020-01-03-120000...',
                       '*deleting fX',
                       '*deleting ln1',
                       '*deleting ln2',
                       '*deleting par!',
                       '*deleting par!/f4',
                       '*deleting par!/f_\\r \\xc2\\xa9',
                       '*deleting par2/f5',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 7 deleted, 12 total',
                       'Deleting in 2020-01-04-120000...',
                       '*deleting fX',
                       '*deleting ln1',
                       '*deleting ln2',
                       '*deleting par!',
                       '*deleting par!/f4',
                       '*deleting par!/f_\\r \\xc2\\xa9',
                       '*deleting par2/f5',
                       'Verifying 2020-01-04-120000...',
                       'Paths: 7 deleted, 12 total'])

    DoVerifyBackups(
      config,
      expected_output=['Verifying 2020-01-01-120000...',
                       'Paths: 2 total, 0 inode hits, 1 checksummed (0b)',
                       'Verifying 2020-01-02-120000...',
                       'Paths: 2 total, 1 inode hits, 0 checksummed (0b)',
                       'Verifying 2020-01-03-120000...',
                       'Paths: 5 total, 0 inode hits, 3 checksummed (1kb)',
                       'Verifying 2020-01-04-120000...',
                       'Paths: 5 total, 3 inode hits, 0 checksummed (0b)'])

    DoDeleteInBackups(
      config, dry_run=True,
      paths=['f1', 'fX', 'f7', 'par!', 'par3', 'par2/f5', 'ln1', 'ln2'],
      expected_output=['Deleting in 2020-01-01-120000...',
                       'Deleting in 2020-01-02-120000...',
                       'Deleting in 2020-01-03-120000...',
                       'Deleting in 2020-01-04-120000...'])

    backups_manager = backups_lib.BackupsManager.Open(
      config, readonly=True, browseable=False)
    try:
      AssertLinesEqual(GetManifestItemized(GetFileTreeManifest(backups_manager.GetBackupsRootDir())),
                       ['.d....... .',
                        '.d....... 2020-01-01-120000',
                        '.d....... 2020-01-01-120000/.metadata',
                        '.f....... 2020-01-01-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-01-120000/Root',
                        '.f....... 2020-01-01-120000/Root/fT',
                        '.d....... 2020-01-02-120000',
                        '.d....... 2020-01-02-120000/.metadata',
                        '.f....... 2020-01-02-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-02-120000/Root',
                        '.f....... 2020-01-02-120000/Root/fT',
                        '.d....... 2020-01-03-120000',
                        '.d....... 2020-01-03-120000/.metadata',
                        '.f....... 2020-01-03-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-03-120000/Root',
                        '.f....... 2020-01-03-120000/Root/f3',
                        '.f....... 2020-01-03-120000/Root/fT',
                        '.d....... 2020-01-03-120000/Root/par2',
                        '.f....... 2020-01-03-120000/Root/par2/f8',
                        '.d....... 2020-01-04-120000',
                        '.d....... 2020-01-04-120000/.metadata',
                        '.f....... 2020-01-04-120000/.metadata/manifest.pbdata',
                        '.d....... 2020-01-04-120000/Root',
                        '.f....... 2020-01-04-120000/Root/f3',
                        '.f....... 2020-01-04-120000/Root/fT',
                        '.d....... 2020-01-04-120000/Root/par2',
                        '.f....... 2020-01-04-120000/Root/par2/f8',
                        '.L....... Latest -> 2020-01-04-120000'])
    finally:
      backups_manager.Close()


def PathsFromArgsTest():
  def DoPathsFromArgsTest(expected_paths, args, required=True, expected_success=True):
    parser = argparse.ArgumentParser()
    backups_lib.AddPathsArgs(parser)
    try:
      paths = backups_lib.GetPathsFromArgs(parser.parse_args(args), required=required)
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


def PathsAndPrefixMatcherTest():
  matcher = backups_lib.PathsAndPrefixMatcher([])
  AssertEquals(False, matcher.Matches('a'))
  AssertEquals(False, matcher.Matches('a/b'))
  AssertEquals(False, matcher.Matches(''))

  matcher = backups_lib.PathsAndPrefixMatcher(['a'])
  AssertEquals(True, matcher.Matches('a'))
  AssertEquals(True, matcher.Matches('a/b'))
  AssertEquals(False, matcher.Matches('/a'))
  AssertEquals(False, matcher.Matches(''))
  AssertEquals(False, matcher.Matches('ab'))
  AssertEquals(False, matcher.Matches('b'))
  AssertEquals(False, matcher.Matches('b/a'))

  matcher = backups_lib.PathsAndPrefixMatcher(['a/b'])
  AssertEquals(False, matcher.Matches('a'))
  AssertEquals(True, matcher.Matches('a/b'))
  AssertEquals(True, matcher.Matches('a/b/c'))
  AssertEquals(False, matcher.Matches('a/bc'))
  AssertEquals(False, matcher.Matches('a/bc/d'))

  matcher = backups_lib.PathsAndPrefixMatcher(['a/b', 'a'])
  AssertEquals(True, matcher.Matches('a'))
  AssertEquals(False, matcher.Matches('ab'))
  AssertEquals(True, matcher.Matches('a/b'))
  AssertEquals(True, matcher.Matches('a/b/c'))
  AssertEquals(True, matcher.Matches('a/bc'))
  AssertEquals(True, matcher.Matches('a/bc/d'))
  AssertEquals(False, matcher.Matches('b'))


def Test(tests=[]):
  if not tests or 'ApplyToBackupsTest' in tests:
    ApplyToBackupsTest()
  if not tests or 'ApplyToBackupsWithFilterMergeTest' in tests:
    ApplyToBackupsWithFilterMergeTest()
  if not tests or 'ListBackupsTest' in tests:
    ListBackupsTest()
  if not tests or 'VerifyBackupsTest' in tests:
    VerifyBackupsTest()
  if not tests or 'AddMissingManifestsToBackupsTest' in tests:
    AddMissingManifestsToBackupsTest()
  if not tests or 'DeDuplicateBackupsTest' in tests:
    DeDuplicateBackupsTest()
  if not tests or 'PruneBackupsTest' in tests:
    PruneBackupsTest()
  if not tests or 'SortedPathInfosByPathSimilarityTest' in tests:
    SortedPathInfosByPathSimilarityTest()
  if not tests or 'CloneBackupTest' in tests:
    CloneBackupTest()
  if not tests or 'DeleteBackupTest' in tests:
    DeleteBackupTest()
  if not tests or 'DumpUniqueFilesInBackupsTest' in tests:
    DumpUniqueFilesInBackupsTest()
  if not tests or 'ExtractFromBackupsTest' in tests:
    ExtractFromBackupsTest()
  if not tests or 'MergeIntoBackupsTest' in tests:
    MergeIntoBackupsTest()
  if not tests or 'DeleteInBackupsTest' in tests:
    DeleteInBackupsTest()
  if not tests or 'PathsFromArgsTest' in tests:
    PathsFromArgsTest()
  if not tests or 'PathsAndPrefixMatcherTest' in tests:
    PathsAndPrefixMatcherTest()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('tests', nargs='*', default=[])
  args = parser.parse_args()

  SetPacificTimezone()

  Test(tests=args.tests)
