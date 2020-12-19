import argparse
import binascii
import time
import os
import re
import shutil
import stat
import sys
import time

import backups_lib
import lib


COMMAND_ONEOFF_UPDATE_IGNORED_XATTRS = 'oneoff-update-ignored-xattrs'
COMMAND_ONEOFF_UPDATE_SOME_FILES = 'oneoff-update-some-files'

COMMANDS = [
  COMMAND_ONEOFF_UPDATE_IGNORED_XATTRS,
  COMMAND_ONEOFF_UPDATE_SOME_FILES,
]


def XattrHashToSummaryString(xattr_hash):
  if xattr_hash is not None:
    return binascii.b2a_hex(xattr_hash)[:6]


class OneoffIgnoredXattrsUpdater(object):
  def __init__(self, config, output, min_backup=None, max_backup=None,
               old_ignored_xattrs=None, new_ignored_xattrs=None,
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.old_ignored_xattrs = old_ignored_xattrs
    self.new_ignored_xattrs = new_ignored_xattrs
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def Apply(self):
    print >>self.output, 'Old ignored xattrs: %s' % ', '.join(
      [ lib.EscapeString(s) for s in self.old_ignored_xattrs ])
    print >>self.output, 'New ignored xattrs: %s' % ', '.join(
      [ lib.EscapeString(s) for s in self.new_ignored_xattrs ])

    backups_manager = backups_lib.BackupsManager.Open(
      self.config, readonly=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      skipped_backups = []

      escape_key_detector = lib.EscapeKeyDetector()
      try:
        for backup in backups_manager.GetBackupList():
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at backup %s' % backup
            return False

          if ((self.min_backup is not None and backup.GetName() < self.min_backup)
              or (self.max_backup is not None and backup.GetName() > self.max_backup)):
            skipped_backups.append(backup)
            continue

          backups_lib.PrintSkippedBackups(skipped_backups, self.output)
          skipped_backups = []

          self._ApplyToBackup(backup)

        backups_lib.PrintSkippedBackups(skipped_backups, self.output)
      finally:
        escape_key_detector.Shutdown()
    finally:
      backups_manager.Close()
    return True

  def _ApplyToBackup(self, backup):
    print >>self.output, 'Applying to backup %s...' % backup.GetName()

    if not os.path.exists(backup.GetManifestPath()):
      raise Exception('*** Error: Manifest file missing for %s' % backup)

    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()

    num_paths = 0
    num_xattr = 0
    num_xattr_changed = 0

    for path in manifest.GetPaths():
      num_paths += 1
      path_info = manifest.GetPathInfo(path)
      if path_info.xattr_hash is not None:
        num_xattr += 1
        full_path = os.path.join(backup.GetContentRootPath(), path)
        old_path_info = lib.PathInfo.FromPath(
          path, full_path, ignored_xattr_keys=self.old_ignored_xattrs)
        new_path_info = lib.PathInfo.FromPath(
          path, full_path, ignored_xattr_keys=self.new_ignored_xattrs)
        old_itemized = lib.PathInfo.GetItemizedDiff(path_info, old_path_info)
        assert not old_itemized.HasDiffs()
        if path_info.xattr_hash != new_path_info.xattr_hash:
          path_info.xattr_hash = new_path_info.xattr_hash
          print >>self.output, 'Updated xattr for %s from %s to %s' % (
            lib.EscapePath(path), XattrHashToSummaryString(old_path_info.xattr_hash),
            XattrHashToSummaryString(path_info.xattr_hash))
          num_xattr_changed += 1

    if num_xattr_changed:
      manifest_bak_path = lib.GetManifestBackupPath(backup.GetManifestPath())

      if not self.dry_run:
        shutil.copy(backup.GetManifestPath(), manifest_bak_path)
        assert os.path.exists(manifest_bak_path)

        manifest.Write()

    print >>self.output, 'Paths: %d paths with xattrs, %d xattrs changed, %d paths' % (
      num_xattr, num_xattr_changed, num_paths)


class OneoffSomeFilesUpdater(object):
  MAYBE_CHANGE_PATH_TEST_HOOK = None

  def __init__(self, config, output, verify=True, min_backup=None, max_backup=None,
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.verify = verify
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def Apply(self):
    backups_manager = backups_lib.BackupsManager.Open(
      self.config, readonly=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      skipped_backups = []

      escape_key_detector = lib.EscapeKeyDetector()
      try:
        for backup in backups_manager.GetBackupList():
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at backup %s' % backup
            return False

          if ((self.min_backup is not None and backup.GetName() < self.min_backup)
              or (self.max_backup is not None and backup.GetName() > self.max_backup)):
            skipped_backups.append(backup)
            continue

          backups_lib.PrintSkippedBackups(skipped_backups, self.output)
          skipped_backups = []

          self._ApplyToBackup(backup)

        backups_lib.PrintSkippedBackups(skipped_backups, self.output)
      finally:
        escape_key_detector.Shutdown()
    finally:
      backups_manager.Close()
    return True

  def _ApplyToBackup(self, backup):
    print >>self.output, 'Applying to backup %s...' % backup.GetName()

    if not os.path.exists(backup.GetManifestPath()):
      raise Exception('*** Error: Manifest file missing for %s' % backup)

    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()

    num_paths = 0
    num_changed = 0

    for path in manifest.GetPaths():
      num_paths += 1

      if self._MaybeChangePath(backup, manifest, path):
        num_changed += 1

    if num_changed and not self.dry_run:
      manifest_bak_path = lib.GetManifestBackupPath(backup.GetManifestPath())
      shutil.copy(backup.GetManifestPath(), manifest_bak_path)
      assert os.path.exists(manifest_bak_path)

      manifest.Write()

      if self.verify:
        print >>self.output, 'Verifying %s...' % backup.GetName()
        verifier = lib.ManifestVerifier(manifest, backup.GetContentRootPath(), self.output, checksum_all=False,
                                        verbose=self.verbose)
        if not verifier.Verify():
          raise Exception('*** Error: Failed to verify %s' % backup.GetName())

      os.unlink(manifest_bak_path)

    print >>self.output, 'Paths: %d changed, %d total' % (num_changed, num_paths)

  def _MaybeChangePath(self, backup, manifest, path):
    if OneoffSomeFilesUpdater.MAYBE_CHANGE_PATH_TEST_HOOK:
      return OneoffSomeFilesUpdater.MAYBE_CHANGE_PATH_TEST_HOOK(
        self, backup=backup, manifest=manifest, path=path, output=self.output, dry_run=self.dry_run)

    path_info = manifest.GetPathInfo(path)
    return False

  def _MaybeUpdateMtimeIfMatching(
      self, backup, path_info, incorrect_mtime, corrected_mtime):
    if path_info.mtime == incorrect_mtime:
      full_path = os.path.join(backup.GetContentRootPath(), path_info.path)
      print >>self.output, 'Updating mtime from %s to %s for path %s' % (
        lib.UnixTimeToSecondsString(incorrect_mtime),
        lib.UnixTimeToSecondsString(corrected_mtime),
        lib.EscapePath(path_info.path))
      lib.ClearPathHardlinks(full_path, dry_run=self.dry_run)
      if not self.dry_run:
        os.utime(full_path, (corrected_mtime, corrected_mtime))
      path_info.mtime = corrected_mtime
      return True

  def _MaybeUpdatePermissionModeIfMatching(
      self, backup, path_info, incorrect_mode, corrected_mode):
    if stat.S_IMODE(path_info.mode) == incorrect_mode:
      full_path = os.path.join(backup.GetContentRootPath(), path_info.path)
      print >>self.output, 'Updating mode from %s to %s for path %s' % (
        oct(incorrect_mode), oct(corrected_mode), lib.EscapePath(path_info.path))
      lib.ClearPathHardlinks(full_path, dry_run=self.dry_run)
      if not self.dry_run:
        os.chmod(full_path, corrected_mode)
      path_info.mode = stat.S_IFMT(path_info.mode) | corrected_mode
      return True


def DoOneoffUpdateIgnoredXattrs(args, output):
  parser = argparse.ArgumentParser()
  backups_lib.AddBackupsConfigArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--old-ignored-xattr', dest='old_ignored_xattrs', action='append', default=[])
  parser.add_argument('--new-ignored-xattr', dest='new_ignored_xattrs', action='append', default=[])
  cmd_args = parser.parse_args(args.cmd_args)

  cmd_args.old_ignored_xattrs.sort()
  cmd_args.new_ignored_xattrs.sort()

  if cmd_args.old_ignored_xattrs == cmd_args.new_ignored_xattrs:
    raise Exception('Old and new ignored xattrs should be different')

  config = backups_lib.GetBackupsConfigFromArgs(cmd_args)

  updater = OneoffIgnoredXattrsUpdater(
    config, output=output, min_backup=cmd_args.min_backup,
    max_backup=cmd_args.max_backup, old_ignored_xattrs=cmd_args.old_ignored_xattrs,
    new_ignored_xattrs=cmd_args.new_ignored_xattrs, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return updater.Apply()


def DoOneoffUpdateSomeFiles(args, output):
  parser = argparse.ArgumentParser()
  backups_lib.AddBackupsConfigArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--no-verify', dest='verify', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  config = backups_lib.GetBackupsConfigFromArgs(cmd_args)

  updater = OneoffSomeFilesUpdater(
    config, output=output, min_backup=cmd_args.min_backup,
    max_backup=cmd_args.max_backup, verify=cmd_args.verify,
    encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return updater.Apply()


def DoCommand(args, output):
  if args.command == COMMAND_ONEOFF_UPDATE_IGNORED_XATTRS:
    return DoOneoffUpdateIgnoredXattrs(args, output=output)
  elif args.command == COMMAND_ONEOFF_UPDATE_SOME_FILES:
    return DoOneoffUpdateSomeFiles(args, output=output)

  print >>output, '*** Error: Unknown command %s' % args.command
  return False
