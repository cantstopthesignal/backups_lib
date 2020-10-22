import argparse
import tempfile
import subprocess
import time
import os
import re
import shutil
import stat
import sys
import difflib

import lib


COMMAND_CREATE_BACKUP = 'create-backup'
COMMAND_APPLY_TO_BACKUPS = 'apply-to-backups'
COMMAND_CREATE_BACKUPS_IMAGE = 'create-backups-image'
COMMAND_LIST_BACKUPS = 'list-backups'
COMMAND_VERIFY_BACKUPS = 'verify-backups'
COMMAND_DEDUPLICATE_BACKUPS = 'deduplicate-backups'
COMMAND_PRUNE_BACKUPS = 'prune-backups'
COMMAND_ADD_MISSING_MANIFESTS_TO_BACKUPS = 'add-missing-manifests-to-backups'
COMMAND_CLONE_BACKUP = 'clone-backup'
COMMAND_DELETE_BACKUP = 'delete-backup'
COMMAND_DUMP_UNIQUE_FILES_IN_BACKUPS = 'dump-unique-files-in-backups'
COMMAND_EXTRACT_FROM_BACKUPS = 'extract-from-backups'
COMMAND_MERGE_INTO_BACKUPS = 'merge-into-backups'
COMMAND_DELETE_IN_BACKUPS = 'delete-in-backups'

COMMANDS = [
  COMMAND_CREATE_BACKUP,
  COMMAND_APPLY_TO_BACKUPS,
  COMMAND_CREATE_BACKUPS_IMAGE,
  COMMAND_LIST_BACKUPS,
  COMMAND_VERIFY_BACKUPS,
  COMMAND_DEDUPLICATE_BACKUPS,
  COMMAND_PRUNE_BACKUPS,
  COMMAND_ADD_MISSING_MANIFESTS_TO_BACKUPS,
  COMMAND_CLONE_BACKUP,
  COMMAND_DELETE_BACKUP,
  COMMAND_DUMP_UNIQUE_FILES_IN_BACKUPS,
  COMMAND_EXTRACT_FROM_BACKUPS,
  COMMAND_MERGE_INTO_BACKUPS,
  COMMAND_DELETE_IN_BACKUPS,
]


BACKUPS_SUBDIR = 'Backups'

DEDUP_MIN_FILE_SIZE = 100 * 1024
DEDUP_WITH_EXTRA_SHA256_ASSERT = False

UNIQUE_FILES_MAX_DUP_FIND_COUNT = 10
UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT = 5

PRUNE_SKIP_FILENAME = 'prune.SKIP'
SUPERSEDED_METADATA_PREFIX = 'superseded-'


class BackupCheckpoint(object):
  BACKUP_CHECKPOINTS_PATTERN = re.compile(
    '([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}).sparseimage')

  STATE_NEW = 'NEW'
  STATE_IN_PROGRESS = 'IN_PROGRESS'
  STATE_DONE = 'DONE'
  STATE_DELETED = 'DELETED'

  @staticmethod
  def IsMatchingPath(path):
    return BackupCheckpoint.BACKUP_CHECKPOINTS_PATTERN.match(os.path.basename(path))

  def __init__(self, path):
    self.path = path
    m = BackupCheckpoint.BACKUP_CHECKPOINTS_PATTERN.match(os.path.basename(path))
    assert m
    self.name = m.group(1)

  def __str__(self):
    return 'BackupCheckpoint<%s>' % self.name

  def __cmp__(self, other):
    return cmp(self.name, other.name)

  def GetPath(self):
    return self.path

  def GetName(self):
    return self.name


def SortedPathInfosByPathSimilarity(path, path_infos):
  sorting_list = []
  for path_info in path_infos:
    sorting_list.append(
      (-difflib.SequenceMatcher(a=path, b=path_info.path).ratio(), path_info.path, path_info))
  sorting_list.sort()
  return [ path_info for (ratio, path, path_info) in sorting_list ]


def ListBackupCheckpoints(checkpoints_dir):
  checkpoints = []
  for filename in os.listdir(checkpoints_dir):
    if BackupCheckpoint.IsMatchingPath(filename):
      checkpoints.append(BackupCheckpoint(os.path.join(checkpoints_dir, filename)))
  checkpoints.sort()
  return checkpoints


def PrintSkippedBackups(skipped_backups, output):
  if len(skipped_backups) == 1:
    print >>output, 'Skipped backup %s' % skipped_backups[0]
  elif len(skipped_backups) > 1:
    print >>output, 'Skipped %d backups: %s to %s' % (
      len(skipped_backups), skipped_backups[0], skipped_backups[-1])


class PathsIntoBackupCopier(object):
  class Result(object):
    def __init__(self):
      self.to_backup = None
      self.to_manifest = None
      self.num_copied = 0
      self.num_hard_linked = 0
      self.total_from_paths = 0
      self.total_to_paths = 0
      self.success = True

  def __init__(self, from_backup, from_manifest, to_backup_manager, to_backup, last_to_backup,
               last_to_manifest, path_matcher, output, verify_with_checksums=False, dry_run=False,
               verbose=False):
    """
    Args:
        to_backup: None to create a new backup matching from_backup's name for the contents,
            Non-None to use an existing backup to copy to.
    """

    self.from_backup = from_backup
    self.from_manifest = from_manifest
    self.to_backup_manager = to_backup_manager
    self.to_backup = to_backup
    self.last_to_backup = last_to_backup
    self.last_to_manifest = last_to_manifest
    self.path_matcher = path_matcher
    self.output = output
    self.verify_with_checksums = verify_with_checksums
    self.dry_run = dry_run
    self.verbose = verbose

  def Copy(self):
    result = PathsIntoBackupCopier.Result()
    result.to_backup = self.to_backup
    to_backup_is_new = self.to_backup is None

    if self.from_manifest is None:
      self.from_manifest = lib.Manifest(self.from_backup.GetManifestPath())
      self.from_manifest.Read()
    result.total_from_paths = self.from_manifest.GetPathCount()

    if self.last_to_backup is not None and self.last_to_manifest is None:
      self.last_to_manifest = lib.Manifest(self.last_to_backup.GetManifestPath())
      self.last_to_manifest.Read()

    if result.to_backup is not None:
      result.to_manifest = lib.Manifest(result.to_backup.GetManifestPath())
      result.to_manifest.Read()
      result.total_to_paths = result.to_manifest.GetPathCount()
    else:
      result.to_manifest = lib.Manifest()

    paths_to_copy = []
    paths_to_link = []
    mismatched_itemized = []
    all_from_files_matched = True

    for path in self.from_manifest.GetPaths():
      if self.path_matcher.Matches(path):
        path_info = self.from_manifest.GetPathInfo(path)

        existing_path_info = result.to_manifest.GetPathInfo(path)
        if existing_path_info is not None:
          onto_existing_itemized = lib.PathInfo.GetItemizedDiff(path_info, existing_path_info)
          if onto_existing_itemized.HasDiffs():
            mismatched_itemized.append(onto_existing_itemized)
          continue

        result.to_manifest.AddPathInfo(path_info.Clone())
        result.total_to_paths += 1

        if path_info.path_type == lib.PathInfo.TYPE_FILE and self.last_to_manifest is not None:
          if not lib.PathInfo.GetItemizedDiff(
              path_info, self.last_to_manifest.GetPathInfo(path)).HasDiffs():
            paths_to_link.append(path)
            continue
        paths_to_copy.append(path)
      else:
        all_from_files_matched = False

    if mismatched_itemized:
      print >>self.output, '*** Error: Failed to copy paths: found mismatched existing paths:'
      for itemized in mismatched_itemized:
        print >>self.output, itemized
      result.success = False
      return result

    paths_to_sync_set = set(paths_to_copy + paths_to_link)

    if not paths_to_sync_set:
      return result

    itemizeds = None
    if self.last_to_manifest is not None:
      itemizeds = result.to_manifest.GetDiffItemized(
        self.last_to_manifest, include_matching=not all_from_files_matched)
    else:
      itemizeds = result.to_manifest.GetItemized()
    for itemized in itemizeds:
      if (itemized.path_type == lib.PathInfo.TYPE_DIR
          and not self.path_matcher.Matches(itemized.path)):
        continue
      print >>self.output, itemized

    unreferenced_parent_dirs = set()
    for path in paths_to_sync_set:
      parent_dir = os.path.dirname(path)
      while parent_dir:
        if not result.to_manifest.HasPath(parent_dir):
          unreferenced_parent_dirs.add(parent_dir)
        parent_dir = os.path.dirname(parent_dir)
    if not result.to_manifest.HasPath('.'):
      unreferenced_parent_dirs.add('.')

    if not self.dry_run:
      if to_backup_is_new:
        assert result.to_backup is None
        result.to_backup = self.to_backup_manager.StartNew(name=self.from_backup.GetName())
        result.to_backup.SetInProgressState(dry_run=self.dry_run)
      try:
        lib.RsyncPaths(paths_to_copy, self.from_backup.GetDiskPath(), result.to_backup.GetDiskPath(),
                       output=self.output, dry_run=self.dry_run, verbose=self.verbose)

        for path in sorted(unreferenced_parent_dirs):
          extracted_full_path = os.path.join(result.to_backup.GetDiskPath(), path)
          if not os.path.lexists(extracted_full_path):
            with lib.PreserveParentMtime(extracted_full_path):
              os.mkdir(extracted_full_path)
          path_stat = os.lstat(os.path.join(self.from_backup.GetDiskPath(), path))
          os.utime(extracted_full_path, (path_stat.st_mtime, path_stat.st_mtime))
          extracted_path_info = lib.PathInfo.FromPath(path, extracted_full_path)
          assert extracted_path_info.path_type == lib.PathInfo.TYPE_DIR
          result.to_manifest.AddPathInfo(extracted_path_info)
          result.total_to_paths += 1

        for path in paths_to_link:
          last_full_path = os.path.join(self.last_to_backup.GetDiskPath(), path)
          full_path = os.path.join(result.to_backup.GetDiskPath(), path)
          with lib.PreserveParentMtime(full_path):
            os.link(last_full_path, full_path)

        result.to_manifest.SetPath(result.to_backup.GetManifestPath())
        result.to_manifest.Write()

        print >>self.output, 'Verifying %s...' % result.to_backup.GetName()
        verifier = lib.ManifestVerifier(
          result.to_manifest, result.to_backup.GetDiskPath(), self.output, checksum_all=self.verify_with_checksums,
          verbose=self.verbose)
        if not verifier.Verify():
          raise Exception('Failed to verify %s' % result.to_backup.GetName())
        if to_backup_is_new:
          result.to_backup.SetDoneState(dry_run=self.dry_run)
      except:
        if to_backup_is_new:
          result.to_backup.Delete(dry_run=self.dry_run)
        raise

    result.num_copied = len(paths_to_sync_set)
    result.num_hard_linked = len(paths_to_link)
    return result


class DeDuplicateBackupsResult(object):
  def __init__(self):
    self.num_new_dup_files = 0


def DeDuplicateBackups(backup, manifest, last_backup, last_manifest, output, min_file_size=DEDUP_MIN_FILE_SIZE,
                       escape_key_detector=None, dry_run=False, verbose=False):
  print >>output, 'De-duplicate %s onto %s...' % (backup, last_backup)

  result = DeDuplicateBackupsResult()

  if manifest is None:
    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()

  if last_manifest is None:
    last_manifest = lib.Manifest(last_backup.GetManifestPath())
    last_manifest.Read()

  sha256_to_last_pathinfos = last_manifest.CreateSha256ToPathInfosMap(
    min_file_size=min_file_size)

  num_large_files = 0
  result.num_new_dup_files = 0
  new_dup_files_total_size = 0
  num_existing_dup_files = 0
  num_similar_files = 0
  num_similar_files_total_size = 0

  for path in manifest.GetPaths():
    if escape_key_detector is not None and escape_key_detector.WasEscapePressed():
      print >>output, '*** Cancelled at path %s' % lib.EscapePath(path)
      break
    path_info = manifest.GetPathInfo(path)
    if path_info.path_type != lib.PathInfo.TYPE_FILE or path_info.size < min_file_size:
      continue
    assert path_info.sha256 is not None

    num_large_files += 1
    dup_path_infos = SortedPathInfosByPathSimilarity(
      path, sha256_to_last_pathinfos.get(path_info.sha256, []))
    if not dup_path_infos:
      continue

    full_path = os.path.join(backup.GetDiskPath(), path)
    path_info = lib.PathInfo.FromPath(path, full_path)
    assert path_info.dev_inode is not None

    already_dupped = False

    matching_dup_path_infos = []
    similar_path_infos = []
    for dup_path_info in dup_path_infos:
      dup_full_path = os.path.join(last_backup.GetDiskPath(), dup_path_info.path)
      dup_path_info = lib.PathInfo.FromPath(dup_path_info.path, dup_full_path)
      if path_info.dev_inode == dup_path_info.dev_inode:
        already_dupped = True
        break
      itemized = lib.PathInfo.GetItemizedDiff(dup_path_info, path_info, ignore_paths=True)
      if itemized.HasDiffs():
        similar_path_infos.append(dup_path_info)
        continue
      matching_dup_path_infos.append(dup_path_info)
    if already_dupped:
      num_existing_dup_files += 1
      continue
    if not matching_dup_path_infos:
      if similar_path_infos:
        if verbose:
          print >>output, 'Similar path %s (size=%s) to:' % (
            lib.EscapePath(path), lib.FileSizeToString(path_info.size))
          for similar_path_info in similar_path_infos:
            itemized = lib.PathInfo.GetItemizedDiff(similar_path_info, path_info, ignore_paths=True)
            print >>output, '  %s' % itemized
        num_similar_files += 1
        num_similar_files_total_size += path_info.size
      continue

    result.num_new_dup_files += 1
    new_dup_files_total_size += path_info.size

    print >>output, 'Duplicate path %s (size=%s) to:' % (
      lib.EscapePath(path), lib.FileSizeToString(path_info.size))
    for dup_path_info in matching_dup_path_infos:
      print >>output, '  %s' % lib.EscapePath(dup_path_info.path)

    matching_dup_path_info = matching_dup_path_infos[0]
    matching_dup_full_path = os.path.join(last_backup.GetDiskPath(), matching_dup_path_info.path)

    assert full_path != matching_dup_full_path
    if DEDUP_WITH_EXTRA_SHA256_ASSERT:
      assert lib.Sha256(full_path) == lib.Sha256(matching_dup_full_path)

    if not dry_run:
      parent_dir = os.path.dirname(full_path)
      parent_stat = os.lstat(parent_dir)
      os.unlink(full_path)
      os.link(matching_dup_full_path, full_path)
      os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime))

  output_messages = []
  if result.num_new_dup_files:
    output_messages.append(
      '%d new (size=%s)' % (result.num_new_dup_files, lib.FileSizeToString(new_dup_files_total_size)))
  if num_existing_dup_files:
    output_messages.append('%d existing' % num_existing_dup_files)
  if num_similar_files:
    output_messages.append(
      '%d similar (size=%s)' % (num_similar_files, lib.FileSizeToString(num_similar_files_total_size)))
  if num_large_files:
    output_messages.append('%d large files' % num_large_files)

  if output_messages:
    print >>output, 'Duplicates: %s' % '; '.join(output_messages)

  return result


class PathMatcher(object):
  def Matches(self, path):
    raise Exception('Must be implemented by subclass')


class MatchAllPathMatcher(PathMatcher):
  def Matches(self, path):
    return True


class PathsAndPrefixMatcher(PathMatcher):
  def __init__(self, paths):
    self.match_paths = set()
    for path in paths:
      path = os.path.normpath(path)
      if path.startswith('/') or not path:
        raise Exception('Invalid path for matcher: %s' % path)
      self.match_paths.add(path)

  def Matches(self, path):
    path = os.path.normpath(path)
    if path.startswith('/'):
      return False
    while path:
      if path in self.match_paths:
        return True
      path = os.path.dirname(path)
    return False


def AddBackupsConfigArgs(parser):
  parser.add_argument('--backups-config')
  parser.add_argument('--backups-image-path')


def GetBackupsConfigFromArgs(args):
  if args.backups_config is None:
    if args.backups_image_path is not None:
      config = BackupsConfig()
      config.image_path = os.path.normpath(args.backups_image_path)
      return config
    else:
      raise Exception('One of --backups-config or --backups-image-path arg required')
  elif args.backups_image_path is None:
    return BackupsConfig.Load(args.backups_config)
  else:
    raise Exception('At most one of --backups-config or --backups-image-path arg expected')


def AddPathsArgs(parser):
  parser.add_argument('--path', dest='paths', action='append', default=[])
  parser.add_argument('--paths-from')


def GetPathsFromArgs(args, required=True):
  paths = args.paths or []
  if args.paths_from:
    with open(args.paths_from, 'r') as f:
      for path_line in f.read().split('\n'):
        if not path_line:
          continue
        paths.append(lib.DeEscapePath(path_line))
  if required and not paths:
    raise Exception('--path args or --paths-from arg required')
  return sorted(paths)


class BackupsConfig(object):
  IMAGE_PATH = 'IMAGE_PATH'
  MOUNT_PATH = 'MOUNT_PATH'
  SRC_PATH = 'SRC_PATH'
  CHECKPOINTS_DIR = 'CHECKPOINTS_DIR'
  FILTER_MERGE_PATH = 'FILTER_MERGE_PATH'

  @staticmethod
  def Load(path):
    config = BackupsConfig(path)
    config.Read()
    return config

  def __init__(self, path=None):
    self.path = path
    self.image_path = None
    self.mount_path = None
    self.src_path = None
    self.checkpoints_dir = None
    self.filter_merge_path = None

  def SetPath(self, path):
    self.path = path

  def Read(self):
    if self.path is None:
      raise Exception('Failed to read config file: path not set')
    with open(self.path, 'r') as f:
      for line in f.read().strip().split('\n'):
        if not line:
          continue
        pieces = line.split(' ', 1)
        if pieces[0] == BackupsConfig.IMAGE_PATH:
          self.image_path = pieces[1]
        elif pieces[0] == BackupsConfig.MOUNT_PATH:
          self.mount_path = pieces[1]
        elif pieces[0] == BackupsConfig.SRC_PATH:
          self.src_path = pieces[1]
        elif pieces[0] == BackupsConfig.CHECKPOINTS_DIR:
          self.checkpoints_dir = pieces[1]
        elif pieces[0] == BackupsConfig.FILTER_MERGE_PATH:
          self.filter_merge_path = pieces[1]
        else:
          raise Exception('Unexpected config file line: %r' % line)

  def Write(self):
    if self.path is None:
      raise Exception('Failed to write config file: path not set')
    with open(self.path, 'w') as f:
      if self.image_path is not None:
        f.write('%s %s\n' % (BackupsConfig.IMAGE_PATH, self.image_path))
      if self.mount_path is not None:
        f.write('%s %s\n' % (BackupsConfig.MOUNT_PATH, self.mount_path))
      if self.src_path is not None:
        f.write('%s %s\n' % (BackupsConfig.SRC_PATH, self.src_path))
      if self.checkpoints_dir is not None:
        f.write('%s %s\n' % (BackupsConfig.CHECKPOINTS_DIR, self.checkpoints_dir))
      if self.filter_merge_path is not None:
        f.write('%s %s\n' % (BackupsConfig.FILTER_MERGE_PATH, self.filter_merge_path))


class Backup(object):
  BACKUP_NAME_PATTERN = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}')
  BACKUP_DIRNAME_PATTERN = re.compile(
      '([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6})(.inProgress)?')

  STATE_NEW = 'NEW'
  STATE_IN_PROGRESS = 'IN_PROGRESS'
  STATE_CLONE = 'CLONE'
  STATE_DONE = 'DONE'
  STATE_DELETED = 'DELETED'

  @staticmethod
  def NewName():
    return time.strftime('%Y-%m-%d-%H%M%S')

  @staticmethod
  def ForDirname(manager, dirname):
    m = Backup.BACKUP_DIRNAME_PATTERN.match(dirname)
    assert m
    name = m.group(1)
    state = Backup.STATE_DONE
    if m.group(2) is not None:
      state = Backup.STATE_IN_PROGRESS
    return Backup(manager, name, state)

  @staticmethod
  def IsBackupName(name):
    return Backup.BACKUP_NAME_PATTERN.match(name)

  @staticmethod
  def IsBackupDirname(dirname):
    return Backup.BACKUP_DIRNAME_PATTERN.match(dirname)

  def __init__(self, backup_manager, name, state):
    self.manager = backup_manager
    m = Backup.BACKUP_DIRNAME_PATTERN.match(name)
    assert m and not m.group(2)
    self.name = name
    self.state = state

  def __str__(self):
    return 'Backup<%s,%s>' % (self.name, self.state)

  def __cmp__(self, other):
    return cmp(self.name, other.name)

  def GetState(self):
    return self.state

  def GetName(self):
    return self.name

  def GetDirname(self):
    if self.state == Backup.STATE_IN_PROGRESS:
      return self.name + '.inProgress'
    if self.state == Backup.STATE_CLONE:
      return self.name + '.clone'
    return self.name

  def GetPath(self):
    return os.path.join(
        self.manager.GetBackupsRootDir(), self.GetDirname())

  def GetDiskPath(self):
    return os.path.join(self.GetPath(), 'Root')

  def GetMetadataPath(self):
    return os.path.join(self.GetPath(), '.metadata')

  def GetManifestPath(self):
    return os.path.join(self.GetMetadataPath(), lib.MANIFEST_FILENAME)

  def GetBackupTime(self):
    return int(time.mktime(time.strptime(self.name, '%Y-%m-%d-%H%M%S')))

  def SetInProgressState(self, dry_run=False):
    assert self.state == Backup.STATE_NEW
    assert not os.path.exists(self.GetPath())
    self.state = Backup.STATE_IN_PROGRESS
    assert not os.path.exists(self.GetPath())
    assert self.GetDiskPath().startswith(self.GetPath())
    if not dry_run:
      os.makedirs(self.GetPath())
    if not os.path.exists(self.GetMetadataPath()):
      if not dry_run:
        os.mkdir(self.GetMetadataPath())
    if not os.path.exists(self.GetDiskPath()):
      if not dry_run:
        os.mkdir(self.GetDiskPath())

  def SetDoneState(self, dry_run=False):
    assert self.state == Backup.STATE_IN_PROGRESS
    old_path = self.GetPath()
    if not dry_run:
      assert os.path.exists(old_path)
    self.state = Backup.STATE_DONE
    new_path = self.GetPath()
    if not dry_run:
      os.rename(old_path, new_path)

  def CopyMetadataToSupersedingBackup(self, superseding_backup, dry_run=False):
    saved_metadata_dest_path = os.path.join(
      superseding_backup.GetMetadataPath(),  '%s%s' % (SUPERSEDED_METADATA_PREFIX, self.GetName()))
    assert not os.path.exists(saved_metadata_dest_path)
    if not dry_run:
      subprocess.check_call(['cp', '-r', self.GetMetadataPath(), saved_metadata_dest_path])
      for child_filename in os.listdir(saved_metadata_dest_path):
        if child_filename.startswith(SUPERSEDED_METADATA_PREFIX):
          child_old_path = os.path.join(saved_metadata_dest_path, child_filename)
          child_new_path = os.path.join(superseding_backup.GetMetadataPath(), child_filename)
          if not os.path.lexists(child_new_path):
            os.rename(child_old_path, child_new_path)

  def Delete(self, dry_run=False):
    path = self.GetPath()
    if not dry_run:
      assert os.path.exists(path)
      delete_path = path + '.deleting'
      os.rename(path, delete_path)
      shutil.rmtree(delete_path)
    self.state = Backup.STATE_DELETED


class BackupsManager(object):
  @staticmethod
  def Open(config, encryption_manager=None, readonly=True, browseable=True, dry_run=False):
    return BackupsManager(config, encryption_manager=encryption_manager, readonly=readonly,
                          browseable=browseable, dry_run=dry_run)

  @staticmethod
  def Create(config, encrypt=True, encryption_manager=None, browseable=True, dry_run=False):
    if os.path.lexists(config.image_path):
      raise Exception('Expected %s to not exist' % config.image_path)
    lib.CreateDiskImage(config.image_path, encrypt=encrypt,
                        encryption_manager=encryption_manager, dry_run=dry_run)
    if not dry_run:
      return BackupsManager(config, encryption_manager=encryption_manager, readonly=False,
                            browseable=browseable, dry_run=dry_run)

  def __init__(self, config, encryption_manager=None, readonly=True, browseable=True, dry_run=False):
    if (not config.image_path.endswith('.sparsebundle')
        and not config.image_path.endswith('.sparseimage')):
      raise Exception('Expected a sparsebundle or sparseimage file')
    if not os.path.exists(config.image_path):
      raise Exception('Expected %s to exist' % config.image_path)
    self.config = config
    self.encryption_manager = encryption_manager
    self.readonly = readonly
    self.browseable = browseable
    self.dry_run = dry_run
    self.attacher = None
    self.backups = None
    self._Open()
    self._LoadBackupsList()

  def __str__(self):
    return 'BackupsManager<%s>' % self.GetImagePath()

  def GetConfig(self):
    return self.config

  def GetPath(self):
    return self.attacher.GetMountPoint()

  def GetImagePath(self):
    return self.config.image_path

  def GetBackupsRootDir(self):
    return os.path.join(self.GetPath(), BACKUPS_SUBDIR)

  def Close(self):
    self.attacher.Close()

  def GetBackupList(self):
    return list(self.backups)

  def GetBackup(self, name):
    for backup in self.backups:
      if backup.GetName() == name:
        return backup

  def GetLastDone(self):
    for backup in reversed(self.backups):
      if backup.GetState() == Backup.STATE_DONE:
        return backup

  def StartNew(self, name=None):
    if name is None:
      name = Backup.NewName()
    for backup in self.backups:
      if backup.GetState() == Backup.STATE_IN_PROGRESS:
        Fail('%s already in progress' % backup)
      if name == backup.GetName():
        Fail('%s already exists' % backup)
    new_backup = Backup(self, name, Backup.STATE_NEW)
    self.backups.append(new_backup)
    return new_backup

  def StartClone(self, backup):
    backup_clone = Backup(self, backup.GetName(), Backup.STATE_CLONE)
    return backup_clone

  def UpdateLatestSymlink(self, backup):
    if not backup.GetState() == Backup.STATE_DONE:
      raise Exception('Cannot set Latest symlink to unfinished backup %s' % backup)
    latest_symlink = os.path.join(self.GetBackupsRootDir(), 'Latest')
    if not self.dry_run:
      if os.path.lexists(latest_symlink):
        os.unlink(latest_symlink)
      os.symlink(backup.GetName(), latest_symlink)

  def _Open(self):
    attacher = lib.ImageAttacher.Open(
      self.GetImagePath(), mount_point=self.config.mount_path,
      encryption_manager=self.encryption_manager, readonly=(self.readonly or self.dry_run),
      browseable=self.browseable)
    try:
      self.attacher = attacher
    except:
      attacher.Close()
      raise

  def _LoadBackupsList(self):
    self.backups = []
    if os.path.isdir(self.GetBackupsRootDir()):
      for dirname in os.listdir(self.GetBackupsRootDir()):
        if Backup.IsBackupDirname(dirname):
          self.backups.append(Backup.ForDirname(self, dirname))
    self.backups.sort()


class BackupCreator:
  def __init__(self, config, output, name=None, encrypt=True, checksum_all=True,
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.name = name
    self.encrypt = encrypt
    self.checksum_all = checksum_all
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def Create(self):
    checkpoints = ListBackupCheckpoints(self.config.checkpoints_dir)
    if not checkpoints:
      print >>self.output, '*** Error: No previous checkpoints found'
      return False

    last_checkpoint = checkpoints[-1]

    basis_path = last_checkpoint.GetPath()
    basis_manifest = lib.ReadManifestFromCheckpointOrPath(
      basis_path, encryption_manager=self.encryption_manager, dry_run=self.dry_run)

    filters = list(lib.RSYNC_FILTERS)
    if self.config.filter_merge_path is not None:
      if not os.path.exists(self.config.filter_merge_path):
        raise Exception('Expected filter merge path %r to exist' % self.config.filter_merge_path)
      filters.append(lib.RsyncFilterMerge(self.config.filter_merge_path))

    creator = lib.CheckpointCreator(
      self.config.src_path, self.config.checkpoints_dir, name=self.name, output=self.output,
      basis_path=basis_path, basis_manifest=basis_manifest, dry_run=self.dry_run,
      verbose=self.verbose, checksum_all=self.checksum_all, manifest_only=False,
      encrypt=self.encrypt, encryption_manager=self.encryption_manager, filters=filters)
    return creator.Create()


class CheckpointsToBackupsApplier:
  def __init__(self, config, output, encryption_manager=None, checksum_all=True,
               dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encryption_manager = encryption_manager
    self.checksum_all = checksum_all
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def Apply(self):
    checkpoints = ListBackupCheckpoints(self.config.checkpoints_dir)
    if not checkpoints:
      print >>self.output, 'No checkpoints found'
      return True

    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      last_backup = self.manager.GetLastDone()
      if not last_backup:
        print >>self.output, '*** Error: No last backup found for %s' % self.manager
        return False
      checkpoints_to_apply = []
      for checkpoint in checkpoints:
        assert Backup.IsBackupName(checkpoint.GetName())
        if checkpoint.GetName() <= last_backup.GetName():
          continue
        test_open_checkpoint = lib.Checkpoint.Open(
          checkpoint.GetPath(), encryption_manager=self.encryption_manager, readonly=True,
          dry_run=self.dry_run)
        test_open_checkpoint.Close()
        checkpoints_to_apply.append(checkpoint)
      for checkpoint in checkpoints_to_apply:
        (success, last_backup) = self._CreateBackupFromCheckpoint(checkpoint, last_backup)
        if not success:
          return False
      if not checkpoints_to_apply:
        print >>self.output, 'No checkpoints to apply found'
        return True
      return True
    finally:
      self.manager.Close()

  def _CreateBackupFromCheckpoint(self, checkpoint, last_backup):
    new_backup = self.manager.StartNew(name=checkpoint.GetName())
    new_backup.SetInProgressState(dry_run=self.dry_run)
    try:
      if not self.dry_run:
        print >>self.output, 'Cloning %s to %s...' % (last_backup.GetName(), new_backup.GetName())
        lib.Rsync(last_backup.GetDiskPath(),
                  new_backup.GetDiskPath(),
                  output=self.output,
                  dry_run=self.dry_run,
                  verbose=self.verbose,
                  link_dest=last_backup.GetDiskPath())

      print >>self.output, 'Applying %s onto %s...' % (checkpoint.GetName(), last_backup.GetName())
      dest_root = new_backup.GetDiskPath()
      if self.dry_run:
        dest_root = last_backup.GetDiskPath()
      checkpoint_applier = lib.CheckpointApplier(
        checkpoint.GetPath(), dest_root, self.output, dry_run=self.dry_run, verbose=self.verbose,
        checksum_all=self.checksum_all, strict_replace=True, encryption_manager=self.encryption_manager)
      if not checkpoint_applier.Apply():
        print >>self.output, ('*** Error: Failed to apply %s onto %s'
                              % (checkpoint.GetName(), last_backup.GetName()))
        new_backup.Delete(dry_run=self.dry_run)
        return (False, None)

      manifest = lib.ReadManifestFromCheckpointOrPath(
        checkpoint.GetPath(), encryption_manager=self.encryption_manager, dry_run=self.dry_run)
      metadata_path = new_backup.GetMetadataPath()
      manifest.SetPath(new_backup.GetManifestPath())
      if not self.dry_run:
        if not os.path.exists(metadata_path):
          os.makedirs(metadata_path)
        manifest.Write()

      if not self.dry_run:
        print >>self.output, 'Verifying %s...' % new_backup.GetName()
        verifier = lib.ManifestVerifier(manifest, dest_root, self.output, checksum_all=self.checksum_all,
                                        verbose=self.verbose)
        if not verifier.Verify():
          print >>self.output, '*** Error: Failed to verify %s' % new_backup.GetName()
          new_backup.Delete(dry_run=self.dry_run)
          return (False, None)

      new_backup.SetDoneState(dry_run=self.dry_run)
      self.manager.UpdateLatestSymlink(new_backup)

      if self.dry_run:
        return (True, last_backup)
      else:
        return (True, new_backup)
    except:
      new_backup.Delete(dry_run=self.dry_run)
      raise


class BackupsImageCreator(object):
  def __init__(self, config, output, encrypt=True, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encrypt = encrypt
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def CreateImage(self):
    print >>self.output, 'Creating image %s...' % self.config.image_path
    manager = BackupsManager.Create(
      self.config, encrypt=self.encrypt, encryption_manager=self.encryption_manager,
      browseable=False, dry_run=self.dry_run)
    if manager is not None:
      manager.Close()
    return True


class BackupsLister(object):
  def __init__(self, config, output, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def List(self):
    backups_manager = BackupsManager.Open(
      self.config, readonly=True, browseable=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      for backup in backups_manager.GetBackupList():
        print >>self.output, backup.GetName()
    finally:
      backups_manager.Close()
    return True


class BackupsVerifier(object):
  def __init__(self, config, output, min_backup=None, max_backup=None, full=True,
               continue_on_error=False, encryption_manager=None, dry_run=False,
               verbose=False):
    self.config = config
    self.output = output
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.full = full
    self.continue_on_error = continue_on_error
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def Verify(self):
    errors_encountered = False

    backups_manager = BackupsManager.Open(
      self.config, readonly=True, browseable=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      skipped_backups = []
      last_manifest = None
      last_backup = None

      for backup in backups_manager.GetBackupList():
        if ((self.min_backup is not None and backup.GetName() < self.min_backup)
            or (self.max_backup is not None and backup.GetName() > self.max_backup)):
          skipped_backups.append(backup)
          last_manifest = None
          last_backup = backup
          continue

        PrintSkippedBackups(skipped_backups, self.output)
        skipped_backups = []

        escape_key_detector = lib.EscapeKeyDetector()
        try:
          (success, last_manifest) = self._VerifyBackup(
            backup, last_backup, last_manifest, escape_key_detector)
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at backup %s' % backup
            return False
          if not success:
            errors_encountered = True
            print >>self.output, "*** Error: Failed to verify backup %s" % backup
            if not self.continue_on_error:
              return False
        finally:
          escape_key_detector.Shutdown()
        last_backup = backup

      PrintSkippedBackups(skipped_backups, self.output)
    finally:
      backups_manager.Close()

    return not errors_encountered

  def _VerifyBackup(self, backup, last_backup, last_manifest, escape_key_detector):
    print >>self.output, 'Verifying %s...' % backup.GetName()

    if not os.path.exists(backup.GetManifestPath()):
      print >>self.output, '*** Error: Manifest file missing for %s' % backup
      return (False, None)

    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()

    if self.full:
      return self._VerifyBackupFull(backup, manifest, last_manifest, escape_key_detector)
    else:
      return self._VerifyBackupFast(
        backup, manifest, last_backup, last_manifest, escape_key_detector)

  def _VerifyBackupFull(self, backup, manifest, last_manifest, escape_key_detector):
    dev_inodes_to_sha256 = {}
    if last_manifest is not None:
      for path in last_manifest.GetPaths():
        last_path_info = last_manifest.GetPathInfo(path)
        if last_path_info.dev_inode is not None and last_path_info.sha256 is not None:
          dev_inodes_to_sha256[last_path_info.dev_inode] = last_path_info.sha256

    num_paths = 0
    num_checksummed = 0
    num_inode_hits = 0
    total_checksummed_size = 0

    new_manifest = lib.Manifest()
    file_enumerator = lib.FileEnumerator(backup.GetDiskPath(), self.output, verbose=self.verbose)
    for path in file_enumerator.Scan():
      num_paths += 1
      full_path = os.path.join(backup.GetDiskPath(), path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.path_type == lib.PathInfo.TYPE_FILE:
        assert path_info.dev_inode is not None
        path_info.sha256 = dev_inodes_to_sha256.get(path_info.dev_inode)
        if path_info.sha256 is None:
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at path %s' % lib.EscapePath(path)
            return (False, None)

          path_info.sha256 = lib.Sha256(full_path)
          num_checksummed += 1
          total_checksummed_size += path_info.size
        else:
          num_inode_hits += 1
      new_manifest.AddPathInfo(path_info)

    print >>self.output, 'Paths: %d total, %d inode hits, %d checksummed (%s)' % (
      num_paths, num_inode_hits, num_checksummed, lib.FileSizeToString(total_checksummed_size))

    itemized_results = new_manifest.GetDiffItemized(manifest)
    for itemized in itemized_results:
      print >>self.output, itemized
      if self.verbose:
        manifest_path_info = manifest.GetPathInfo(itemized.path)
        if manifest_path_info:
          print >>self.output, '<', manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True)
        new_manifest_path_info = new_manifest.GetPathInfo(itemized.path)
        if new_manifest_path_info:
          print >>self.output, '>', new_manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True)

    return (not itemized_results, new_manifest)

  def _VerifyBackupFast(self, backup, manifest, last_backup, last_manifest, escape_key_detector):
    if last_manifest is None and last_backup is not None:
      last_manifest = lib.Manifest(last_backup.GetManifestPath())
      last_manifest.Read()

    if last_manifest is not None:
      sha256_to_last_pathinfos = last_manifest.CreateSha256ToPathInfosMap()
    else:
      sha256_to_last_pathinfos = None

    num_unique = 0
    num_matching = 0
    num_checksummed = 0
    total_checksummed_size = 0

    new_manifest = lib.Manifest()
    for path in manifest.GetPaths():
      path_info = manifest.GetPathInfo(path)
      if last_manifest is not None:
        last_path_info = last_manifest.GetPathInfo(path)
        if last_path_info is not None:
          itemized = lib.PathInfo.GetItemizedDiff(path_info, last_path_info)
          if not itemized.HasDiffs():
            new_manifest.AddPathInfo(path_info.Clone())
            num_matching += 1
            continue

      num_unique += 1

      full_path = os.path.join(backup.GetDiskPath(), path)
      new_path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.path_type == lib.PathInfo.TYPE_FILE:
        if last_manifest is not None:
          assert path_info.sha256
          for dup_path_info in sha256_to_last_pathinfos.get(path_info.sha256, []):
            dup_itemized = lib.PathInfo.GetItemizedDiff(
              path_info, dup_path_info, ignore_paths=True)
            if not dup_itemized.HasDiffs():
              new_path_info.sha256 = path_info.sha256
              break
        if not new_path_info.sha256:
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at path %s' % lib.EscapePath(path)
            return (False, None)

          new_path_info.sha256 = lib.Sha256(full_path)
          num_checksummed += 1
          total_checksummed_size += new_path_info.size
      new_manifest.AddPathInfo(new_path_info)

    print >>self.output, 'Paths: %d unique, %d matching, %d checksummed (%s)' % (
      num_unique, num_matching, num_checksummed, lib.FileSizeToString(total_checksummed_size))

    itemized_results = new_manifest.GetDiffItemized(manifest)
    for itemized in itemized_results:
      print >>self.output, itemized
      if self.verbose:
        manifest_path_info = manifest.GetPathInfo(itemized.path)
        if manifest_path_info:
          print >>self.output, '<', manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True)
        new_manifest_path_info = new_manifest.GetPathInfo(itemized.path)
        if new_manifest_path_info:
          print >>self.output, '>', new_manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True)

    return (not itemized_results, new_manifest)


class BackupsDeDuplicator(object):
  def __init__(self, config, output, min_file_size=DEDUP_MIN_FILE_SIZE, min_backup=None, max_backup=None,
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.min_file_size = min_file_size
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def DeDuplicate(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      skipped_backups = []
      last_backup = None
      last_manifest = None

      for backup in self.manager.GetBackupList():
        if ((self.min_backup is not None and backup.GetName() < self.min_backup)
            or (self.max_backup is not None and backup.GetName() > self.max_backup)):
          skipped_backups.append(backup)
          last_backup = None
          last_manifest = None
          continue

        PrintSkippedBackups(skipped_backups, self.output)
        skipped_backups = []

        manifest = lib.ReadManifestFromCheckpointOrPath(
          backup.GetManifestPath(), encryption_manager=self.encryption_manager, dry_run=self.dry_run)

        if last_manifest is not None:
          escape_key_detector = lib.EscapeKeyDetector()
          try:
            DeDuplicateBackups(
              backup, manifest, last_backup, last_manifest, self.output, min_file_size=self.min_file_size,
              escape_key_detector=escape_key_detector, dry_run=self.dry_run, verbose=self.verbose)
          finally:
            escape_key_detector.Shutdown()
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at backup %s' % backup
            return False

        last_manifest = manifest
        last_backup = backup

      PrintSkippedBackups(skipped_backups, self.output)
      return True
    finally:
      self.manager.Close()


class BackupsPruner(object):
  def __init__(self, config, output, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.num_pruned = 0

  def Prune(self):
    backups_manager = BackupsManager.Open(
      self.config, readonly=False, browseable=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      self._PruneInternal(backups_manager)

      if not self.num_pruned:
        print >>self.output, 'No backups needed to be pruned out of %d' % len(backups_manager.GetBackupList())
        return True
    finally:
      backups_manager.Close()

    lib.CompactImage(backups_manager.GetImagePath(), output=self.output, dry_run=self.dry_run,
                     encryption_manager=self.encryption_manager)
    return True

  def _PruneInternal(self, backups_manager):
    time_buckets = {}

    for backup in backups_manager.GetBackupList():
      backup_time = backup.GetBackupTime()
      parsed_time = time.localtime(backup_time)
      time_bucket = backup_time - (parsed_time.tm_wday) * 24 * 60 * 60
      time_bucket -= parsed_time.tm_hour * 60 * 60
      time_bucket -= parsed_time.tm_min * 60
      time_bucket -= parsed_time.tm_sec
      if not time_bucket in time_buckets:
        time_buckets[time_bucket] = []
      time_buckets[time_bucket].append(backup)

    for time_bucket, bucket_backups in sorted(time_buckets.items()):
      if len(bucket_backups) == 1:
        continue
      backups_to_prune_pair = []
      superseding_backup = bucket_backups[-1]
      for backup in reversed(bucket_backups[:-1]):
        if not os.path.exists(backup.GetMetadataPath()):
          raise Exception('Expected path %s to exist' % backup.GetMetadataPath())
        if os.path.exists(os.path.join(
            backup.GetMetadataPath(), PRUNE_SKIP_FILENAME)):
          superseding_backup = backup
        else:
          backups_to_prune_pair.append((backup, superseding_backup))
      for backup, superseding_backup in reversed(backups_to_prune_pair):
        print >>self.output, "Pruning %s: %s supersedes it..." % (backup, superseding_backup)
        backup.CopyMetadataToSupersedingBackup(superseding_backup, dry_run=self.dry_run)
        if not self.dry_run:
          backup.Delete()
        self.num_pruned += 1


class MissingManifestsToBackupsAdder(object):
  def __init__(self, config, output, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def AddMissingManifests(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      last_manifest = None
      for backup in self.manager.GetBackupList():
        manifest_path = backup.GetManifestPath()
        if os.path.lexists(manifest_path):
          print >>self.output, 'Manifest already exists for backup %s' % backup
          last_manifest = None
          continue

        manifest = lib.Manifest(manifest_path)
        self._CreateManifestForBackup(backup, manifest, last_manifest)
        if not self.dry_run:
          manifest.Write()

        last_manifest = manifest
      return True
    finally:
      self.manager.Close()

  def _CreateManifestForBackup(self, backup, manifest, last_manifest):
    print >>self.output, 'Add missing manifest for backup %s...' % backup

    dev_inodes_to_sha256 = {}
    if last_manifest is not None:
      for path in last_manifest.GetPaths():
        last_path_info = last_manifest.GetPathInfo(path)
        if last_path_info.dev_inode is not None and last_path_info.sha256 is not None:
          dev_inodes_to_sha256[last_path_info.dev_inode] = last_path_info.sha256

    num_paths = 0
    num_checksummed = 0
    num_inode_hits = 0
    total_checksummed_size = 0

    file_enumerator = lib.FileEnumerator(backup.GetDiskPath(), self.output, verbose=self.verbose)
    for path in file_enumerator.Scan():
      num_paths += 1
      full_path = os.path.join(backup.GetDiskPath(), path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.path_type == lib.PathInfo.TYPE_FILE:
        assert path_info.dev_inode is not None
        path_info.sha256 = dev_inodes_to_sha256.get(path_info.dev_inode)
        if path_info.sha256 is None:
          path_info.sha256 = lib.Sha256(full_path)
          num_checksummed += 1
          total_checksummed_size += path_info.size
        else:
          num_inode_hits += 1
      manifest.AddPathInfo(path_info)
    print >>self.output, 'Paths: %d total, %d inode hits, %d checksummed (%s)' % (
      num_paths, num_inode_hits, num_checksummed, lib.FileSizeToString(total_checksummed_size))


class BackupCloner(object):
  def __init__(self, config, output, backup_name=None, encryption_manager=None, dry_run=False,
               verbose=False):
    self.config = config
    self.output = output
    self.backup_name = backup_name
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def CloneBackup(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      backup = self.manager.GetBackup(self.backup_name)
      if not backup:
        print >>self.output, '*** Error: No backup %s found for %s' % (self.backup_name, self.manager)
        return False
      return self._CloneBackupInternal(backup)
    finally:
      self.manager.Close()

  def _CloneBackupInternal(self, backup):
    backup_clone = self.manager.StartClone(backup)
    print >>self.output, 'Cloning %s to %s...' % (backup, backup_clone)
    if os.path.lexists(backup_clone.GetPath()):
      print >>self.output, '*** Error: directory %s already exists' % backup_clone.GetPath()
      return False
    if not self.dry_run:
      os.mkdir(backup_clone.GetPath())
    lib.Rsync(backup.GetMetadataPath(),
              backup_clone.GetMetadataPath(),
              output=self.output,
              dry_run=self.dry_run,
              verbose=self.verbose)
    lib.Rsync(backup.GetDiskPath(),
              backup_clone.GetDiskPath(),
              output=self.output,
              dry_run=self.dry_run,
              verbose=self.verbose,
              link_dest=backup.GetDiskPath())
    return True


class BackupDeleter(object):
  def __init__(self, config, output, backup_name=None, encryption_manager=None, dry_run=False,
               verbose=False):
    self.config = config
    self.output = output
    self.backup_name = backup_name
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def DeleteBackup(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      backup = self.manager.GetBackup(self.backup_name)
      if not backup:
        print >>self.output, '*** Error: No backup %s found for %s' % (self.backup_name, self.manager)
        return False
      return self._DeleteBackupInternal(backup)
    finally:
      self.manager.Close()

  def _DeleteBackupInternal(self, backup):
    backups = self.manager.GetBackupList()
    backup_index = backups.index(backup)
    superseding_backup = None
    if backup_index + 1 < len(backups):
      superseding_backup = backups[backup_index + 1]
    if superseding_backup is not None:
      print >>self.output, "Deleting %s: %s supersedes it..." % (backup, superseding_backup)
      backup.CopyMetadataToSupersedingBackup(superseding_backup, dry_run=self.dry_run)
    else:
      print >>self.output, "Deleting %s..." % backup
    if not self.dry_run:
      backup.Delete()
    return True


class UniqueFilesInBackupsDumper(object):
  def __init__(self, config, output, min_backup=None, max_backup=None, ignore_matching_renames=False,
               match_previous_only=False, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.ignore_matching_renames = ignore_matching_renames
    self.match_previous_only = match_previous_only
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def DumpUniqueFiles(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=True,
      dry_run=self.dry_run)
    try:
      backups = self.manager.GetBackupList()
      for i in range(0, len(backups)):
        backup = backups[i]

        if ((self.min_backup is not None and backup.GetName() < self.min_backup)
            or (self.max_backup is not None and backup.GetName() > self.max_backup)):
          continue

        previous_backup = i > 0 and backups[i - 1] or None
        if not self.match_previous_only:
          next_backup = i + 1 < len(backups) and backups[i + 1] or None
        else:
          next_backup = None

        if not self._DumpUniqueFilesInternal(backup, previous_backup, next_backup):
          return False
    finally:
      self.manager.Close()

    return True

  def _DumpUniqueFilesInternal(self, backup, previous_backup, next_backup):
    print >>self.output, "Finding unique files in backup %s..." % backup
    compared_to_output = []
    if previous_backup is not None:
      compared_to_output.append('previous %s' % previous_backup)
    if next_backup is not None:
      compared_to_output.append('next %s' % next_backup)
    if compared_to_output:
      print >>self.output, "Compare to %s..." % ' and '.join(compared_to_output)

    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()
    num_paths = manifest.GetPathCount()

    if previous_backup is None and next_backup is None:
      for itemized in manifest.GetItemized():
        print >>self.output, itemized
      print >>self.output, 'Paths: %d unique, %d total' % (num_paths, num_paths)
      return True

    if previous_backup is not None:
      previous_manifest = lib.Manifest(previous_backup.GetManifestPath())
      previous_manifest.Read()
      sha256_to_previous_pathinfos = previous_manifest.CreateSha256ToPathInfosMap()
    else:
      previous_manifest = None
      sha256_to_previous_pathinfos = None

    if next_backup is not None:
      next_manifest = lib.Manifest(next_backup.GetManifestPath())
      next_manifest.Read()
      sha256_to_next_pathinfos = next_manifest.CreateSha256ToPathInfosMap()
    else:
      next_manifest = None
      sha256_to_next_pathinfos = None

    if next_manifest is not None:
      compare_manifest = next_manifest
    else:
      compare_manifest = previous_manifest

    num_unique = 0
    unique_size = 0

    for itemized in manifest.GetDiffItemized(compare_manifest):
      path_info = manifest.GetPathInfo(itemized.path)
      previous_path_info = previous_manifest and previous_manifest.GetPathInfo(itemized.path) or None
      next_path_info = next_manifest and next_manifest.GetPathInfo(itemized.path) or None

      if itemized.delete_path:
        if self.verbose:
          print >>self.output, itemized
          if previous_path_info is not None:
            print >>self.output, '  <', previous_path_info.ToString(
              include_path=False, shorten_sha256=True, shorten_xattr_hash=True)
          if next_path_info is not None:
            print >>self.output, '  >', next_path_info.ToString(
              include_path=False, shorten_sha256=True, shorten_xattr_hash=True)
        continue

      if next_manifest is not None and previous_path_info is not None:
        previous_itemized = lib.PathInfo.GetItemizedDiff(path_info, previous_path_info)
        if not previous_itemized.HasDiffs():
          continue
        if itemized.new_path:
          assert not previous_itemized.new_path
          itemized = previous_itemized

      found_matching_rename = False

      dup_output_lines = []
      if itemized.new_path and path_info.path_type == lib.PathInfo.TYPE_FILE:
        for sha256_to_other_pathinfos, verb in [
            (sha256_to_next_pathinfos, 'replaced by'), (sha256_to_previous_pathinfos, 'replacing')]:
          if sha256_to_other_pathinfos is not None:
            dup_path_infos = sha256_to_other_pathinfos.get(path_info.sha256, [])
            if len(dup_path_infos) < UNIQUE_FILES_MAX_DUP_FIND_COUNT:
              dup_path_infos = SortedPathInfosByPathSimilarity(path_info.path, dup_path_infos)
            similar_dup_info = []
            dup_info = []
            for dup_path_info in dup_path_infos:
              dup_itemized = lib.PathInfo.GetItemizedDiff(
                dup_path_info, path_info, ignore_paths=True)
              if dup_itemized.HasDiffs():
                similar_dup_info.append((dup_itemized, dup_path_info))
              else:
                found_matching_rename = True
                dup_info.append((dup_itemized, dup_path_info))
            if len(dup_path_infos) < UNIQUE_FILES_MAX_DUP_FIND_COUNT:
              for dup_itemized, dup_path_info in dup_info[:UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT]:
                dup_output_lines.append('  %s duplicate: %s' % (verb, dup_itemized))
                if self.verbose:
                  dup_output_lines.append('    %s' % dup_path_info.ToString(
                    include_path=False, shorten_sha256=True, shorten_xattr_hash=True))
              if len(dup_info) > UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT:
                dup_output_lines.append('  and %s %d other duplicates' % (
                  verb, len(dup_info) - UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT))
              for dup_itemized, dup_path_info in similar_dup_info[:UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT]:
                dup_output_lines.append('  %s similar: %s' % (verb, dup_itemized))
                if self.verbose:
                  dup_output_lines.append('    %s' % dup_path_info.ToString(
                    include_path=False, shorten_sha256=True, shorten_xattr_hash=True))
              if len(similar_dup_info) > UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT:
                dup_output_lines.append('  and %s %d other similar' % (
                  verb, len(similar_dup_info) - UNIQUE_FILES_MAX_DUP_PRINTOUT_COUNT))
            else:
              if dup_info:
                dup_output_lines.append('  %s %d duplicates' % (verb, len(dup_info)))
              if similar_dup_info:
                dup_output_lines.append('  %s %d similar' % (verb, len(similar_dup_info)))

      if not self.ignore_matching_renames or not found_matching_rename:
        num_unique += 1
        if path_info.path_type == lib.PathInfo.TYPE_FILE:
          unique_size += path_info.size

        print >>self.output, itemized
        if self.verbose:
          if previous_path_info is not None:
            print >>self.output, '  <', previous_path_info.ToString(
              include_path=False, shorten_sha256=True, shorten_xattr_hash=True)
          print >>self.output, '  =', path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True)
          if next_path_info is not None:
            print >>self.output, '  >', next_path_info.ToString(
              include_path=False, shorten_sha256=True, shorten_xattr_hash=True)

        for dup_output_line in dup_output_lines:
          print >>self.output, dup_output_line

    print >>self.output, 'Paths: %d unique (%s), %d total' % (
      num_unique, lib.FileSizeToString(unique_size), num_paths)
    return True


class PathsFromBackupsExtractor(object):
  def __init__(self, config, output, output_image_path=None, paths=[],
               min_backup=None, max_backup=None, encrypt=True, encryption_manager=None,
               dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.output_image_path = output_image_path
    self.paths = paths
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.encrypt = encrypt
    self.checksum_all = True
    self.encryption_manager = encryption_manager
    self.extracted_manager = None
    self.dry_run = dry_run
    self.verbose = verbose

  def ExtractPaths(self):
    if not self.dry_run:
      if self.output_image_path is None:
        print >>self.output, '*** Error: --output-image-path argument required'
        return False
      if os.path.lexists(self.output_image_path):
        print >>self.output, '*** Error: Output image path %s already exists' % self.output_image_path
        return False
      output_config = BackupsConfig()
      output_config.image_path = self.output_image_path
      self.extracted_manager = BackupsManager.Create(
        output_config, encrypt=self.encrypt, encryption_manager=self.encryption_manager,
        browseable=False, dry_run=self.dry_run)
    success = False
    try:
      success = self._ExtractPathsInternal()
      return success
    finally:
      if self.extracted_manager is not None:
        self.extracted_manager.Close()
        if not success:
          shutil.rmtree(self.output_image_path)

  def _ExtractPathsInternal(self):
    backups_manager = BackupsManager.Open(
      self.config, readonly=True, browseable=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      skipped_backups = []
      last_extracted_backup = None
      last_extracted_manifest = None

      for backup in backups_manager.GetBackupList():
        if ((self.min_backup is not None and backup.GetName() < self.min_backup)
            or (self.max_backup is not None and backup.GetName() > self.max_backup)):
          skipped_backups.append(backup)
          continue

        PrintSkippedBackups(skipped_backups, self.output)
        skipped_backups = []

        escape_key_detector = lib.EscapeKeyDetector()
        try:
          (extracted_backup, extracted_manifest) = self._ExtractPathsFromBackup(
            backup, last_extracted_backup, last_extracted_manifest)
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at backup %s' % backup
            return False

          if extracted_backup is not None:
            last_extracted_backup = extracted_backup
          if extracted_manifest is not None:
            last_extracted_manifest = extracted_manifest
        finally:
          escape_key_detector.Shutdown()

      PrintSkippedBackups(skipped_backups, self.output)
    finally:
      backups_manager.Close()

    return True

  def _ExtractPathsFromBackup(self, backup, last_extracted_backup, last_extracted_manifest):
    print >>self.output, 'Extracting from %s...' % backup.GetName()

    path_matcher = PathsAndPrefixMatcher(self.paths)

    copier = PathsIntoBackupCopier(
      from_backup=backup, from_manifest=None, to_backup_manager=self.extracted_manager,
      to_backup=None, last_to_backup=last_extracted_backup, last_to_manifest=last_extracted_manifest,
      path_matcher=path_matcher, output=self.output, dry_run=self.dry_run, verbose=self.verbose)
    result = copier.Copy()

    if not result.success:
      raise Exception('Failed to copy paths from %s' % backup)

    if result.num_copied:
      print >>self.output, 'Paths: %d extracted, %d hard links, %d total' % (
        result.num_copied, result.num_hard_linked, result.total_from_paths)
      return (result.to_backup, result.to_manifest)

    return (None, None)


class IntoBackupsMerger(object):
  def __init__(self, config, output, from_image_path=None,
               min_backup=None, max_backup=None, encryption_manager=None,
               dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.from_image_path = from_image_path
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.checksum_all = True
    self.encryption_manager = encryption_manager
    self.backups_manager = None
    self.from_backups_manager = None
    self.dry_run = dry_run
    self.verbose = verbose

  def Merge(self):
    from_backups_config = BackupsConfig()
    from_backups_config.image_path = self.from_image_path
    self.from_backups_manager = BackupsManager.Open(
      from_backups_config, encryption_manager=self.encryption_manager,
      browseable=False, readonly=True, dry_run=self.dry_run)
    try:
      return self._MergeInternal()
    finally:
      if self.from_backups_manager is not None:
        self.from_backups_manager.Close()

  def _MergeInternal(self):
    self.backups_manager = BackupsManager.Open(
      self.config, readonly=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      skipped_from_backups = []

      from_backups = []

      for from_backup in self.from_backups_manager.GetBackupList():
        if ((self.min_backup is not None and from_backup.GetName() < self.min_backup)
            or (self.max_backup is not None and from_backup.GetName() > self.max_backup)):
          skipped_from_backups.append(backup)
          continue

        PrintSkippedBackups(skipped_from_backups, self.output)
        skipped_from_backups = []

        from_backups.append(from_backup)

      backups = self.backups_manager.GetBackupList()
      last_backup = None
      last_backup_was_modified = False

      while True:
        backup = backups and backups[0] or None
        from_backup = from_backups and from_backups[0] or None
        if backup and from_backup:
          if backup.GetName() < from_backup.GetName():
            from_backup = None
          elif backup.GetName() > from_backup.GetName():
            backup = None

        if backup:
          if from_backup:
            if not self._MergeBackup(backup, from_backup, last_backup):
              return False
            last_backup = backup
            last_backup_was_modified = True
            del backups[0]
            del from_backups[0]
            continue
          else:
            last_backup_was_modified = self._RetainBackup(
              backup, last_backup, last_backup_was_modified)
            last_backup = backup
            del backups[0]
            continue
        elif from_backup:
          last_backup = self._ImportNewBackup(from_backup, last_backup)
          last_backup_was_modified = True
          del from_backups[0]
          continue

        break

      PrintSkippedBackups(skipped_from_backups, self.output)
    finally:
      self.backups_manager.Close()

    return True

  def _MergeBackup(self, backup, from_backup, last_backup):
    print >>self.output, 'Backup %s: merging...' % backup.GetName()

    copier = PathsIntoBackupCopier(
      from_backup=from_backup, from_manifest=None, to_backup_manager=self.backups_manager,
      to_backup=backup, last_to_backup=last_backup, last_to_manifest=None,
      path_matcher=MatchAllPathMatcher(), output=self.output, dry_run=self.dry_run,
      verbose=self.verbose)
    result = copier.Copy()

    if not result.success:
      return False

    print >>self.output, 'Paths: %d copied, %d hard links, %d total in source, %d total in result' % (
      result.num_copied, result.num_hard_linked, result.total_from_paths, result.total_to_paths)

    return True

  def _RetainBackup(self, backup, last_backup, last_backup_was_modified):
    """
    Return: whether the retained backup was modified
    """

    print >>self.output, 'Backup %s: existing retained.' % backup.GetName()
    if last_backup is not None and last_backup_was_modified:
      result = DeDuplicateBackups(
        backup=backup, manifest=None, last_backup=last_backup, last_manifest=None,
        output=self.output, dry_run=self.dry_run, verbose=self.verbose)
      return result.num_new_dup_files > 0

    return False

  def _ImportNewBackup(self, from_backup, last_backup):
    print >>self.output, 'Backup %s: importing new...' % from_backup.GetName()

    copier = PathsIntoBackupCopier(
      from_backup=from_backup, from_manifest=None, to_backup_manager=self.backups_manager,
      to_backup=None, last_to_backup=last_backup, last_to_manifest=None,
      path_matcher=MatchAllPathMatcher(), output=self.output, dry_run=self.dry_run,
      verbose=self.verbose)
    result = copier.Copy()

    if not result.success or not result.num_copied:
      raise Exception('Expected to import %s' % from_backup)

    print >>self.output, 'Paths: %d copied, %d hard links, %d total' % (
      result.num_copied, result.num_hard_linked, result.total_from_paths)

    return result.to_backup


class PathsInBackupsDeleter(object):
  def __init__(self, config, output, min_backup=None, max_backup=None, paths=[],
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.paths = paths
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose

  def DeletePaths(self):
    backups_manager = BackupsManager.Open(
      self.config, readonly=False, browseable=False, encryption_manager=self.encryption_manager,
      dry_run=self.dry_run)
    try:
      skipped_backups = []
      for backup in backups_manager.GetBackupList():
        if ((self.min_backup is not None and backup.GetName() < self.min_backup)
            or (self.max_backup is not None and backup.GetName() > self.max_backup)):
          skipped_backups.append(backup)
          continue

        PrintSkippedBackups(skipped_backups, self.output)
        skipped_backups = []

        escape_key_detector = lib.EscapeKeyDetector()
        try:
          self._DeletePathsInBackup(backup, escape_key_detector)
          if escape_key_detector.WasEscapePressed():
            print >>self.output, '*** Cancelled at backup %s' % backup
            return False
        finally:
          escape_key_detector.Shutdown()

      PrintSkippedBackups(skipped_backups, self.output)
    finally:
      backups_manager.Close()

    return True

  def _DeletePathsInBackup(self, backup, escape_key_detector):
    print >>self.output, 'Deleting in %s...' % backup.GetName()

    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()
    num_paths = manifest.GetPathCount()

    paths_to_delete = []

    path_matcher = PathsAndPrefixMatcher(self.paths)
    for path in manifest.GetPaths():
      if path_matcher.Matches(path):
        path_info = manifest.RemovePathInfo(path)
        itemized = path_info.GetItemized()
        itemized.new_path = False
        itemized.delete_path = True
        print >>self.output, itemized
        paths_to_delete.append(path)

    if not paths_to_delete:
      return

    manifest_bak_path = lib.GetManifestBackupPath(backup.GetManifestPath())

    if not self.dry_run:
      shutil.copy(backup.GetManifestPath(), manifest_bak_path)
      assert os.path.exists(manifest_bak_path)

      for path in reversed(paths_to_delete):
        full_path = os.path.join(backup.GetDiskPath(), path)
        parent_dir = os.path.dirname(full_path)
        parent_stat = os.lstat(parent_dir)
        path_stat = os.lstat(full_path)
        if stat.S_ISDIR(path_stat.st_mode):
          os.rmdir(full_path)
        else:
          os.unlink(full_path)
        os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime))

      manifest.Write()

      print >>self.output, 'Verifying %s...' % backup.GetName()
      verifier = lib.ManifestVerifier(manifest, backup.GetDiskPath(), self.output, checksum_all=False,
                                      verbose=self.verbose)
      if not verifier.Verify():
        raise Exception('*** Error: Failed to verify %s' % backup.GetName())

      os.unlink(manifest_bak_path)

    print >>self.output, 'Paths: %d deleted, %d total' % (len(paths_to_delete), num_paths)


def DoCreateBackup(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-config', required=True)
  parser.add_argument('--no-checksum-all', dest='checksum_all', action='store_false')
  parser.add_argument('--no-encrypt', dest='encrypt', action='store_false')
  parser.add_argument('--backup-name')
  cmd_args = parser.parse_args(args.cmd_args)

  config = BackupsConfig.Load(cmd_args.backups_config)

  creator = BackupCreator(
    config, output=output, name=cmd_args.backup_name, encrypt=cmd_args.encrypt,
    encryption_manager=lib.EncryptionManager(), checksum_all=cmd_args.checksum_all,
    dry_run=args.dry_run, verbose=args.verbose)
  return creator.Create()


def DoApplyToBackups(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-config', required=True)
  parser.add_argument('--no-checksum-all', dest='checksum_all', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  config = BackupsConfig.Load(cmd_args.backups_config)

  applier = CheckpointsToBackupsApplier(
    config, output=output, encryption_manager=lib.EncryptionManager(),
    checksum_all=cmd_args.checksum_all, dry_run=args.dry_run, verbose=args.verbose)
  return applier.Apply()


def DoCreateBackupsImage(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-image-path', required=True)
  parser.add_argument('--no-encrypt', dest='encrypt', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  config = BackupsConfig()
  config.image_path = cmd_args.backups_image_path

  creator = BackupsImageCreator(
    config, output=output, encrypt=cmd_args.encrypt,
    encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return creator.CreateImage()


def DoListBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  lister = BackupsLister(
    config, output=output, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return lister.List()


def DoVerifyBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--no-full', dest='full', action='store_false')
  parser.add_argument('--continue-on-error', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  verifier = BackupsVerifier(
    config, output=output, min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup,
    full=cmd_args.full, continue_on_error=cmd_args.continue_on_error,
    encryption_manager=lib.EncryptionManager(), dry_run=args.dry_run, verbose=args.verbose)
  return verifier.Verify()


def DoDeDuplicateBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--min-file-size', default=DEDUP_MIN_FILE_SIZE, type=int)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  deduplicator = BackupsDeDuplicator(
    config, output=output, min_file_size=cmd_args.min_file_size, min_backup=cmd_args.min_backup,
    max_backup=cmd_args.max_backup, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return deduplicator.DeDuplicate()


def DoPruneBackups(args, output):
  parser = argparse.ArgumentParser(
    prog='... %s' % COMMAND_PRUNE_BACKUPS,
    description=("Prunes backups that are more dense than one per week, unless\n"
                 "they have the file prune.SKIP within their metadata directories.\n"
                 "The week ends Sunday evening."))
  AddBackupsConfigArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  pruner = BackupsPruner(
    config, output=output, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return pruner.Prune()


def DoAddMissingManifestsToBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  adder = MissingManifestsToBackupsAdder(
    config, output=output, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return adder.AddMissingManifests()


def DoCloneBackup(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--backup-name', required=True)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  cloner = BackupCloner(
    config, output=output, backup_name=cmd_args.backup_name,
    encryption_manager=lib.EncryptionManager(), dry_run=args.dry_run, verbose=args.verbose)
  return cloner.CloneBackup()


def DoDeleteBackup(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--backup-name', required=True)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  deleter = BackupDeleter(
    config, output=output, backup_name=cmd_args.backup_name,
    encryption_manager=lib.EncryptionManager(), dry_run=args.dry_run, verbose=args.verbose)
  return deleter.DeleteBackup()


def DoDumpUniqueFilesInBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--backup-name')
  parser.add_argument('--ignore-matching-renames', action='store_true')
  parser.add_argument('--match-previous-only', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  if cmd_args.backup_name is not None:
    if cmd_args.min_backup is not None or cmd_args.max_backup is not None:
      print >>output, ('*** Error: --backup-name arg cannot be used at the same time as '
                       '--min-backup or --max-backup args')
      return False
    cmd_args.min_backup = cmd_args.backup_name
    cmd_args.max_backup = cmd_args.backup_name

  dumper = UniqueFilesInBackupsDumper(
    config, output=output, min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup,
    ignore_matching_renames=cmd_args.ignore_matching_renames,
    match_previous_only=cmd_args.match_previous_only,
    encryption_manager=lib.EncryptionManager(), dry_run=args.dry_run, verbose=args.verbose)
  return dumper.DumpUniqueFiles()


def DoExtractFromBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  AddPathsArgs(parser)
  parser.add_argument('--output-image-path')
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--no-encrypt', dest='encrypt', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)
  paths = GetPathsFromArgs(cmd_args)

  extractor = PathsFromBackupsExtractor(
    config, output=output, output_image_path=cmd_args.output_image_path, paths=paths,
    min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup, encrypt=cmd_args.encrypt,
    encryption_manager=lib.EncryptionManager(), dry_run=args.dry_run, verbose=args.verbose)
  return extractor.ExtractPaths()


def DoMergeIntoBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--from-image-path', required=True)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  merger = IntoBackupsMerger(
    config, output=output, from_image_path=cmd_args.from_image_path,
    min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup,
    encryption_manager=lib.EncryptionManager(), dry_run=args.dry_run, verbose=args.verbose)
  return merger.Merge()


def DoDeleteInBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  AddPathsArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)
  paths = GetPathsFromArgs(cmd_args)

  deleter = PathsInBackupsDeleter(
    config, output=output, paths=paths, min_backup=cmd_args.min_backup,
    max_backup=cmd_args.max_backup, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return deleter.DeletePaths()


def DoCommand(args, output):
  if args.command == COMMAND_CREATE_BACKUP:
    return DoCreateBackup(args, output=output)
  elif args.command == COMMAND_APPLY_TO_BACKUPS:
    return DoApplyToBackups(args, output=output)
  elif args.command == COMMAND_CREATE_BACKUPS_IMAGE:
    return DoCreateBackupsImage(args, output=output)
  elif args.command == COMMAND_LIST_BACKUPS:
    return DoListBackups(args, output=output)
  elif args.command == COMMAND_VERIFY_BACKUPS:
    return DoVerifyBackups(args, output=output)
  elif args.command == COMMAND_DEDUPLICATE_BACKUPS:
    return DoDeDuplicateBackups(args, output=output)
  elif args.command == COMMAND_PRUNE_BACKUPS:
    return DoPruneBackups(args, output=output)
  elif args.command == COMMAND_ADD_MISSING_MANIFESTS_TO_BACKUPS:
    return DoAddMissingManifestsToBackups(args, output=output)
  elif args.command == COMMAND_CLONE_BACKUP:
    return DoCloneBackup(args, output=output)
  elif args.command == COMMAND_DELETE_BACKUP:
    return DoDeleteBackup(args, output=output)
  elif args.command == COMMAND_DUMP_UNIQUE_FILES_IN_BACKUPS:
    return DoDumpUniqueFilesInBackups(args, output=output)
  elif args.command == COMMAND_EXTRACT_FROM_BACKUPS:
    return DoExtractFromBackups(args, output=output)
  elif args.command == COMMAND_MERGE_INTO_BACKUPS:
    return DoMergeIntoBackups(args, output=output)
  elif args.command == COMMAND_DELETE_IN_BACKUPS:
    return DoDeleteInBackups(args, output=output)

  print >>output, '*** Error: Unknown command %s' % args.command
  return False
