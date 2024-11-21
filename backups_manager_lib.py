import argparse
import tempfile
import subprocess
import time
import os
import re
import shutil
import stat
import sys

from . import checkpoint_lib
from . import lib


COMMAND_CREATE_BACKUP = 'create-backup'
COMMAND_APPLY_TO_BACKUPS = 'apply-to-backups'
COMMAND_CREATE_BACKUPS_IMAGE = 'create-backups-image'
COMMAND_LIST_BACKUPS = 'list-backups'
COMMAND_VERIFY_BACKUPS = 'verify-backups'
COMMAND_DEDUPLICATE_BACKUPS = 'deduplicate-backups'
COMMAND_ADD_MISSING_MANIFESTS_TO_BACKUPS = 'add-missing-manifests-to-backups'
COMMAND_CLONE_BACKUP = 'clone-backup'
COMMAND_DELETE_BACKUPS = 'delete-backups'
COMMAND_DELETE_BACKUPS_INTERACTIVE = 'delete-backups-interactive'
COMMAND_DUMP_UNIQUE_FILES_IN_BACKUPS = 'dump-unique-files-in-backups'
COMMAND_EXTRACT_FROM_BACKUPS = 'extract-from-backups'
COMMAND_MERGE_INTO_BACKUPS = 'merge-into-backups'
COMMAND_DELETE_IN_BACKUPS = 'delete-in-backups'
COMMAND_MARK_BACKUPS_NOT_PRUNEABLE = 'mark-backups-not-pruneable'
COMMAND_RESTORE_META = 'restore-meta'

COMMANDS = [
  COMMAND_CREATE_BACKUP,
  COMMAND_APPLY_TO_BACKUPS,
  COMMAND_CREATE_BACKUPS_IMAGE,
  COMMAND_LIST_BACKUPS,
  COMMAND_VERIFY_BACKUPS,
  COMMAND_DEDUPLICATE_BACKUPS,
  COMMAND_ADD_MISSING_MANIFESTS_TO_BACKUPS,
  COMMAND_CLONE_BACKUP,
  COMMAND_DELETE_BACKUPS,
  COMMAND_DELETE_BACKUPS_INTERACTIVE,
  COMMAND_DUMP_UNIQUE_FILES_IN_BACKUPS,
  COMMAND_EXTRACT_FROM_BACKUPS,
  COMMAND_MERGE_INTO_BACKUPS,
  COMMAND_DELETE_IN_BACKUPS,
  COMMAND_MARK_BACKUPS_NOT_PRUNEABLE,
  COMMAND_RESTORE_META,
]


BACKUPS_SUBDIR = 'Backups'

DEDUP_MIN_FILE_SIZE = 100 * 1024

SUPERSEDED_METADATA_PREFIX = 'superseded-'

NOT_PRUNEABLE_FILENAME = 'prune.SKIP'


class BackupCheckpoint(object):
  BACKUP_CHECKPOINTS_PATTERN = re.compile(
    '^([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6})(-manifest)?[.](sparseimage|img|luks.img)$')

  STATE_NEW = 'NEW'
  STATE_IN_PROGRESS = 'IN_PROGRESS'
  STATE_DONE = 'DONE'
  STATE_DELETED = 'DELETED'

  @staticmethod
  def IsMatchingPath(path):
    return BackupCheckpoint.BACKUP_CHECKPOINTS_PATTERN.match(os.path.basename(path)) is not None

  def __init__(self, path):
    self.path = path
    m = BackupCheckpoint.BACKUP_CHECKPOINTS_PATTERN.match(os.path.basename(path))
    assert m
    self.name = m.group(1)
    self.is_manifest_only = m.group(2) is not None

  def __str__(self):
    manifest_only_str = self.is_manifest_only and ',manifest-only' or ''
    return 'BackupCheckpoint<%s%s>' % (self.name, manifest_only_str)

  def __lt__(self, other):
    return self.name < other.name

  def GetPath(self):
    return self.path

  def GetName(self):
    return self.name

  def IsManifestOnly(self):
    return self.is_manifest_only


def ListBackupCheckpoints(checkpoints_dir):
  checkpoints = []
  checkpoint_names = set()
  for filename in os.listdir(checkpoints_dir):
    if BackupCheckpoint.IsMatchingPath(filename):
      checkpoint = BackupCheckpoint(os.path.join(checkpoints_dir, filename))
      if checkpoint.GetName() in checkpoint_names:
        raise Exception('Checkpoint %s already in checkpoints list' % checkpoint)
      checkpoints.append(checkpoint)
      checkpoint_names.add(checkpoint.GetName())
  checkpoints.sort()
  return checkpoints


def PrintSkippedBackups(skipped_backups, output):
  if len(skipped_backups) == 1:
    print('Skipped backup %s' % skipped_backups[0], file=output)
  elif len(skipped_backups) > 1:
    print('Skipped %d backups: %s to %s' % (
      len(skipped_backups), skipped_backups[0], skipped_backups[-1]), file=output)


class LogThrottler(object):
  def __init__(self):
    self.log_always = False
    self.last_log_time = 0

  def SetLogAlways(self, log_always):
    self.log_always = log_always

  def GetLogAlways(self):
    return self.log_always

  def ResetLastLogTime(self):
    self.last_log_time = 0

  def ShouldLog(self):
    now = time.time()
    should_log = self.log_always or (self.last_log_time and now > self.last_log_time + 120)
    if should_log or not self.last_log_time:
      self.last_log_time = now

    return should_log


class PathsIntoBackupCopier(object):
  HARD_LINK_LOG_THROTTLER = LogThrottler()

  class Result(object):
    def __init__(self):
      self.to_backup = None
      self.to_manifest = None
      self.num_copied = 0
      self.num_hard_linked = 0
      self.num_hard_linked_to_duplicates = 0
      self.total_from_paths = 0
      self.total_to_paths = 0
      self.success = True

  def __init__(self, from_backup_or_checkpoint, from_manifest, to_backup_manager, to_backup,
               last_to_backup, last_to_manifest, path_matcher, output, verify_with_checksums=False,
               verify_hardlinks_with_checksums=True, deduplicate=True,
               deduplicate_min_file_size=DEDUP_MIN_FILE_SIZE, dry_run=False,
               verbose=False):
    """
    Args:
        to_backup: None to create a new backup matching from_backup_or_checkpoint's name for the contents,
            Non-None to use an existing backup to copy to.
    """

    self.from_backup_or_checkpoint = from_backup_or_checkpoint
    self.from_manifest = from_manifest
    self.to_backup_manager = to_backup_manager
    self.to_backup = to_backup
    self.last_to_backup = last_to_backup
    self.last_to_manifest = last_to_manifest
    self.path_matcher = path_matcher
    self.output = output
    self.verify_with_checksums = verify_with_checksums
    self.verify_hardlinks_with_checksums = verify_hardlinks_with_checksums
    self.deduplicate = deduplicate
    self.deduplicate_min_file_size = deduplicate_min_file_size
    self.dry_run = dry_run
    self.verbose = verbose

  def Copy(self):
    result = PathsIntoBackupCopier.Result()
    result.to_backup = self.to_backup
    to_backup_is_new = self.to_backup is None

    if self.from_manifest is None:
      self.from_manifest = lib.Manifest(self.from_backup_or_checkpoint.GetManifestPath())
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

    if self.deduplicate and self.last_to_manifest is not None:
      sha256_to_last_pathinfos = self.last_to_manifest.CreateSha256ToPathInfosMap(
        min_file_size=self.deduplicate_min_file_size)
    else:
      sha256_to_last_pathinfos = None

    paths_to_copy_set = set()
    paths_to_copy_from_last_set = set()
    paths_to_link_map = {}
    all_from_files_matched = True

    expanded_from_paths = set()
    for path in self.from_manifest.GetPaths():
      if self.path_matcher.Matches(path):
        expanded_from_paths.add(path)

        parent_dir = os.path.dirname(path)
        while parent_dir:
          if not result.to_manifest.HasPath(parent_dir):
            expanded_from_paths.add(parent_dir)
          parent_dir = os.path.dirname(parent_dir)
        if not result.to_manifest.HasPath('.'):
          expanded_from_paths.add('.')
      else:
        all_from_files_matched = False

    from_root_path = self.from_backup_or_checkpoint.GetContentRootPath()
    mismatched_itemizeds = []
    missing_from_itemizeds = []

    for path in sorted(expanded_from_paths):
      path_info = self.from_manifest.GetPathInfo(path)

      existing_path_info = result.to_manifest.GetPathInfo(path)
      if existing_path_info is not None:
        onto_existing_itemized = lib.PathInfo.GetItemizedDiff(path_info, existing_path_info)
        if onto_existing_itemized.HasDiffs():
          mismatched_itemizeds.append(onto_existing_itemized)
        continue

      result.to_manifest.AddPathInfo(path_info.Clone())
      result.total_to_paths += 1

      if self.last_to_manifest is not None:
        last_to_path_info = self.last_to_manifest.GetPathInfo(path)
        matches_last_to = not lib.PathInfo.GetItemizedDiff(path_info, last_to_path_info).HasDiffs()
        if matches_last_to:
          if path_info.HasFileContents():
            paths_to_link_map[path] = path
          else:
            paths_to_copy_from_last_set.add(path)
          continue

        if path_info.HasFileContents():
          if self.deduplicate and sha256_to_last_pathinfos is not None:
            dup_path_info = path_info.FindBestDup(sha256_to_last_pathinfos)
            if dup_path_info is not None:
              paths_to_link_map[path] = dup_path_info.path
              continue

      if not os.path.lexists(os.path.join(from_root_path, path)):
        missing_from_itemized = path_info.GetItemized()
        missing_from_itemized.error_path = True
        missing_from_itemizeds.append(missing_from_itemized)

      paths_to_copy_set.add(path)

    if mismatched_itemizeds:
      print('*** Error: Failed to copy paths: found mismatched existing paths:', file=self.output)
      for itemized in mismatched_itemizeds:
        itemized.Print(output=self.output)
      result.success = False
      return result
    if missing_from_itemizeds:
      print('*** Error: Failed to copy paths: found missing from paths:', file=self.output)
      for itemized in missing_from_itemizeds:
        itemized.Print(output=self.output)
      result.success = False
      return result

    paths_to_sync_set = set(paths_to_copy_set)
    paths_to_sync_set.update(paths_to_copy_from_last_set)
    paths_to_sync_set.update(list(paths_to_link_map.keys()))

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
      itemized.Print(output=self.output)
      link_to_path = paths_to_link_map.get(itemized.path)
      if link_to_path is not None and link_to_path != itemized.path:
        path_info = self.from_manifest.GetPathInfo(itemized.path)
        print('  duplicate to %s (size=%s)' % (
          lib.EscapePath(link_to_path), lib.FileSizeToString(path_info.size)), file=self.output)

    result.num_copied = len(paths_to_sync_set)
    for path, path_to in list(paths_to_link_map.items()):
      result.num_hard_linked += 1
      if path != path_to:
        result.num_hard_linked_to_duplicates += 1

    out_pieces = []
    if result.num_copied:
      out_pieces = ['%d to copy' % result.num_copied]
    if result.num_hard_linked:
      out_pieces.append('%d to hard link' % result.num_hard_linked)
    if result.num_hard_linked_to_duplicates:
      out_pieces.append('%d to duplicate' % result.num_hard_linked_to_duplicates)
    if result.total_from_paths:
      out_pieces.append('%d total in source' % result.total_from_paths)
    if result.total_to_paths:
      out_pieces.append('%d total in result' % result.total_to_paths)
    print('Copying paths: %s...' % ', '.join(out_pieces), file=self.output)

    if not self.dry_run:
      if to_backup_is_new:
        assert result.to_backup is None
        result.to_backup = self.to_backup_manager.StartNew(name=self.from_backup_or_checkpoint.GetName())
        result.to_backup.SetInProgressState(dry_run=self.dry_run)
      try:
        if paths_to_copy_from_last_set:
          lib.RsyncPaths(sorted(paths_to_copy_from_last_set),
                         self.last_to_backup.GetContentRootPath(),
                         result.to_backup.GetContentRootPath(),
                         output=self.output, dry_run=self.dry_run, verbose=self.verbose)
        if paths_to_copy_set:
          lib.RsyncPaths(sorted(paths_to_copy_set),
                         self.from_backup_or_checkpoint.GetContentRootPath(),
                         result.to_backup.GetContentRootPath(),
                         output=self.output, dry_run=self.dry_run, verbose=self.verbose)

        PathsIntoBackupCopier.HARD_LINK_LOG_THROTTLER.ResetLastLogTime()
        hard_links_total = len(paths_to_link_map)
        hard_links_remaining = hard_links_total
        for path, path_to in list(paths_to_link_map.items()):
          last_full_path = os.path.join(self.last_to_backup.GetContentRootPath(), path_to)
          full_path = os.path.join(result.to_backup.GetContentRootPath(), path)
          os.link(last_full_path, full_path)
          hard_links_remaining -= 1
          if PathsIntoBackupCopier.HARD_LINK_LOG_THROTTLER.ShouldLog() and hard_links_remaining:
            print('%d/%d hard links remaining (%d%%)...' % (
              hard_links_remaining, hard_links_total,
              (hard_links_total - hard_links_remaining) * 100.0 / hard_links_total), file=self.output)

        for path in result.to_manifest.GetPaths():
          path_info = result.to_manifest.GetPathInfo(path)
          if path_info.path_type == lib.PathInfo.TYPE_DIR:
            full_path = os.path.join(result.to_backup.GetContentRootPath(), path)
            os.utime(full_path, (path_info.mtime, path_info.mtime), follow_symlinks=False)

        result.to_manifest.SetPath(result.to_backup.GetManifestPath())
        result.to_manifest.Write()

        if self.verify_with_checksums:
          if self.verify_hardlinks_with_checksums:
            checksum_path_matcher = lib.PathMatcherAll()
          else:
            checksum_path_matcher = lib.PathMatcherSet(paths_to_link_map.keys(), include=False)
        else:
          checksum_path_matcher = lib.PathMatcherNone()

        print('Verifying %s...' % result.to_backup.GetName(), file=self.output)
        verifier = lib.ManifestVerifier(
          result.to_manifest, result.to_backup.GetContentRootPath(), self.output,
          checksum_path_matcher=checksum_path_matcher, verbose=self.verbose)
        if not verifier.Verify():
          raise Exception('Failed to verify %s' % result.to_backup.GetName())
        self._OutputVerifyStats(verifier.GetStats())
        if to_backup_is_new:
          result.to_backup.SetDoneState(dry_run=self.dry_run)
      except:
        if to_backup_is_new:
          result.to_backup.Delete(dry_run=self.dry_run)
        raise

    return result

  def _OutputVerifyStats(self, stats):
    out_pieces = ['%d total (%s)' % (stats.total_paths, lib.FileSizeToString(stats.total_size))]
    if stats.total_mismatched_paths:
      out_pieces.append('%d mismatched (%s)' % (
        stats.total_mismatched_paths, lib.FileSizeToString(stats.total_mismatched_size)))
    if stats.total_checksummed_paths:
      out_pieces.append('%d checksummed (%s)' % (
        stats.total_checksummed_paths, lib.FileSizeToString(stats.total_checksummed_size)))
    if stats.total_checksum_skipped_paths:
      out_pieces.append('%d checksums skipped (%s)' % (
        stats.total_checksum_skipped_paths, lib.FileSizeToString(stats.total_checksum_skipped_size)))
    if stats.total_skipped_paths:
      out_pieces.append('%d skipped' % stats.total_skipped_paths)
    print('Paths: %s' % ', '.join(out_pieces), file=self.output)


class DeDuplicateBackupsResult(object):
  def __init__(self):
    self.num_new_dup_files = 0


def DeDuplicateBackups(backup, manifest, last_backup, last_manifest, output, min_file_size=DEDUP_MIN_FILE_SIZE,
                       match_older_mtimes=False, escape_key_detector=None, dry_run=False, verbose=False):
  print('De-duplicate %s onto %s...' % (backup, last_backup), file=output)

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
  num_older_mtime_files_matched = 0
  manifest_modified = False

  for path in manifest.GetPaths():
    if escape_key_detector is not None and escape_key_detector.WasEscapePressed():
      print('*** Cancelled at path %s' % lib.EscapePath(path), file=output)
      break
    manifest_path_info = manifest.GetPathInfo(path)
    if not manifest_path_info.HasFileContents() or manifest_path_info.size < min_file_size:
      continue
    assert manifest_path_info.sha256 is not None

    num_large_files += 1
    dup_path_infos = lib.PathInfo.SortedByPathSimilarity(
      path, sha256_to_last_pathinfos.get(manifest_path_info.sha256, []))
    if not dup_path_infos:
      continue

    full_path = os.path.join(backup.GetContentRootPath(), path)
    path_info = lib.PathInfo.FromPath(path, full_path)
    assert path_info.dev_inode is not None
    assert not lib.PathInfo.GetItemizedDiff(manifest_path_info, path_info).HasDiffs()

    already_dupped = False

    matching_dup_path_infos = []
    similar_path_infos = []
    for dup_path_info in dup_path_infos:
      dup_full_path = os.path.join(last_backup.GetContentRootPath(), dup_path_info.path)
      dup_path_info = lib.PathInfo.FromPath(dup_path_info.path, dup_full_path)
      if path_info.dev_inode == dup_path_info.dev_inode:
        already_dupped = True
        break
      itemized = lib.PathInfo.GetItemizedDiff(dup_path_info, path_info, ignore_paths=True)
      if itemized.time_diff and match_older_mtimes and dup_path_info.mtime < path_info.mtime:
        itemized.time_diff = False
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
          print('Similar path %s (size=%s) to:' % (
            lib.EscapePath(path), lib.FileSizeToString(path_info.size)), file=output)
          for similar_path_info in similar_path_infos:
            itemized = lib.PathInfo.GetItemizedDiff(similar_path_info, path_info, ignore_paths=True)
            print('  %s' % itemized, file=output)
        num_similar_files += 1
        num_similar_files_total_size += path_info.size
      continue

    result.num_new_dup_files += 1
    new_dup_files_total_size += path_info.size

    print('Duplicate path %s (size=%s) to:' % (
      lib.EscapePath(path), lib.FileSizeToString(path_info.size)), file=output)
    for dup_path_info in matching_dup_path_infos:
      print('  %s' % lib.EscapePath(dup_path_info.path), file=output)

    matching_dup_path_info = matching_dup_path_infos[0]
    matching_dup_full_path = os.path.join(last_backup.GetContentRootPath(), matching_dup_path_info.path)

    assert full_path != matching_dup_full_path

    if not dry_run:
      parent_dir = os.path.dirname(full_path)
      parent_stat = os.lstat(parent_dir)
      os.unlink(full_path)
      os.link(matching_dup_full_path, full_path)
      os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime), follow_symlinks=False)

    if match_older_mtimes and matching_dup_path_info.mtime < path_info.mtime:
      manifest_path_info.mtime = matching_dup_path_info.mtime
      num_older_mtime_files_matched += 1
      manifest_modified = True

  if manifest_modified and not dry_run:
    manifest.Write()

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
  if num_older_mtime_files_matched:
    output_messages.append('%d older mtime files matched' % num_older_mtime_files_matched)

  if output_messages:
    print('Duplicates: %s' % '; '.join(output_messages), file=output)

  return result


def DumpUniqueFilesInBackup(
    backup, previous_backup, next_backup, output, verbose=False,
    ignore_matching_renames=False):
  print("Finding unique files in backup %s..." % backup, file=output)
  compared_to_output = []
  if previous_backup is not None:
    compared_to_output.append('previous %s' % previous_backup)
  if next_backup is not None:
    compared_to_output.append('next %s' % next_backup)
  if compared_to_output:
    print("Compare to %s..." % ' and '.join(compared_to_output), file=output)

  manifest = lib.Manifest(backup.GetManifestPath())
  manifest.Read()
  num_paths = manifest.GetPathCount()

  if previous_backup is None and next_backup is None:
    for itemized in manifest.GetItemized():
      itemized.Print(output=output, warn_for_new_path=True)
    print('Paths: %d unique, %d total' % (num_paths, num_paths), file=output)
    return

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
      if verbose:
        itemized.Print(output=output, warn_for_new_path=True)
        if previous_path_info is not None:
          print('  <', previous_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=output)
        if next_path_info is not None:
          print('  >', next_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=output)
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
    if itemized.new_path and path_info.HasFileContents():
      for sha256_to_other_pathinfos, replacing_previous in [
          (sha256_to_next_pathinfos, False), (sha256_to_previous_pathinfos, True)]:
        if sha256_to_other_pathinfos is not None:
          dup_path_infos = sha256_to_other_pathinfos.get(path_info.sha256, [])
          analyze_result = lib.AnalyzePathInfoDups(
            path_info, dup_path_infos, replacing_previous=replacing_previous, verbose=verbose)
          dup_output_lines.extend(analyze_result.dup_output_lines)
          if analyze_result.found_matching_rename:
            found_matching_rename = True

    if not ignore_matching_renames or not found_matching_rename:
      num_unique += 1
      if path_info.HasFileContents():
        unique_size += path_info.size

      itemized.Print(output=output, found_matching_rename=found_matching_rename,
                     warn_for_new_path=True)
      if verbose:
        if previous_path_info is not None:
          print('  <', previous_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=output)
        print('  =', path_info.ToString(
          include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=output)
        if next_path_info is not None:
          print('  >', next_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=output)

      for dup_output_line in dup_output_lines:
        print(dup_output_line, file=output)

  print('Paths: %d unique (%s), %d total' % (
    num_unique, lib.FileSizeToString(unique_size), num_paths), file=output)


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


class BackupsMatcher(object):
  def __init__(self, min_backup=None, max_backup=None, backup_names=[]):
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.backup_names = list(backup_names)

  def IsDefault(self):
    return self.min_backup is None and self.max_backup is None and not self.backup_names

  def Matches(self, backup_name):
    if self.min_backup is not None and backup_name < self.min_backup:
      return False
    if self.max_backup is not None and backup_name > self.max_backup:
      return False
    if self.backup_names and backup_name not in self.backup_names:
      return False
    return True


class BackupsMatcherArgsError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


def AddBackupsMatcherArgs(parser):
  parser.add_argument('--backup-name', dest='backup_names', action='append', default=[])
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')


def GetBackupsMatcherFromArgs(args):
  if args.backup_names and (args.min_backup is not None or args.max_backup is not None):
    raise BackupsMatcherArgsError('--backup-name args cannot be used at the same time as '
                                  '--min-backup or --max-backup args')
  return BackupsMatcher(min_backup=args.min_backup, max_backup=args.max_backup,
                        backup_names=args.backup_names)


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

  def GetFilters(self):
    filters = list(checkpoint_lib.STAGED_BACKUP_DEFAULT_FILTERS)
    if self.filter_merge_path is not None:
      if not os.path.exists(self.filter_merge_path):
        raise Exception('Expected filter merge path %r to exist' % self.filter_merge_path)
      filters.append(lib.FilterRuleMerge(self.filter_merge_path))
    return filters


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

  def __lt__(self, other):
    return self.name < other.name

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

  def GetContentRootPath(self):
    return os.path.join(self.GetPath(), lib.CONTENT_DIR_NAME)

  def GetMetadataPath(self):
    return os.path.join(self.GetPath(), lib.METADATA_DIR_NAME)

  def GetManifestPath(self):
    return os.path.join(self.GetMetadataPath(), lib.MANIFEST_FILENAME)

  def GetBackupTime(self):
    return int(time.mktime(time.strptime(self.name, '%Y-%m-%d-%H%M%S')))

  def SetInProgressState(self, dry_run=False):
    assert self.state == Backup.STATE_NEW
    assert not os.path.exists(self.GetPath())
    self.state = Backup.STATE_IN_PROGRESS
    assert not os.path.exists(self.GetPath())
    assert self.GetContentRootPath().startswith(self.GetPath())
    if not dry_run:
      os.makedirs(self.GetPath())
    if not os.path.exists(self.GetMetadataPath()):
      if not dry_run:
        os.mkdir(self.GetMetadataPath())
    if not os.path.exists(self.GetContentRootPath()):
      if not dry_run:
        os.mkdir(self.GetContentRootPath())

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
      subprocess.check_call(['cp', '-a', self.GetMetadataPath(), saved_metadata_dest_path])
      for child_filename in os.listdir(saved_metadata_dest_path):
        if child_filename.startswith(SUPERSEDED_METADATA_PREFIX):
          child_old_path = os.path.join(saved_metadata_dest_path, child_filename)
          child_new_path = os.path.join(superseding_backup.GetMetadataPath(), child_filename)
          if not os.path.lexists(child_new_path):
            os.rename(child_old_path, child_new_path)

  def CopyMetadataToBackup(self, to_backup, skip_manifest=False, dry_run=False):
    from_metadata_path = self.GetMetadataPath()
    to_metadata_path = to_backup.GetMetadataPath()
    for filename in os.listdir(from_metadata_path):
      if skip_manifest and filename == lib.MANIFEST_FILENAME:
        continue
      from_path = os.path.join(from_metadata_path, filename)
      to_path = os.path.join(to_metadata_path, filename)
      if os.path.lexists(to_path):
        raise Exception('Cannot replace %r with %r' % (to_path, from_path))
      subprocess.check_call(['cp', '-a', from_path, to_path])

  def IsPruneable(self):
    return not os.path.isfile(os.path.join(self.GetMetadataPath(), NOT_PRUNEABLE_FILENAME))

  def MarkPruneable(self, pruneable, dry_run=False):
    not_pruneable_file_path = os.path.join(self.GetMetadataPath(), NOT_PRUNEABLE_FILENAME)
    if pruneable:
      if os.path.isfile(not_pruneable_file_path) and not dry_run:
        os.unlink(not_pruneable_file_path)
    elif not os.path.isfile(not_pruneable_file_path) and not dry_run:
      with open(not_pruneable_file_path, 'w'):
        pass

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
  def Open(config, encryption_manager=None, readonly=True, browseable=True, hdiutil_verify=True, dry_run=False):
    return BackupsManager(config, encryption_manager=encryption_manager, readonly=readonly,
                          browseable=browseable, hdiutil_verify=hdiutil_verify, dry_run=dry_run)

  @staticmethod
  def Create(config, volume_name=None, encrypt=True, encryption_manager=None, browseable=True,
             size=lib.DISK_IMAGE_DEFAULT_CAPACITY, dry_run=False):
    if os.path.lexists(config.image_path):
      raise Exception('Expected %s to not exist' % config.image_path)
    lib.CreateDiskImage(config.image_path, volume_name=volume_name, encrypt=encrypt, size=size,
                        encryption_manager=encryption_manager, dry_run=dry_run)
    if not dry_run:
      return BackupsManager(config, encryption_manager=encryption_manager, readonly=False,
                            browseable=browseable, dry_run=dry_run)

  def __init__(self, config, encryption_manager=None, readonly=True, browseable=True,
               hdiutil_verify=True, dry_run=False):
    if (not config.image_path.endswith('.sparsebundle')
        and not config.image_path.endswith('.sparseimage')
        and not config.image_path.endswith('.dmg')
        and not config.image_path.endswith('.img')):
      raise Exception('Expected a sparsebundle, sparseimage, dmg, or img file')
    if not os.path.exists(config.image_path):
      raise Exception('Expected %s to exist' % config.image_path)
    self.config = config
    self.encryption_manager = encryption_manager
    self.readonly = readonly
    self.browseable = browseable
    self.hdiutil_verify = hdiutil_verify
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

  def Reopen(self, readonly=True):
    if self.readonly == readonly:
      return
    self.Close()
    self.readonly = readonly
    self._Open()

  def Close(self):
    self.attacher.Close()
    self.attacher = None

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

  def DeleteBackup(self, backup, output, dry_run=False):
    backup_index = self.backups.index(backup)
    superseding_backup = None
    if backup_index + 1 < len(self.backups):
      superseding_backup = self.backups[backup_index + 1]
    if superseding_backup is not None:
      print("Deleting %s: %s supersedes it..." % (backup, superseding_backup), file=output)
      backup.CopyMetadataToSupersedingBackup(superseding_backup, dry_run=dry_run)
    else:
      print("Deleting %s..." % backup, file=output)
    if not dry_run:
      backup.Delete()

  def GetPreviousBackup(self, backup, skip_deleted=True):
    backup_index = self.backups.index(backup)
    for i in range(backup_index - 1, -1, -1):
      if self.backups[i].GetState() == Backup.STATE_DONE:
        return self.backups[i]
      elif self.backups[i].GetState() == Backup.STATE_DELETED:
        if skip_deleted:
          continue
        else:
          return self.backups[i]
      else:
        raise Exception('Unexpected backup state: %s' % self.backups[i])

  def GetNextBackup(self, backup, skip_deleted=True):
    backup_index = self.backups.index(backup)
    for i in range(backup_index + 1, len(self.backups)):
      if self.backups[i].GetState() == Backup.STATE_DONE:
        return self.backups[i]
      elif self.backups[i].GetState() == Backup.STATE_DELETED:
        if skip_deleted:
          continue
        else:
          return self.backups[i]
      else:
        raise Exception('Unexpected backup state: %s' % self.backups[i])

  def _Open(self):
    self.attacher = lib.ImageAttacher.Open(
      self.GetImagePath(), mount_point=self.config.mount_path,
      encryption_manager=self.encryption_manager, readonly=(self.readonly or self.dry_run),
      browseable=self.browseable, hdiutil_verify=self.hdiutil_verify)

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
      print('*** Error: No previous checkpoints found', file=self.output)
      return False

    last_checkpoint = checkpoints[-1]

    basis_path = last_checkpoint.GetPath()
    basis_manifest = lib.ReadManifestFromImageOrPath(
      basis_path, encryption_manager=self.encryption_manager, dry_run=self.dry_run)

    filters = self.config.GetFilters()

    creator = checkpoint_lib.CheckpointCreator(
      self.config.src_path, self.config.checkpoints_dir, name=self.name, output=self.output,
      basis_path=basis_path, basis_manifest=basis_manifest, dry_run=self.dry_run,
      verbose=self.verbose, checksum_all=self.checksum_all, manifest_only=False,
      encrypt=self.encrypt, encryption_manager=self.encryption_manager, filters=filters)
    return creator.Create()


class CheckpointsToBackupsApplier:
  def __init__(self, config, output, encryption_manager=None, checksum_all=True,
               checksum_hardlinks=True, deduplicate_min_file_size=DEDUP_MIN_FILE_SIZE,
               dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encryption_manager = encryption_manager
    self.checksum_all = checksum_all
    self.checksum_hardlinks = checksum_hardlinks
    self.deduplicate_min_file_size = deduplicate_min_file_size
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def Apply(self):
    checkpoints = ListBackupCheckpoints(self.config.checkpoints_dir)
    if not checkpoints:
      print('No checkpoints found', file=self.output)
      return True

    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=True,
      dry_run=self.dry_run)
    try:
      last_backup = self.manager.GetLastDone()
      if not last_backup:
        print('*** Error: No last backup found for %s' % self.manager, file=self.output)
        return False
      checkpoints_to_apply = []
      for checkpoint in checkpoints:
        assert Backup.IsBackupName(checkpoint.GetName())
        if checkpoint.GetName() <= last_backup.GetName():
          continue
        test_open_checkpoint = checkpoint_lib.Checkpoint.Open(
          checkpoint.GetPath(), encryption_manager=self.encryption_manager, readonly=True,
          dry_run=self.dry_run)
        test_open_checkpoint.Close()
        if checkpoint.IsManifestOnly():
          raise Exception('Checkpoint %s is manifest only: cannot apply to backups' % checkpoint)
        checkpoints_to_apply.append(checkpoint)
      if not checkpoints_to_apply:
        print('No checkpoints to apply found', file=self.output)
        return True
      if not self.dry_run:
        self.manager.Reopen(readonly=False)
      for checkpoint in checkpoints_to_apply:
        open_checkpoint = checkpoint_lib.Checkpoint.Open(
          checkpoint.GetPath(), encryption_manager=self.encryption_manager, readonly=True,
          dry_run=self.dry_run)
        try:
          (success, last_backup) = self._CreateBackupFromCheckpoint(open_checkpoint, last_backup)
        finally:
          open_checkpoint.Close()
        if not success:
          return False
      return True
    finally:
      self.manager.Close()

  def _CreateBackupFromCheckpoint(self, checkpoint, last_backup):
    print('Applying %s onto %s...' % (checkpoint.GetName(), last_backup.GetName()), file=self.output)
    copier = PathsIntoBackupCopier(
      from_backup_or_checkpoint=checkpoint, from_manifest=None, to_backup_manager=self.manager,
      to_backup=None, last_to_backup=last_backup, last_to_manifest=None,
      path_matcher=lib.PathMatcherAll(), deduplicate_min_file_size=self.deduplicate_min_file_size,
      output=self.output, verify_with_checksums=self.checksum_all,
      verify_hardlinks_with_checksums=self.checksum_hardlinks,
      dry_run=self.dry_run, verbose=self.verbose)
    result = copier.Copy()
    if not result.success:
      print(('*** Error: Failed to apply %s onto %s'
                            % (checkpoint.GetName(), last_backup.GetName())), file=self.output)
      return (False, None)

    if not self.dry_run:
      self.manager.UpdateLatestSymlink(result.to_backup)

    if self.dry_run:
      return (True, last_backup)
    else:
      return (True, result.to_backup)


class BackupsImageCreator(object):
  def __init__(self, config, output, volume_name=None, encrypt=True, encryption_manager=None,
               size=lib.DISK_IMAGE_DEFAULT_CAPACITY, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.volume_name = volume_name
    self.encrypt = encrypt
    self.encryption_manager = encryption_manager
    self.size = size
    self.dry_run = dry_run
    self.verbose = verbose

  def CreateImage(self):
    print('Creating image %s...' % self.config.image_path, file=self.output)
    manager = BackupsManager.Create(
      self.config, volume_name=self.volume_name, encrypt=self.encrypt, size=self.size,
      encryption_manager=self.encryption_manager, browseable=False, dry_run=self.dry_run)
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
        msg = backup.GetName()
        if self.verbose:
          if not backup.IsPruneable():
            msg += ' (pruneable=False)'
        print(msg, file=self.output)
    finally:
      backups_manager.Close()
    return True


class BackupsVerifier(object):
  def __init__(self, config, output, min_backup=None, max_backup=None, full=True,
               continue_on_error=False, hdiutil_verify=True, encryption_manager=None,
               checksum_all=True, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.full = full
    self.continue_on_error = continue_on_error
    self.hdiutil_verify = hdiutil_verify
    self.encryption_manager = encryption_manager
    self.checksum_all = checksum_all
    self.dry_run = dry_run
    self.verbose = verbose

  def Verify(self):
    errors_encountered = False

    backups_manager = BackupsManager.Open(
      self.config, readonly=True, browseable=False, encryption_manager=self.encryption_manager,
      hdiutil_verify=self.hdiutil_verify, dry_run=self.dry_run)
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
            print('*** Cancelled at backup %s' % backup, file=self.output)
            return False
          if not success:
            errors_encountered = True
            print("*** Error: Failed to verify backup %s" % backup, file=self.output)
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
    print('Verifying %s...' % backup.GetName(), file=self.output)

    if not os.path.exists(backup.GetManifestPath()):
      print('*** Error: Manifest file missing for %s' % backup, file=self.output)
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
    path_enumerator = lib.PathEnumerator(backup.GetContentRootPath(), self.output, verbose=self.verbose)
    for enumerated_path in path_enumerator.Scan():
      path = enumerated_path.GetPath()
      num_paths += 1
      full_path = os.path.join(backup.GetContentRootPath(), path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.HasFileContents():
        assert path_info.dev_inode is not None
        path_info.sha256 = dev_inodes_to_sha256.get(path_info.dev_inode)
        if path_info.sha256 is None:
          if escape_key_detector.WasEscapePressed():
            print('*** Cancelled at path %s' % lib.EscapePath(path), file=self.output)
            return (False, None)

          if self.checksum_all:
            path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
            num_checksummed += 1
            total_checksummed_size += path_info.size
        else:
          num_inode_hits += 1
      new_manifest.AddPathInfo(path_info)

    out_pieces = ['%d total' % num_paths]
    if num_inode_hits:
      out_pieces .append('%d inode hits' % num_inode_hits)
    if num_checksummed:
      out_pieces.append('%d checksummed (%s)' % (num_checksummed, lib.FileSizeToString(total_checksummed_size)))
    print('Paths: %s' % ', '.join(out_pieces), file=self.output)

    itemized_results = new_manifest.GetDiffItemized(manifest)
    for itemized in itemized_results:
      itemized.Print(output=self.output)
      if self.verbose:
        manifest_path_info = manifest.GetPathInfo(itemized.path)
        if manifest_path_info:
          print('<', manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
        new_manifest_path_info = new_manifest.GetPathInfo(itemized.path)
        if new_manifest_path_info:
          print('>', new_manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=self.output)

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

      full_path = os.path.join(backup.GetContentRootPath(), path)
      new_path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.HasFileContents():
        if last_manifest is not None:
          assert path_info.sha256
          for dup_path_info in sha256_to_last_pathinfos.get(path_info.sha256, []):
            dup_itemized = lib.PathInfo.GetItemizedDiff(
              path_info, dup_path_info, ignore_paths=True)
            if not dup_itemized.HasDiffs():
              new_path_info.sha256 = path_info.sha256
              break
        if not self.checksum_all:
          new_path_info.sha256 = path_info.sha256
        if not new_path_info.sha256:
          if escape_key_detector.WasEscapePressed():
            print('*** Cancelled at path %s' % lib.EscapePath(path), file=self.output)
            return (False, None)

          new_path_info.sha256 = lib.Sha256WithProgress(full_path, new_path_info, output=self.output)
          num_checksummed += 1
          total_checksummed_size += new_path_info.size
      new_manifest.AddPathInfo(new_path_info)

    out_pieces = ['%d unique, %d matching' % (num_unique, num_matching)]
    if num_checksummed:
      out_pieces.append('%d checksummed (%s)' % (num_checksummed, lib.FileSizeToString(total_checksummed_size)))
    print('Paths: %s' % ', '.join(out_pieces), file=self.output)

    itemized_results = new_manifest.GetDiffItemized(manifest)
    for itemized in itemized_results:
      itemized.Print(output=self.output)
      if self.verbose:
        manifest_path_info = manifest.GetPathInfo(itemized.path)
        if manifest_path_info:
          print('<', manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
        new_manifest_path_info = new_manifest.GetPathInfo(itemized.path)
        if new_manifest_path_info:
          print('>', new_manifest_path_info.ToString(
            include_path=False, shorten_sha256=True, shorten_xattr_hash=True), file=self.output)

    return (not itemized_results, new_manifest)


class BackupsDeDuplicator(object):
  def __init__(self, config, output, min_file_size=DEDUP_MIN_FILE_SIZE, min_backup=None, max_backup=None,
               match_older_mtimes=False, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.min_file_size = min_file_size
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.match_older_mtimes = match_older_mtimes
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

      escape_key_detector = lib.EscapeKeyDetector()
      try:
        for backup in self.manager.GetBackupList():
          if ((self.min_backup is not None and backup.GetName() < self.min_backup)
              or (self.max_backup is not None and backup.GetName() > self.max_backup)):
            skipped_backups.append(backup)
            last_backup = None
            last_manifest = None
            continue

          if escape_key_detector.WasEscapePressed():
            print('*** Cancelled before backup %s' % backup, file=self.output)
            return False

          PrintSkippedBackups(skipped_backups, self.output)
          skipped_backups = []

          manifest = lib.ReadManifestFromImageOrPath(
            backup.GetManifestPath(), encryption_manager=self.encryption_manager, dry_run=self.dry_run)

          if last_manifest is not None:
            DeDuplicateBackups(
              backup, manifest, last_backup, last_manifest, self.output, min_file_size=self.min_file_size,
              match_older_mtimes=self.match_older_mtimes, escape_key_detector=escape_key_detector,
              dry_run=self.dry_run, verbose=self.verbose)

          last_manifest = manifest
          last_backup = backup

        PrintSkippedBackups(skipped_backups, self.output)
        return True
      finally:
        escape_key_detector.Shutdown()
    finally:
      self.manager.Close()


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
          print('Manifest already exists for backup %s' % backup, file=self.output)
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
    print('Add missing manifest for backup %s...' % backup, file=self.output)

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

    path_enumerator = lib.PathEnumerator(backup.GetContentRootPath(), self.output, verbose=self.verbose)
    for enumerated_path in path_enumerator.Scan():
      path = enumerated_path.GetPath()
      num_paths += 1
      full_path = os.path.join(backup.GetContentRootPath(), path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.HasFileContents():
        assert path_info.dev_inode is not None
        path_info.sha256 = dev_inodes_to_sha256.get(path_info.dev_inode)
        if path_info.sha256 is None:
          path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
          num_checksummed += 1
          total_checksummed_size += path_info.size
        else:
          num_inode_hits += 1
      manifest.AddPathInfo(path_info)
    print('Paths: %d total, %d inode hits, %d checksummed (%s)' % (
      num_paths, num_inode_hits, num_checksummed, lib.FileSizeToString(total_checksummed_size)), file=self.output)


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
        print('*** Error: No backup %s found for %s' % (self.backup_name, self.manager), file=self.output)
        return False
      return self._CloneBackupInternal(backup)
    finally:
      self.manager.Close()

  def _CloneBackupInternal(self, backup):
    backup_clone = self.manager.StartClone(backup)
    print('Cloning %s to %s...' % (backup, backup_clone), file=self.output)
    if os.path.lexists(backup_clone.GetPath()):
      print('*** Error: directory %s already exists' % backup_clone.GetPath(), file=self.output)
      return False
    if not self.dry_run:
      os.mkdir(backup_clone.GetPath())
    lib.Rsync(backup.GetMetadataPath(),
              backup_clone.GetMetadataPath(),
              output=self.output,
              dry_run=self.dry_run,
              verbose=self.verbose)
    lib.Rsync(backup.GetContentRootPath(),
              backup_clone.GetContentRootPath(),
              output=self.output,
              dry_run=self.dry_run,
              verbose=self.verbose,
              link_dest=backup.GetContentRootPath())
    return True


class BackupsDeleter(object):
  def __init__(self, config, output, backup_names=[], encryption_manager=None, dry_run=False,
               verbose=False):
    self.config = config
    self.output = output
    self.backup_names = backup_names
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def DeleteBackups(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      escape_key_detector = lib.EscapeKeyDetector()
      try:
        for backup_name in self.backup_names:
          if escape_key_detector.WasEscapePressed():
            print('*** Cancelled before backup %s' % backup_name, file=self.output)
            return False
          backup = self.manager.GetBackup(backup_name)
          if not backup:
            print('*** Error: No backup %s found for %s' % (backup_name, self.manager), file=self.output)
            return False
          self._DeleteBackupInternal(backup)
        return True
      finally:
        escape_key_detector.Shutdown()
    finally:
      self.manager.Close()

  def _DeleteBackupInternal(self, backup):
    self.manager.DeleteBackup(backup, output=self.output, dry_run=self.dry_run)


class BackupsInteractiveDeleter(object):
  INTERACTIVE_CHECKER = lib.InteractiveChecker()

  def __init__(self, config, output, backups_matcher=BackupsMatcher(), ignore_matching_renames=False,
               include_latest_backup=True, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.backups_matcher = backups_matcher
    self.ignore_matching_renames = ignore_matching_renames
    self.include_latest_backup = include_latest_backup
    self.match_previous_only = False
    self.match_next_only = False
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def DeleteBackupsInteractively(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=True,
      dry_run=self.dry_run)
    try:
      if self.backups_matcher.IsDefault():
        # Start after the last not pruneable backup by default
        min_backup = None
        for backup in reversed(self.manager.GetBackupList()):
          if not backup.IsPruneable():
            if min_backup is None:
              print('*** The latest backup %s is not pruneable ***' % backup, file=self.output)
              return
            break
          min_backup = backup.GetName()
        self.backups_matcher = BackupsMatcher(min_backup=min_backup)
      for backup in self.manager.GetBackupList():
        if not self.backups_matcher.Matches(backup.GetName()):
          continue

        if not self.match_next_only:
          previous_backup = self.manager.GetPreviousBackup(backup, skip_deleted=True)
        else:
          previous_backup = None

        next_backup = self.manager.GetNextBackup(backup, skip_deleted=True)
        if next_backup is None and not self.include_latest_backup:
          print('*** Skipping latest backup %s ***' % backup, file=self.output)
          continue
        if self.match_previous_only:
          next_backup = None

        if not backup.IsPruneable():
          print('*** Skipping backup %s: marked as not pruneable ***' % backup, file=self.output)
          continue

        self._DumpUniqueFilesInternal(backup, previous_backup, next_backup)

        if not self.INTERACTIVE_CHECKER.Confirm('Delete backup?', self.output):
          print('*** Skipping backup %s ***' % backup, file=self.output)
          continue
        if not self.dry_run:
          self.manager.Reopen(readonly=False)
        self.manager.DeleteBackup(backup, output=self.output, dry_run=self.dry_run)
        if not self.dry_run:
          self.manager.Reopen(readonly=True)
    finally:
      self.manager.Close()

    return True

  def _DumpUniqueFilesInternal(self, backup, previous_backup, next_backup):
    DumpUniqueFilesInBackup(
      backup, previous_backup, next_backup, output=self.output, verbose=self.verbose,
      ignore_matching_renames=self.ignore_matching_renames)


class UniqueFilesInBackupsDumper(object):
  def __init__(self, config, output, backups_matcher=BackupsMatcher(), ignore_matching_renames=False,
               match_previous_only=False, match_next_only=False, encryption_manager=None,
               dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.backups_matcher = backups_matcher
    self.ignore_matching_renames = ignore_matching_renames
    self.match_previous_only = match_previous_only
    self.match_next_only = match_next_only
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def DumpUniqueFiles(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=True,
      dry_run=self.dry_run)
    try:
      escape_key_detector = lib.EscapeKeyDetector()
      try:
        for backup in self.manager.GetBackupList():
          if not self.backups_matcher.Matches(backup.GetName()):
            continue

          if not self.match_next_only:
            previous_backup = self.manager.GetPreviousBackup(backup, skip_deleted=True)
          else:
            previous_backup = None
          if not self.match_previous_only:
            next_backup = self.manager.GetNextBackup(backup, skip_deleted=True)
          else:
            next_backup = None

          if escape_key_detector.WasEscapePressed():
            print('*** Cancelled before backup %s' % backup, file=self.output)
            return False

          self._DumpUniqueFilesInternal(backup, previous_backup, next_backup)
      finally:
        escape_key_detector.Shutdown()
    finally:
      self.manager.Close()

    return True

  def _DumpUniqueFilesInternal(self, backup, previous_backup, next_backup):
    DumpUniqueFilesInBackup(
      backup, previous_backup, next_backup, output=self.output, verbose=self.verbose,
      ignore_matching_renames=self.ignore_matching_renames)


class PathsFromBackupsExtractor(object):
  def __init__(self, config, output, output_image_path=None, output_volume_name=None, paths=[],
               min_backup=None, max_backup=None, deduplicate_min_file_size=DEDUP_MIN_FILE_SIZE,
               encrypt=True, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.output_image_path = output_image_path
    self.output_volume_name = output_volume_name
    self.paths = paths
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.encrypt = encrypt
    self.checksum_all = True
    self.deduplicate_min_file_size = deduplicate_min_file_size
    self.encryption_manager = encryption_manager
    self.extracted_manager = None
    self.dry_run = dry_run
    self.verbose = verbose

  def ExtractPaths(self):
    if not self.dry_run:
      if self.output_image_path is None:
        print('*** Error: --output-image-path argument required', file=self.output)
        return False
      if os.path.lexists(self.output_image_path):
        print('*** Error: Output image path %s already exists' % self.output_image_path, file=self.output)
        return False
      output_config = BackupsConfig()
      output_config.image_path = os.path.normpath(self.output_image_path)
      self.extracted_manager = BackupsManager.Create(
        output_config, volume_name=self.output_volume_name, encrypt=self.encrypt,
        encryption_manager=self.encryption_manager, browseable=False, dry_run=self.dry_run)
    success = False
    try:
      success = self._ExtractPathsInternal()
      return success
    finally:
      if self.extracted_manager is not None:
        self.extracted_manager.Close()
        if not success:
          if os.path.isdir(self.output_image_path):
            shutil.rmtree(self.output_image_path)
          else:
            os.unlink(self.output_image_path)

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
            print('*** Cancelled at backup %s' % backup, file=self.output)
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
    print('Extracting from %s...' % backup.GetName(), file=self.output)

    path_matcher = lib.PathMatcherPathsAndPrefix(self.paths)

    copier = PathsIntoBackupCopier(
      from_backup_or_checkpoint=backup, from_manifest=None, to_backup_manager=self.extracted_manager,
      to_backup=None, last_to_backup=last_extracted_backup, last_to_manifest=last_extracted_manifest,
      path_matcher=path_matcher, deduplicate_min_file_size=self.deduplicate_min_file_size,
      output=self.output, dry_run=self.dry_run, verbose=self.verbose)
    result = copier.Copy()

    if not result.success:
      raise Exception('Failed to copy paths from %s' % backup)

    if result.num_copied:
      return (result.to_backup, result.to_manifest)

    return (None, None)


class IntoBackupsMerger(object):
  def __init__(self, config, output, from_image_path=None,
               min_backup=None, max_backup=None, deduplicate_min_file_size=DEDUP_MIN_FILE_SIZE,
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.from_image_path = from_image_path
    self.min_backup = min_backup
    self.max_backup = max_backup
    self.deduplicate_min_file_size = deduplicate_min_file_size
    self.checksum_all = True
    self.encryption_manager = encryption_manager
    self.backups_manager = None
    self.from_backups_manager = None
    self.dry_run = dry_run
    self.verbose = verbose

  def Merge(self):
    from_backups_config = BackupsConfig()
    from_backups_config.image_path = os.path.normpath(self.from_image_path)
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
          skipped_from_backups.append(from_backup)
          continue

        PrintSkippedBackups(skipped_from_backups, self.output)
        skipped_from_backups = []

        from_backups.append(from_backup)

      backups = self.backups_manager.GetBackupList()
      last_backup = None
      last_backup_was_modified = False

      escape_key_detector = lib.EscapeKeyDetector()
      try:
        while True:
          backup = backups and backups[0] or None
          from_backup = from_backups and from_backups[0] or None
          if backup and from_backup:
            if backup.GetName() < from_backup.GetName():
              from_backup = None
            elif backup.GetName() > from_backup.GetName():
              backup = None

          if backup:
            if escape_key_detector.WasEscapePressed():
              print('*** Cancelled before backup %s' % backup, file=self.output)
              return False
            if from_backup:
              (last_backup_was_modified, success) = self._MergeBackup(
                backup, from_backup, last_backup)
              if not success:
                return False
              last_backup = backup
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
            if escape_key_detector.WasEscapePressed():
              print('*** Cancelled before from backup %s' % from_backup, file=self.output)
              return False
            last_backup = self._ImportNewBackup(from_backup, last_backup)
            last_backup_was_modified = True
            del from_backups[0]
            continue

          break
      finally:
        escape_key_detector.Shutdown()

      PrintSkippedBackups(skipped_from_backups, self.output)
    finally:
      self.backups_manager.Close()

    return True

  def _MergeBackup(self, backup, from_backup, last_backup):
    print('Backup %s: merging...' % backup.GetName(), file=self.output)

    copier = PathsIntoBackupCopier(
      from_backup_or_checkpoint=from_backup, from_manifest=None, to_backup_manager=self.backups_manager,
      to_backup=backup, last_to_backup=last_backup, last_to_manifest=None,
      path_matcher=lib.PathMatcherAll(), deduplicate_min_file_size=self.deduplicate_min_file_size,
      output=self.output, dry_run=self.dry_run, verbose=self.verbose)
    result = copier.Copy()

    if not result.success:
      return (result.num_copied != 0, False)

    return (result.num_copied != 0, True)

  def _RetainBackup(self, backup, last_backup, last_backup_was_modified):
    """
    Return: whether the retained backup was modified
    """

    print('Backup %s: existing retained.' % backup.GetName(), file=self.output)
    if last_backup is not None and last_backup_was_modified:
      result = DeDuplicateBackups(
        backup=backup, manifest=None, last_backup=last_backup, last_manifest=None,
        min_file_size=self.deduplicate_min_file_size,
        output=self.output, dry_run=self.dry_run, verbose=self.verbose)
      return result.num_new_dup_files > 0

    return False

  def _ImportNewBackup(self, from_backup, last_backup):
    print('Backup %s: importing new...' % from_backup.GetName(), file=self.output)

    copier = PathsIntoBackupCopier(
      from_backup_or_checkpoint=from_backup, from_manifest=None, to_backup_manager=self.backups_manager,
      to_backup=None, last_to_backup=last_backup, last_to_manifest=None,
      path_matcher=lib.PathMatcherAll(), deduplicate_min_file_size=self.deduplicate_min_file_size,
      output=self.output, dry_run=self.dry_run, verbose=self.verbose)
    result = copier.Copy()

    if not result.success or not result.num_copied:
      raise Exception('Expected to import %s' % from_backup)

    if result.to_backup is not None:
      from_backup.CopyMetadataToBackup(result.to_backup, skip_manifest=True, dry_run=self.dry_run)

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
      escape_key_detector = lib.EscapeKeyDetector()
      try:
        skipped_backups = []
        for backup in backups_manager.GetBackupList():
          if ((self.min_backup is not None and backup.GetName() < self.min_backup)
              or (self.max_backup is not None and backup.GetName() > self.max_backup)):
            skipped_backups.append(backup)
            continue

          PrintSkippedBackups(skipped_backups, self.output)
          skipped_backups = []

          self._DeletePathsInBackup(backup, escape_key_detector)
          if escape_key_detector.WasEscapePressed():
            print('*** Cancelled at backup %s' % backup, file=self.output)
            return False

        PrintSkippedBackups(skipped_backups, self.output)
      finally:
        escape_key_detector.Shutdown()
    finally:
      backups_manager.Close()

    return True

  def _DeletePathsInBackup(self, backup, escape_key_detector):
    print('Deleting in %s...' % backup.GetName(), file=self.output)

    manifest = lib.Manifest(backup.GetManifestPath())
    manifest.Read()
    num_paths = manifest.GetPathCount()

    paths_to_delete = []

    path_matcher = lib.PathMatcherPathsAndPrefix(self.paths)
    for path in manifest.GetPaths():
      if path_matcher.Matches(path):
        path_info = manifest.RemovePathInfo(path)
        itemized = path_info.GetItemized()
        itemized.new_path = False
        itemized.delete_path = True
        itemized.Print(output=self.output)
        paths_to_delete.append(path)

    if not paths_to_delete:
      return

    manifest_bak_path = lib.GetManifestBackupPath(backup.GetManifestPath())

    if not self.dry_run:
      shutil.copy(backup.GetManifestPath(), manifest_bak_path)
      assert os.path.exists(manifest_bak_path)

      for path in reversed(paths_to_delete):
        full_path = os.path.join(backup.GetContentRootPath(), path)
        parent_dir = os.path.dirname(full_path)
        parent_stat = os.lstat(parent_dir)
        path_stat = os.lstat(full_path)
        if stat.S_ISDIR(path_stat.st_mode):
          os.rmdir(full_path)
        else:
          os.unlink(full_path)
        os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime), follow_symlinks=False)

      manifest.Write()

      print('Verifying %s...' % backup.GetName(), file=self.output)
      verifier = lib.ManifestVerifier(manifest, backup.GetContentRootPath(), self.output,
                                      checksum_path_matcher=lib.PathMatcherNone(),
                                      verbose=self.verbose)
      if not verifier.Verify():
        raise Exception('*** Error: Failed to verify %s' % backup.GetName())

      os.unlink(manifest_bak_path)

    print('Paths: %d deleted, %d total' % (len(paths_to_delete), num_paths), file=self.output)


class BackupNotPruneableMarker(object):
  def __init__(self, config, output, backups_matcher=BackupsMatcher(),
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.backups_matcher = backups_matcher
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def MarkBackupsNotPruneable(self):
    self.manager = BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      for backup in self.manager.GetBackupList():
        if not self.backups_matcher.Matches(backup.GetName()):
          continue
        if backup.IsPruneable():
          print('Marking backup %s as not pruneable' % backup, file=self.output)
          backup.MarkPruneable(pruneable=False, dry_run=self.dry_run)
        else:
          print('Backup %s is already not pruneable' % backup, file=self.output)
    finally:
      self.manager.Close()
    return True


class MetadataRestorer:
  def __init__(self, config, output, mtimes=False, path_matcher=lib.PathMatcherAll(),
               encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.mtimes = mtimes
    self.path_matcher = path_matcher
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.total_paths = 0
    self.total_updated_paths = 0
    self.total_unknown_paths = 0
    self.total_skipped_paths = 0

  def RestoreMetadata(self):
    assert self.mtimes

    checkpoints = ListBackupCheckpoints(self.config.checkpoints_dir)
    if not checkpoints:
      print('*** Error: No previous checkpoints found', file=self.output)
      return False

    last_checkpoint = checkpoints[-1]

    basis_path = last_checkpoint.GetPath()
    basis_manifest = lib.ReadManifestFromImageOrPath(
      basis_path, encryption_manager=self.encryption_manager, dry_run=self.dry_run)

    filters = self.config.GetFilters()

    path_enumerator = lib.PathEnumerator(self.config.src_path, self.output, filters=filters, verbose=self.verbose)

    meta_strs = []
    if self.mtimes:
      meta_strs.append('mtimes')
    print('Restoring metadata (%s)...' % ', '.join(meta_strs), file=self.output)

    for enumerated_path in path_enumerator.Scan():
      self.total_paths += 1

      path = enumerated_path.GetPath()
      if not self.path_matcher.Matches(path):
        self.total_skipped_paths += 1
        continue

      basis_path_info = basis_manifest.GetPathInfo(path)
      if basis_path_info is None:
        self.total_unknown_paths += 1
        continue

      full_path = os.path.join(self.config.src_path, path)
      path_info = lib.PathInfo.FromPath(path, full_path)

      itemized = path_info.GetItemized()
      if self.mtimes and path_info.mtime != basis_path_info.mtime:
        itemized.time_diff = True
        if not self.dry_run:
          os.utime(full_path, (basis_path_info.mtime, basis_path_info.mtime), follow_symlinks=False)

      if itemized.HasDiffs():
        self.total_updated_paths += 1
        print(itemized, file=self.output)

    self._PrintResults()
    return True

  def _PrintResults(self):
    if self.total_paths:
      out_pieces = ['%d total' % self.total_paths]
      if self.total_updated_paths:
        out_pieces.append('%d updated' % self.total_updated_paths)
      if self.total_unknown_paths:
        out_pieces.append('%d unknown' % self.total_unknown_paths)
      if self.total_skipped_paths:
        out_pieces.append('%d skipped' % self.total_skipped_paths)
      print('Paths: %s' % ', '.join(out_pieces), file=self.output)


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
    encryption_manager=lib.EncryptionManager(output=output), checksum_all=cmd_args.checksum_all,
    dry_run=args.dry_run, verbose=args.verbose)
  return creator.Create()


def DoApplyToBackups(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-config', required=True)
  parser.add_argument('--no-checksum-all', dest='checksum_all', action='store_false')
  parser.add_argument('--no-checksum-hardlinks', dest='checksum_hardlinks', action='store_false')
  parser.add_argument('--deduplicate-min-file-size', default=DEDUP_MIN_FILE_SIZE, type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  config = BackupsConfig.Load(cmd_args.backups_config)

  applier = CheckpointsToBackupsApplier(
    config, output=output, encryption_manager=lib.EncryptionManager(output=output),
    checksum_all=cmd_args.checksum_all, checksum_hardlinks=cmd_args.checksum_hardlinks,
    deduplicate_min_file_size=cmd_args.deduplicate_min_file_size,
    dry_run=args.dry_run, verbose=args.verbose)
  return applier.Apply()


def DoCreateBackupsImage(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-image-path', required=True)
  parser.add_argument('--volume-name')
  parser.add_argument('--size', default=lib.DISK_IMAGE_DEFAULT_CAPACITY)
  parser.add_argument('--no-encrypt', dest='encrypt', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  config = BackupsConfig()
  config.image_path = os.path.normpath(cmd_args.backups_image_path)

  creator = BackupsImageCreator(
    config, output=output, volume_name=cmd_args.volume_name, size=cmd_args.size,
    encrypt=cmd_args.encrypt, encryption_manager=lib.EncryptionManager(output=output),
    dry_run=args.dry_run, verbose=args.verbose)
  return creator.CreateImage()


def DoListBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  lister = BackupsLister(
    config, output=output, encryption_manager=lib.EncryptionManager(output=output),
    dry_run=args.dry_run, verbose=args.verbose)
  return lister.List()


def DoVerifyBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--no-full', dest='full', action='store_false')
  parser.add_argument('--continue-on-error', action='store_true')
  parser.add_argument('--no-hdiutil-verify', dest='hdiutil_verify', action='store_false')
  parser.add_argument('--no-checksum-all', dest='checksum_all', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  verifier = BackupsVerifier(
    config, output=output, min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup,
    full=cmd_args.full, continue_on_error=cmd_args.continue_on_error,
    hdiutil_verify=cmd_args.hdiutil_verify, encryption_manager=lib.EncryptionManager(output=output),
    checksum_all=cmd_args.checksum_all, dry_run=args.dry_run, verbose=args.verbose)
  return verifier.Verify()


def DoDeDuplicateBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--min-file-size', default=DEDUP_MIN_FILE_SIZE, type=int)
  parser.add_argument('--match-older-mtimes', action='store_true')
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  deduplicator = BackupsDeDuplicator(
    config, output=output, min_file_size=cmd_args.min_file_size, min_backup=cmd_args.min_backup,
    max_backup=cmd_args.max_backup, match_older_mtimes=cmd_args.match_older_mtimes,
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return deduplicator.DeDuplicate()


def DoAddMissingManifestsToBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  adder = MissingManifestsToBackupsAdder(
    config, output=output, encryption_manager=lib.EncryptionManager(output=output),
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
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return cloner.CloneBackup()


def DoDeleteBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--backup-name', dest='backup_names', action='append', default=[])
  cmd_args = parser.parse_args(args.cmd_args)

  if not cmd_args.backup_names:
    print(('*** Error: One or more --backup-name args required'), file=output)
    return False

  config = GetBackupsConfigFromArgs(cmd_args)

  deleter = BackupsDeleter(
    config, output=output, backup_names=cmd_args.backup_names,
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return deleter.DeleteBackups()


def DoDeleteBackupsInteractive(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  AddBackupsMatcherArgs(parser)
  parser.add_argument('--ignore-matching-renames', action='store_true')
  parser.add_argument('--include-latest-backup', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)
  try:
    backups_matcher = GetBackupsMatcherFromArgs(cmd_args)
  except BackupsMatcherArgsError as e:
    print('*** Error:', e.args[0], file=output)
    return False

  deleter = BackupsInteractiveDeleter(
    config, output=output, backups_matcher=backups_matcher,
    ignore_matching_renames=cmd_args.ignore_matching_renames,
    include_latest_backup=cmd_args.include_latest_backup,
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return deleter.DeleteBackupsInteractively()


def DoDumpUniqueFilesInBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  AddBackupsMatcherArgs(parser)
  parser.add_argument('--ignore-matching-renames', action='store_true')
  parser.add_argument('--match-previous-only', action='store_true')
  parser.add_argument('--match-next-only', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  if cmd_args.match_previous_only and cmd_args.match_next_only:
    raise Exception('Cannot use both --match-previous-only and --match-next-only')

  config = GetBackupsConfigFromArgs(cmd_args)
  try:
    backups_matcher = GetBackupsMatcherFromArgs(cmd_args)
  except BackupsMatcherArgsError as e:
    print('*** Error:', e.args[0], file=output)
    return False

  dumper = UniqueFilesInBackupsDumper(
    config, output=output, backups_matcher=backups_matcher,
    ignore_matching_renames=cmd_args.ignore_matching_renames,
    match_previous_only=cmd_args.match_previous_only, match_next_only=cmd_args.match_next_only,
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return dumper.DumpUniqueFiles()


def DoExtractFromBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  lib.AddPathsArgs(parser)
  parser.add_argument('--output-image-path')
  parser.add_argument('--output-volume-name')
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--no-encrypt', dest='encrypt', action='store_false')
  parser.add_argument('--deduplicate-min-file-size', default=DEDUP_MIN_FILE_SIZE, type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)
  paths = lib.GetPathsFromArgs(cmd_args)

  extractor = PathsFromBackupsExtractor(
    config, output=output, output_image_path=cmd_args.output_image_path,
    output_volume_name=cmd_args.output_volume_name, paths=paths,
    min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup,
    deduplicate_min_file_size=cmd_args.deduplicate_min_file_size, encrypt=cmd_args.encrypt,
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return extractor.ExtractPaths()


def DoMergeIntoBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  parser.add_argument('--from-image-path', required=True)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  parser.add_argument('--deduplicate-min-file-size', default=DEDUP_MIN_FILE_SIZE, type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)

  merger = IntoBackupsMerger(
    config, output=output, from_image_path=cmd_args.from_image_path,
    min_backup=cmd_args.min_backup, max_backup=cmd_args.max_backup,
    deduplicate_min_file_size=cmd_args.deduplicate_min_file_size,
    encryption_manager=lib.EncryptionManager(output=output), dry_run=args.dry_run, verbose=args.verbose)
  return merger.Merge()


def DoDeleteInBackups(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  lib.AddPathsArgs(parser)
  parser.add_argument('--min-backup')
  parser.add_argument('--max-backup')
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)
  paths = lib.GetPathsFromArgs(cmd_args)

  deleter = PathsInBackupsDeleter(
    config, output=output, paths=paths, min_backup=cmd_args.min_backup,
    max_backup=cmd_args.max_backup, encryption_manager=lib.EncryptionManager(output=output),
    dry_run=args.dry_run, verbose=args.verbose)
  return deleter.DeletePaths()


def DoMarkBackupsNotPruneable(args, output):
  parser = argparse.ArgumentParser()
  AddBackupsConfigArgs(parser)
  AddBackupsMatcherArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = GetBackupsConfigFromArgs(cmd_args)
  try:
    backups_matcher = GetBackupsMatcherFromArgs(cmd_args)
  except BackupsMatcherArgsError as e:
    print('*** Error:', e.args[0], file=output)
    return False

  marker = BackupNotPruneableMarker(
    config, output=output, backups_matcher=backups_matcher,
    encryption_manager=lib.EncryptionManager(output=output),
    dry_run=args.dry_run, verbose=args.verbose)
  return marker.MarkBackupsNotPruneable()


def DoRestoreMeta(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-config', required=True)
  parser.add_argument('--mtimes', action='store_true')
  lib.AddPathsArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  config = BackupsConfig.Load(cmd_args.backups_config)
  path_matcher = lib.GetPathMatcherFromArgs(cmd_args)

  if not cmd_args.mtimes:
    print('*** Error: --mtimes arg is required', file=output)
    return False

  if not cmd_args.paths:
    print('*** Error: --path args are required', file=output)
    return False

  metadata_restorer = MetadataRestorer(
    config, output=output, path_matcher=path_matcher, mtimes=cmd_args.mtimes,
    encryption_manager=lib.EncryptionManager(output=output),
    dry_run=args.dry_run, verbose=args.verbose)
  return metadata_restorer.RestoreMetadata()


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
  elif args.command == COMMAND_ADD_MISSING_MANIFESTS_TO_BACKUPS:
    return DoAddMissingManifestsToBackups(args, output=output)
  elif args.command == COMMAND_CLONE_BACKUP:
    return DoCloneBackup(args, output=output)
  elif args.command == COMMAND_DELETE_BACKUPS:
    return DoDeleteBackups(args, output=output)
  elif args.command == COMMAND_DELETE_BACKUPS_INTERACTIVE:
    return DoDeleteBackupsInteractive(args, output=output)
  elif args.command == COMMAND_DUMP_UNIQUE_FILES_IN_BACKUPS:
    return DoDumpUniqueFilesInBackups(args, output=output)
  elif args.command == COMMAND_EXTRACT_FROM_BACKUPS:
    return DoExtractFromBackups(args, output=output)
  elif args.command == COMMAND_MERGE_INTO_BACKUPS:
    return DoMergeIntoBackups(args, output=output)
  elif args.command == COMMAND_DELETE_IN_BACKUPS:
    return DoDeleteInBackups(args, output=output)
  elif args.command == COMMAND_MARK_BACKUPS_NOT_PRUNEABLE:
    return DoMarkBackupsNotPruneable(args, output=output)
  elif args.command == COMMAND_RESTORE_META:
    return DoRestoreMeta(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
