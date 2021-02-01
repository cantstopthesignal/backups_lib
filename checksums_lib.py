import argparse
import os
import re

from . import lib


COMMAND_CREATE = 'create'
COMMAND_VERIFY = 'verify'
COMMAND_SYNC = 'sync'
COMMAND_RENAME_PATHS = 'rename-paths'

COMMANDS = [
  COMMAND_CREATE,
  COMMAND_VERIFY,
  COMMAND_SYNC,
  COMMAND_RENAME_PATHS
]

FILTER_DIR_MERGE_FILENAME = '.adjoined_checksums_filter'

CHECKSUM_FILTERS = [lib.RsyncExclude('/.metadata'),
                    lib.RsyncExclude('.DS_Store'),
                    lib.RsyncFilterDirMerge(FILTER_DIR_MERGE_FILENAME)]

MIN_RENAME_DETECTION_FILE_SIZE = 1


def GetManifestNewPath(manifest_path):
  path = '%s.new' % manifest_path
  assert path.endswith('.pbdata.new')
  return path


class InteractiveChecker:
  def __init__(self):
    self.ready_results = []

  def AddReadyResult(self, result):
    self.ready_results.append(result)

  def ClearReadyResults(self):
    self.ready_results = []

  def Confirm(self, message, output):
    if self.ready_results:
      result = self.ready_results[0]
      del self.ready_results[0]
      print('%s (y/N): %s' % (message, result and 'y' or 'n'), file=output)
      return result

    print('%s (y/N):' % message, end=' ', file=output)
    return input() == 'y'


class ChecksumsError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


class Checksums(object):
  @staticmethod
  def Create(root_path, manifest_path=None, dry_run=False):
    root_path = os.path.normpath(root_path)
    if not os.path.isdir(root_path):
      raise ChecksumsError('Expected %s to be a directory' % root_path)
    if manifest_path is None:
      metadata_path = os.path.join(root_path, lib.METADATA_DIR_NAME)
      if os.path.lexists(metadata_path):
        raise ChecksumsError('Did not expect %s to exist' % metadata_path)
      if not dry_run:
        os.mkdir(metadata_path)
      manifest_path = os.path.join(metadata_path, lib.MANIFEST_FILENAME)
    else:
      if os.path.lexists(manifest_path):
        raise ChecksumsError('Did not expect %s to exist' % manifest_path)
    manifest = lib.Manifest(manifest_path)
    if not dry_run:
      manifest.Write()
    return Checksums(root_path, manifest, dry_run=dry_run)

  @staticmethod
  def Open(root_path, manifest_path=None, dry_run=False):
    root_path = os.path.normpath(root_path)
    if manifest_path is None:
      metadata_path = os.path.join(root_path, lib.METADATA_DIR_NAME)
      manifest_path = os.path.join(metadata_path, lib.MANIFEST_FILENAME)
    manifest = lib.Manifest(manifest_path)
    manifest.Read()
    return Checksums(root_path, manifest, dry_run=dry_run)

  def __init__(self, root_path, manifest, dry_run=False):
    self.root_path = root_path
    self.manifest = manifest
    self.dry_run = dry_run

  def GetRootPath(self):
    return self.root_path

  def GetMetadataPath(self):
    return os.path.join(self.GetRootPath(), METADATA_DIR_NAME)

  def GetManifest(self):
    return self.manifest


class ChecksumsCreator(object):
  def __init__(self, root_path, output, manifest_path=None, dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.manifest_path = manifest_path
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None

  def Create(self):
    try:
      self.checksums = Checksums.Create(
        self.root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except ChecksumsError as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    print('Created checksums metadata for %s' % self.root_path, file=self.output)
    return True


class ChecksumsVerifier(object):
  def __init__(self, root_path, output, manifest_path=None, checksum_all=False,
               path_matcher=lib.MatchAllPathMatcher(), dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.manifest_path = manifest_path
    self.output = output
    self.checksum_all = checksum_all
    self.path_matcher = path_matcher
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.filters = CHECKSUM_FILTERS

  def Verify(self):
    try:
      self.checksums = Checksums.Open(self.root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    escape_key_detector = lib.EscapeKeyDetector()
    try:
      verifier = lib.ManifestVerifier(
        self.checksums.GetManifest(), self.root_path, output=self.output,
        filters=self.filters, manifest_on_top=False, checksum_all=self.checksum_all,
        escape_key_detector=escape_key_detector, path_matcher=self.path_matcher, verbose=self.verbose)
      verify_result = verifier.Verify()
      stats = verifier.GetStats()

      out_pieces = ['%d total (%s)' % (stats.total_paths, lib.FileSizeToString(stats.total_size))]
      if stats.total_mismatched_paths:
        out_pieces.append('%d mismatched (%s)' % (
          stats.total_mismatched_paths, lib.FileSizeToString(stats.total_mismatched_size)))
      if stats.total_checksummed_paths:
        out_pieces.append('%d checksummed (%s)' % (
          stats.total_checksummed_paths, lib.FileSizeToString(stats.total_checksummed_size)))
      if stats.total_skipped_paths:
        out_pieces.append('%d skipped' % stats.total_skipped_paths)
      print('Paths: %s' % ', '.join(out_pieces), file=self.output)

      return verify_result
    finally:
      escape_key_detector.Shutdown()


class ChecksumsSyncer(object):
  INTERACTIVE_CHECKER = InteractiveChecker()

  def __init__(self, root_path, output, manifest_path=None, checksum_all=False, interactive=False,
               detect_renames=True, path_matcher=lib.MatchAllPathMatcher(), dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.manifest_path = manifest_path
    self.checksum_all = checksum_all
    self.interactive = interactive
    self.detect_renames = detect_renames
    self.path_matcher = path_matcher
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.basis_manifest = None
    self.manifest = None
    self.scan_manifest = None
    self.file_enumerator = lib.FileEnumerator(root_path, output, filters=CHECKSUM_FILTERS, verbose=verbose)
    self.escape_key_detector = None
    self.sha256_to_basis_pathinfos = None
    self.size_to_pathinfos = None
    self.total_paths = 0
    self.total_size = 0
    self.total_synced_paths = 0
    self.total_synced_size = 0
    self.total_checksummed_paths = 0
    self.total_checksummed_size = 0
    self.total_renamed_paths = 0
    self.total_renamed_size = 0
    self.total_deleted_paths = 0
    self.total_deleted_size = 0
    self.total_skipped_paths = 0

  def Sync(self):
    try:
      self.checksums = Checksums.Open(self.root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    self.basis_manifest = self.checksums.GetManifest()
    self.manifest = self.basis_manifest.Clone()
    self.manifest.SetPath(GetManifestNewPath(self.basis_manifest.GetPath()))
    self.scan_manifest = lib.Manifest()

    self.escape_key_detector = lib.EscapeKeyDetector()
    try:
      self._SyncInternal()
      if not self.interactive and self.escape_key_detector.WasEscapePressed():
        return False
    finally:
      self.escape_key_detector.Shutdown()
      self.escape_key_detector = None

    self._PrintResults()

    if self.total_synced_paths:
      if not self.dry_run:
        self.manifest.Write()

      if self.interactive:
        if not ChecksumsSyncer.INTERACTIVE_CHECKER.Confirm('Apply update?', self.output):
          print('*** Cancelled ***', file=self.output)
          if not self.dry_run:
            os.unlink(self.manifest.GetPath())
          return False

      if not self.dry_run:
        os.rename(self.manifest.GetPath(), self.basis_manifest.GetPath())

    return True

  def _SyncInternal(self):
    existing_paths = self.basis_manifest.GetPaths()

    for path in self.file_enumerator.Scan():
      if not self.path_matcher.Matches(path):
        self.total_skipped_paths += 1
        continue

      full_path = os.path.join(self.root_path, path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      self.scan_manifest.AddPathInfo(path_info)
      self.total_paths += 1
      if path_info.size is not None:
        self.total_size += path_info.size

    for path in self.scan_manifest.GetPaths():
      if self.escape_key_detector.WasEscapePressed():
        print('*** Cancelled at path %s' % lib.EscapePath(path), file=self.output)
        return

      self._HandleExistingPaths(existing_paths, next_new_path=path)
      self._SyncPathIfChanged(path)

    self._HandleExistingPaths(existing_paths, next_new_path=None)

  def _PrintResults(self):
    if self.total_paths:
      out_pieces = ['%d total (%s)' % (self.total_paths, lib.FileSizeToString(self.total_size))]
      if self.total_synced_paths:
        out_pieces.append('%d synced (%s)' % (
          self.total_synced_paths, lib.FileSizeToString(self.total_synced_size)))
      if self.total_renamed_paths:
        out_pieces.append('%d renamed (%s)' % (
          self.total_renamed_paths, lib.FileSizeToString(self.total_renamed_size)))
      if self.total_deleted_paths:
        out_pieces.append('%d deleted (%s)' % (
          self.total_deleted_paths, lib.FileSizeToString(self.total_deleted_size)))
      if self.total_checksummed_paths:
        out_pieces.append('%d checksummed (%s)' % (
          self.total_checksummed_paths, lib.FileSizeToString(self.total_checksummed_size)))
      if self.total_skipped_paths:
        out_pieces.append('%d skipped' % self.total_skipped_paths)
      print('Paths: %s' % ', '.join(out_pieces), file=self.output)

  def _HandleExistingPaths(self, existing_paths, next_new_path=None):
    while existing_paths:
      next_existing_path = existing_paths[0]

      if self.escape_key_detector.WasEscapePressed():
        print('*** Cancelled at path %s' % lib.EscapePath(next_existing_path), file=self.output)
        return

      if next_new_path is not None and next_existing_path > next_new_path:
        break
      if next_new_path != next_existing_path and self.path_matcher.Matches(next_existing_path):
        self._SyncRemovedPath(next_existing_path)
      del existing_paths[0]

  def _SyncPathIfChanged(self, path):
    full_path = os.path.join(self.root_path, path)
    path_info = self.scan_manifest.GetPathInfo(path)

    basis_path_info = self.basis_manifest.GetPathInfo(path)
    if basis_path_info is None:
      self._SyncNewPath(path, full_path, path_info)
      return

    self.manifest.AddPathInfo(path_info, allow_replace=True)

    checksum_copied = False
    if path_info.path_type == lib.PathInfo.TYPE_FILE:
      if path_info.sha256 is None:
        path_info.sha256 = basis_path_info.sha256
        checksum_copied = True

    itemized = lib.PathInfo.GetItemizedDiff(path_info, basis_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        print(itemized, file=self.output)
      return
    if path_info.path_type == lib.PathInfo.TYPE_FILE:
      if checksum_copied:
        path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
        self.total_checksummed_paths += 1
        self.total_checksummed_size += path_info.size
    if path_info.sha256 != basis_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        print(itemized, file=self.output)
      return

    print(itemized, file=self.output)

    self._AddStatsForSyncedPath(path_info)

  def _SyncNewPath(self, path, full_path, path_info):
    if path_info.path_type == lib.PathInfo.TYPE_FILE:
      if path_info.sha256 is None:
        path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
        self.total_checksummed_paths += 1
        self.total_checksummed_size += path_info.size

    itemized = path_info.GetItemized()
    itemized.new_path = True
    print(itemized, file=self.output)
    self.manifest.AddPathInfo(path_info)

    if (self.detect_renames and path_info.path_type == lib.PathInfo.TYPE_FILE
        and path_info.size >= MIN_RENAME_DETECTION_FILE_SIZE):
      if self.sha256_to_basis_pathinfos is None:
        self.sha256_to_basis_pathinfos = self.basis_manifest.CreateSha256ToPathInfosMap(
          min_file_size=MIN_RENAME_DETECTION_FILE_SIZE)

      dup_path_infos = self.sha256_to_basis_pathinfos.get(path_info.sha256, [])
      analyze_result = lib.AnalyzePathInfoDups(
        path_info, dup_path_infos, replacing_previous=True, verbose=self.verbose)
      for dup_output_line in analyze_result.dup_output_lines:
        print(dup_output_line, file=self.output)

    self._AddStatsForSyncedPath(path_info)

  def _SyncRemovedPath(self, path):
    basis_path_info = self.basis_manifest.GetPathInfo(path)
    itemized = basis_path_info.GetItemized()
    itemized.delete_path = True
    print(itemized, file=self.output)
    self.manifest.RemovePathInfo(path)

    self.total_synced_paths += 1

    if (self.detect_renames and basis_path_info.path_type == lib.PathInfo.TYPE_FILE
        and basis_path_info.size >= MIN_RENAME_DETECTION_FILE_SIZE):
      if self.size_to_pathinfos is None:
        self.size_to_pathinfos = self.scan_manifest.CreateSizeToPathInfosMap(
          min_file_size=MIN_RENAME_DETECTION_FILE_SIZE)

      matching_size_path_infos = self.size_to_pathinfos.get(basis_path_info.size, [])

      dup_path_infos = []
      for path_info in matching_size_path_infos:
        if path_info.sha256 is None:
          if self.escape_key_detector.WasEscapePressed():
            print('*** Cancelled at path %s' % lib.EscapePath(path), file=self.output)
            return

          full_path = os.path.join(self.root_path, path_info.path)
          path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
          self.total_checksummed_paths += 1
          self.total_checksummed_size += path_info.size
        assert basis_path_info.sha256 is not None
        if path_info.sha256 == basis_path_info.sha256:
          dup_path_infos.append(path_info)

      analyze_result = lib.AnalyzePathInfoDups(
        basis_path_info, dup_path_infos, replacing_previous=False, verbose=self.verbose)
      for dup_output_line in analyze_result.dup_output_lines:
        print(dup_output_line, file=self.output)
      if analyze_result.found_matching_rename:
        self.total_renamed_paths += 1
        self.total_renamed_size += basis_path_info.size
      else:
        self.total_deleted_paths += 1
        self.total_deleted_size += basis_path_info.size
    else:
      self.total_deleted_paths += 1

  def _AddStatsForSyncedPath(self, path_info):
    self.total_synced_paths += 1
    if path_info.size is not None:
      self.total_synced_size += path_info.size


class ChecksumsPathRenamer(object):
  def __init__(self, root_path, output, path_regex_from, path_regex_to, manifest_path=None,
               dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.manifest_path = manifest_path
    self.path_regex_from = re.compile(path_regex_from)
    self.path_regex_to = path_regex_to
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None

  def RenamePaths(self):
    try:
      self.checksums = Checksums.Open(self.root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    manifest = self.checksums.GetManifest()

    total_paths = 0
    total_renamed_paths = 0

    for path in manifest.GetPaths():
      path_info = manifest.GetPathInfo(path)
      total_paths += 1

      new_path = self.path_regex_from.sub(self.path_regex_to, path)
      if new_path != path:
        if manifest.HasPath(new_path):
          print('*** Error: renamed to path %s already in manifest' % lib.EscapePath(new_path), file=self.output)
          return False

        print(path_info.GetItemized(), file=self.output)
        print('  renamed to %s' % lib.EscapePath(new_path), file=self.output)
        total_renamed_paths += 1

        manifest.RemovePathInfo(path)
        path_info.path = new_path
        manifest.AddPathInfo(path_info)

    if not self.dry_run and total_renamed_paths:
      manifest.Write()

    print('Paths: %d paths, %d renamed' % (total_paths, total_renamed_paths), file=self.output)
    return True


def DoCreate(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_creator = ChecksumsCreator(
    cmd_args.root_path, manifest_path=cmd_args.manifest_path, output=output, dry_run=args.dry_run,
    verbose=args.verbose)
  return checksums_creator.Create()


def DoVerify(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  parser.add_argument('--checksum-all', action='store_true')
  lib.AddPathsArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  path_matcher = lib.GetPathMatcherFromArgs(cmd_args)

  checksums_verifier = ChecksumsVerifier(
    cmd_args.root_path, output=output, manifest_path=cmd_args.manifest_path,
    checksum_all=cmd_args.checksum_all, path_matcher=path_matcher, dry_run=args.dry_run,
    verbose=args.verbose)
  return checksums_verifier.Verify()


def DoSync(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  parser.add_argument('--checksum-all', action='store_true')
  parser.add_argument('--interactive', action='store_true')
  parser.add_argument('--no-detect-renames', dest='detect_renames', action='store_false')
  lib.AddPathsArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  path_matcher = lib.GetPathMatcherFromArgs(cmd_args)

  checksums_syncer = ChecksumsSyncer(
    cmd_args.root_path, output=output, manifest_path=cmd_args.manifest_path,
    checksum_all=cmd_args.checksum_all, interactive=cmd_args.interactive,
    detect_renames=cmd_args.detect_renames, path_matcher=path_matcher,
    dry_run=args.dry_run, verbose=args.verbose)
  return checksums_syncer.Sync()


def DoRenamePaths(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  parser.add_argument('--path-regex-from', required=True)
  parser.add_argument('--path-regex-to', required=True)
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_path_renamer = ChecksumsPathRenamer(
    cmd_args.root_path, output=output, manifest_path=cmd_args.manifest_path,
    path_regex_from=cmd_args.path_regex_from, path_regex_to=cmd_args.path_regex_to,
    dry_run=args.dry_run, verbose=args.verbose)
  return checksums_path_renamer.RenamePaths()


def DoCommand(args, output):
  if args.command == COMMAND_CREATE:
    return DoCreate(args, output=output)
  elif args.command == COMMAND_VERIFY:
    return DoVerify(args, output=output)
  elif args.command == COMMAND_SYNC:
    return DoSync(args, output=output)
  elif args.command == COMMAND_RENAME_PATHS:
    return DoRenamePaths(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
