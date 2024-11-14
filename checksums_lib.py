import argparse
import io
import os
import pipes
import platform
import re
import shutil
import stat
import subprocess
import tempfile

from . import lib


COMMAND_CREATE = 'create'
COMMAND_DIFF = 'diff'
COMMAND_VERIFY = 'verify'
COMMAND_SYNC = 'sync'
COMMAND_RENAME_PATHS = 'rename-paths'
COMMAND_IMAGE_FROM_FOLDER = 'image-from-folder'
COMMAND_SAFE_COPY = 'safe-copy'
COMMAND_SAFE_MOVE = 'safe-move'
COMMAND_RESTORE_META = 'restore-meta'

COMMANDS = [
  COMMAND_CREATE,
  COMMAND_DIFF,
  COMMAND_VERIFY,
  COMMAND_SYNC,
  COMMAND_RENAME_PATHS,
  COMMAND_IMAGE_FROM_FOLDER,
  COMMAND_SAFE_COPY,
  COMMAND_SAFE_MOVE,
  COMMAND_RESTORE_META,
]

FILTER_DIR_MERGE_FILENAME = '.adjoined_checksums_filter'

CHECKSUM_FILTERS = [lib.FilterRuleExclude('/.metadata'),
                    lib.FilterRuleExclude('.DS_Store'),
                    lib.FilterRuleDirMerge(FILTER_DIR_MERGE_FILENAME)]

MIN_RENAME_DETECTION_FILE_SIZE = 1
MAX_RENAME_DETECTION_MATCHING_SIZE_FILE_COUNT = 10


def GetManifestNewPath(manifest_path):
  path = '%s.new' % manifest_path
  assert path.endswith('.pbdata.new')
  return path


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
    return os.path.join(self.GetRootPath(), lib.METADATA_DIR_NAME)

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


class ChecksumsDiffer(object):
  def __init__(self, path1, path2, root_path1=None, root_path2=None,
               manifest_path1=None, manifest_path2=None, output=None,
               dry_run=False, verbose=False):
    self.path1 = os.path.normpath(path1)
    self.path2 = os.path.normpath(path2)
    self.root_path1 = root_path1
    self.root_path2 = root_path2
    self.manifest_path1 = manifest_path1
    self.manifest_path2 = manifest_path2
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums1 = None
    self.checksums2 = None

  def Diff(self):
    self.path1, self.root_path1 = self._LocatePathAndRoot(self.path1, self.root_path1)
    self.path2, self.root_path2 = self._LocatePathAndRoot(self.path2, self.root_path2)
    if self.root_path1 is None or self.root_path2 is None:
      return False

    try:
      self.checksums1 = Checksums.Open(self.root_path1, manifest_path=self.manifest_path1, dry_run=self.dry_run)
      self.checksums2 = Checksums.Open(self.root_path2, manifest_path=self.manifest_path2, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    return self._DiffInternal()

  def _DiffInternal(self):
    manifest1 = self.checksums1.GetManifest()
    manifest2 = self.checksums2.GetManifest()

    cmp_manifest1 = self._CreateCmpManifest(manifest1, self.path1)
    cmp_manifest2 = self._CreateCmpManifest(manifest2, self.path2)

    diff_dumper = lib.ManifestDiffDumper(
      first_manifest=cmp_manifest1, second_manifest=cmp_manifest2, output=self.output, verbose=self.verbose)
    diff_dumper.DumpDiff()
    stats = diff_dumper.GetStats()

    out_pieces = ['%d total' % stats.total_paths]
    if stats.total_matched_paths:
      out_pieces.append('%d matched (%s)' % (
        stats.total_matched_paths, lib.FileSizeToString(stats.total_matched_size)))
    if stats.total_mismatched_paths:
      out_pieces.append('%d mismatched (%s)' % (
        stats.total_mismatched_paths, lib.FileSizeToString(stats.total_mismatched_size)))
    print('Paths: %s' % ', '.join(out_pieces), file=self.output)

    return not stats.total_mismatched_paths

  def _CreateCmpManifest(self, manifest, match_path):
    cmp_manifest = lib.Manifest()

    for path, path_info in manifest.GetPathMap().items():
      if path == match_path or match_path == '.' or path.startswith(match_path + '/'):
        cmp_path_info = path_info.Clone()
        cmp_path_info.path = os.path.relpath(path, match_path)
        cmp_manifest.AddPathInfo(cmp_path_info)

    return cmp_manifest

  def _LocatePathAndRoot(self, path, root_path=None):
    path = os.path.normpath(os.path.abspath(path))
    if root_path is None:
      parent_dir = os.path.isdir(path) and path or os.path.dirname(path)
      while parent_dir:
        if os.path.exists(os.path.join(parent_dir, lib.METADATA_DIR_NAME, lib.MANIFEST_FILENAME)):
          root_path = parent_dir
          break
        if parent_dir == '/':
          break
        parent_dir = os.path.dirname(parent_dir)
      if root_path is None:
        print('*** Error: Could not determine the checksums root path for %s'
              % lib.EscapePath(path), file=self.output)
        return path, None
    path = os.path.relpath(path, root_path)
    return path, root_path


class ChecksumsVerifier(object):
  def __init__(self, root_or_image_path, output, manifest_path=None,
               path_matcher=lib.PathMatcherAll(), checksum_path_matcher=lib.PathMatcherNone(),
               dry_run=False, verbose=False,
               encryption_manager=None, hdiutil_verify=True):
    if root_or_image_path is None:
      raise Exception('root_or_image_path cannot be None')
    self.root_or_image_path = root_or_image_path
    self.manifest_path = manifest_path
    self.output = output
    self.path_matcher = path_matcher
    self.checksum_path_matcher = checksum_path_matcher
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.filters = CHECKSUM_FILTERS
    self.encryption_manager = encryption_manager
    self.hdiutil_verify = hdiutil_verify

  def Verify(self):
    if lib.IsLikelyPathToDiskImage(self.root_or_image_path):
      with lib.ImageAttacher(
          self.root_or_image_path, readonly=True, encryption_manager=self.encryption_manager,
          hdiutil_verify=self.hdiutil_verify) as attacher:
        return self._VerifyRootPath(attacher.GetMountPoint())
    else:
      return self._VerifyRootPath(self.root_or_image_path)

  def _VerifyRootPath(self, root_path):
    try:
      self.checksums = Checksums.Open(root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    escape_key_detector = lib.EscapeKeyDetector()
    try:
      verifier = lib.ManifestVerifier(
        self.checksums.GetManifest(), root_path, output=self.output,
        filters=self.filters, manifest_on_top=False, checksum_path_matcher=self.checksum_path_matcher,
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
  INTERACTIVE_CHECKER = lib.InteractiveChecker()

  def __init__(self, root_path, output, manifest_path=None, checksum_all=False, interactive=False,
               detect_renames=True, path_matcher=lib.PathMatcherAll(), dry_run=False, verbose=False):
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
    self.path_enumerator = lib.PathEnumerator(root_path, output, filters=CHECKSUM_FILTERS, verbose=verbose)
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
    escape_key_pressed = False
    try:
      self._SyncInternal()
      escape_key_pressed = self.escape_key_detector.WasEscapePressed()
    finally:
      self.escape_key_detector.Shutdown()
      self.escape_key_detector = None

    self._PrintResults()

    if self.total_synced_paths:
      if not self.dry_run:
        self.manifest.Write()

      if self.interactive or escape_key_pressed:
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

    for enumerated_path in self.path_enumerator.Scan():
      path = enumerated_path.GetPath()
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
    if path_info.HasFileContents():
      if path_info.sha256 is None:
        path_info.sha256 = basis_path_info.sha256
        checksum_copied = True

    itemized = lib.PathInfo.GetItemizedDiff(path_info, basis_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        itemized.Print(output=self.output)
      return
    if path_info.HasFileContents():
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
        itemized.Print(output=self.output)
      return

    find_matching_renames_results = self._FindMatchingRenames(basis_path_info)
    if find_matching_renames_results is None:
      return
    found_matching_rename, dup_output_lines = find_matching_renames_results

    itemized.Print(output=self.output, found_matching_rename=found_matching_rename)
    for dup_output_line in dup_output_lines:
      print(dup_output_line, file=self.output)

    self._AddStatsForSyncedPath(path_info)

  def _SyncNewPath(self, path, full_path, path_info):
    if path_info.HasFileContents():
      if path_info.sha256 is None:
        path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
        self.total_checksummed_paths += 1
        self.total_checksummed_size += path_info.size

    itemized = path_info.GetItemized()
    itemized.new_path = True
    itemized.Print(output=self.output)
    self.manifest.AddPathInfo(path_info)

    if (self.detect_renames and path_info.HasFileContents()
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
    self.manifest.RemovePathInfo(path)

    self.total_synced_paths += 1

    find_matching_renames_results = self._FindMatchingRenames(basis_path_info)
    if find_matching_renames_results is None:
      return
    found_matching_rename, dup_output_lines = find_matching_renames_results

    itemized.Print(output=self.output, found_matching_rename=found_matching_rename)
    for dup_output_line in dup_output_lines:
      print(dup_output_line, file=self.output)

    if found_matching_rename:
      self.total_renamed_paths += 1
      self.total_renamed_size += basis_path_info.size
    else:
      self.total_deleted_paths += 1
      if basis_path_info.HasFileContents():
        self.total_deleted_size += basis_path_info.size

  def _FindMatchingRenames(self, basis_path_info):
    found_matching_rename = False
    dup_output_lines = []

    if (self.detect_renames and basis_path_info.HasFileContents()
        and basis_path_info.size >= MIN_RENAME_DETECTION_FILE_SIZE):
      if self.size_to_pathinfos is None:
        self.size_to_pathinfos = self.scan_manifest.CreateSizeToPathInfosMap(
          min_file_size=MIN_RENAME_DETECTION_FILE_SIZE)

      matching_size_path_infos = self.size_to_pathinfos.get(basis_path_info.size, [])

      if len(matching_size_path_infos) > MAX_RENAME_DETECTION_MATCHING_SIZE_FILE_COUNT:
        dup_output_lines = [
          '  too many potential renames to check: %d > %d'
          % (len(matching_size_path_infos), MAX_RENAME_DETECTION_MATCHING_SIZE_FILE_COUNT)]
      else:
        dup_path_infos = []
        for path_info in matching_size_path_infos:
          if path_info.path == basis_path_info.path:
            continue
          if path_info.sha256 is None:
            if self.escape_key_detector.WasEscapePressed():
              print('*** Cancelled at path %s' % lib.EscapePath(basis_path_info.path), file=self.output)
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
        dup_output_lines = analyze_result.dup_output_lines
        found_matching_rename = analyze_result.found_matching_rename

    return (found_matching_rename, dup_output_lines)

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
          print('*** Error: Renamed to path %s already in manifest' % lib.EscapePath(new_path), file=self.output)
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


class ImageFromFolderCreator(object):
  def __init__(self, root_path, output_path, output, volume_name=None, compressed=True, temp_dir=None,
               dry_run=False, verbose=False, encryption_manager=None, encrypt=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output_path = output_path
    self.volume_name = volume_name
    self.compressed = compressed
    self.temp_dir = temp_dir
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.encryption_manager = encryption_manager
    self.encrypt = encrypt
    self.password = None

  def CreateImage(self):
    if not os.path.isdir(self.root_path):
      print('*** Error: Root path %s is not a directory' % lib.EscapePath(self.root_path), file=self.output)
      return False
    if os.path.lexists(self.output_path):
      print('*** Error: Output path %s already exists' % lib.EscapePath(self.output_path), file=self.output)
      return False
    if self.temp_dir is not None and not os.path.isdir(self.temp_dir):
      print('*** Error: Temporary dir %s is not a directory' % lib.EscapePath(self.temp_dir), file=self.output)
      return False
    image_ext = lib.SplitImageExt(self.output_path)[1]
    if platform.system() == lib.PLATFORM_DARWIN:
      if image_ext not in ['.sparseimage', '.sparsebundle', '.dmg']:
        raise Exception('Unexpected disk image extension %s' % image_ext)
    else:
      if self.encrypt and image_ext != '.luks.img':
        raise Exception('Encrypted images should have the extension .luks.img')
      elif not self.encrypt and image_ext != '.img':
        raise Exception('Non-Encrypted images should have the extension .img')
    tmp = tempfile.NamedTemporaryFile(
      delete=False, dir=self.temp_dir, suffix=image_ext)
    try:
      tmp.close()
      return self._CreateImageInner(rw_image_path=tmp.name)
    finally:
      if os.path.lexists(tmp.name):
        os.unlink(tmp.name)
    return True

  def _CreateImageInner(self, rw_image_path):
    if self.dry_run:
      return True

    if self.encrypt:
      self.password = self.encryption_manager.CreatePassword(self.output_path)

    self._CreateRwImageFromFolder(rw_image_path=rw_image_path)
    with lib.ImageAttacher(
        rw_image_path, readonly=False, encryption_manager=self.encryption_manager) as attacher:
      has_existing_manifest = os.path.exists(os.path.join(
        attacher.GetMountPoint(), lib.METADATA_DIR_NAME, lib.MANIFEST_FILENAME))
      if has_existing_manifest:
        print('Using existing manifest from source path', file=self.output)
      else:
        create_output = io.StringIO()
        checksums_creator = ChecksumsCreator(
          attacher.GetMountPoint(), output=create_output, dry_run=self.dry_run,
          verbose=self.verbose)
        if not checksums_creator.Create():
          print(create_output.getvalue(), file=self.output)
          return False
      self._ReSyncSymlinkTimes(attacher.GetMountPoint())
      self._ReSyncRootDirectory(attacher.GetMountPoint())
      if not has_existing_manifest or platform.system() == lib.PLATFORM_LINUX:
        checksums_syncer = ChecksumsSyncer(
          attacher.GetMountPoint(), output=self.output, dry_run=self.dry_run,
          checksum_all=True, verbose=self.verbose)
        if not checksums_syncer.Sync():
          return False

    self._CreateRoImage(source_path=rw_image_path, output_path=self.output_path)
    try:
      if not self._VerifyAndComplete():
        os.unlink(self.output_path)
        return False
      return True
    except:
      if os.path.lexists(self.output_path):
        os.unlink(self.output_path)
      raise

  def _ReSyncSymlinkTimes(self, dest_root):
    path_enumerator = lib.PathEnumerator(self.root_path, self.output, filters=[], verbose=self.verbose)
    for enumerated_path in path_enumerator.Scan():
      path = enumerated_path.GetPath()
      full_path = os.path.join(self.root_path, path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.path_type == lib.PathInfo.TYPE_SYMLINK:
        dest_full_path = os.path.join(dest_root, path)
        os.utime(dest_full_path, (path_info.mtime, path_info.mtime), follow_symlinks=False)

  def _ReSyncRootDirectory(self, dest_root):
    path_datas = [lib.PathSyncer.PathData('.')]
    path_syncer = lib.PathSyncer(path_datas, self.root_path, dest_root, output=self.output,
                                 dry_run=self.dry_run, verbose=self.verbose)
    path_syncer.Sync()

  def _VerifyAndComplete(self):
    image_manifest = None
    with lib.ImageAttacher(
        self.output_path, readonly=True, encryption_manager=self.encryption_manager) as attacher:
      print('Verifying checksums in %s...' % lib.EscapePath(self.output_path), file=self.output)
      verify_output = io.StringIO()
      checksums_verifier = ChecksumsVerifier(
        attacher.GetMountPoint(), output=verify_output,
        checksum_path_matcher=lib.PathMatcherAll(), dry_run=self.dry_run, verbose=self.verbose)
      if not checksums_verifier.Verify():
        print(verify_output.getvalue(), file=self.output)
        return False
      image_manifest = Checksums.Open(attacher.GetMountPoint()).GetManifest()

    print('Verifying source tree matches...', file=self.output)
    if platform.system() == lib.PLATFORM_LINUX:
      image_manifest_compare = image_manifest.Clone()
      image_manifest_compare.RemovePathInfo('lost+found')
    else:
      image_manifest_compare = image_manifest
    source_verifier = lib.ManifestVerifier(
      image_manifest_compare, self.root_path, output=self.output,
      filters=CHECKSUM_FILTERS, checksum_path_matcher=lib.PathMatcherAll(),
      verbose=self.verbose)
    if not source_verifier.Verify():
      return False
    source_total_size = source_verifier.GetStats().total_size

    output_stat = os.lstat(self.output_path)
    print('Created image %s (%s); Source size %s'
          % (lib.EscapePath(self.output_path), lib.FileSizeToString(output_stat.st_size),
             lib.FileSizeToString(source_total_size)), file=self.output)
    return True

  def _CreateRwImageFromFolder(self, rw_image_path):
    if platform.system() == lib.PLATFORM_DARWIN:
      self._CreateRwImageFromFolderDarwin(rw_image_path)
    else:
      self._CreateRwImageFromFolderLinux(rw_image_path)

  def _CreateRwImageFromFolderDarwin(self, rw_image_path):
    assert not self.dry_run
    print('Creating temporary image from folder %s...'
          % lib.EscapePath(self.root_path), file=self.output)
    cmd = ['hdiutil', 'create', '-fs', 'APFS', '-format', 'UDRW', '-ov', '-quiet', '-atomic',
           '-srcfolder', self.root_path]
    if self.volume_name is not None:
      cmd.extend(['-volname', self.volume_name])
    if self.encrypt:
      cmd.extend(['-encryption', lib.ENCRYPTION_AES_256, '-stdinpass'])
    cmd.append(rw_image_path)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
    if self.encrypt:
      p.stdin.write(self.password)
    p.stdin.close()
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))
    if self.encrypt:
      _, image_uuid = lib.GetDiskImageHelper().GetImageEncryptionDetails(rw_image_path)
      assert image_uuid
      self.encryption_manager.SavePassword(self.password, image_uuid)

  def _CreateRwImageFromFolderLinux(self, rw_image_path):
    assert not self.dry_run
    print('Creating temporary image from folder %s...'
          % lib.EscapePath(self.root_path), file=self.output)
    needed_size = (
      int(lib.GetPathTreeSize(self.root_path) * 1.1)
      + lib.FileSizeStringToBytes('100mb'))
    encryption = None
    if self.encrypt:
      encryption = lib.ENCRYPTION_AES_256
    lib.GetDiskImageHelper().CreateImage(
      rw_image_path, filesystem=lib.FILESYSTEM_EXT4, size='%db' % needed_size, volume_name=self.volume_name,
      encryption=encryption, password=self.password)
    if self.encrypt:
      _, image_uuid = lib.GetDiskImageHelper().GetImageEncryptionDetails(rw_image_path)
      assert image_uuid
      self.encryption_manager.SavePassword(self.password, image_uuid)
    with lib.ImageAttacher(
        rw_image_path, readonly=False, encryption_manager=self.encryption_manager) as attacher:
      lib.Rsync(self.root_path, attacher.GetMountPoint(), output=self.output,
                dry_run=False, verbose=self.verbose)

  def _CreateRoImage(self, source_path, output_path):
    if platform.system() == lib.PLATFORM_DARWIN:
      self._CreateRoImageDarwin(source_path, output_path)
    else:
      self._CreateRoImageLinux(source_path, output_path)

  def _CreateRoImageDarwin(self, source_path, output_path):
    assert not self.dry_run
    assert not os.path.lexists(output_path)
    image_format = 'UDRO'
    if self.compressed:
      image_format = 'UDZO'
    print('Converting to image %s with format %s...'
          % (lib.EscapePath(output_path), image_format), file=self.output)
    cmd = ['hdiutil', 'convert', '-format', image_format, '-quiet', '-o', output_path]
    if self.encrypt:
      cmd.extend(['-encryption', lib.ENCRYPTION_AES_256, '-stdinpass'])
    cmd.append(source_path)
    p = subprocess.Popen(['expect'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    with p.stdin:
      p.stdin.write('set timeout 120\n')
      p.stdin.write('log_user 0\n')
      p.stdin.write('spawn %s\n' % ' '.join([self._QuoteTclString(a) for a in cmd]))
      if self.encrypt:
        p.stdin.write('expect "Enter disk image passphrase:"\n')
        p.stdin.write('send %s\n' % self._QuoteTclString(self.password))
        p.stdin.write('send "\n"\n')
        p.stdin.write('expect "Enter password to access *"\n')
        p.stdin.write('send %s\n' % self._QuoteTclString(self.password))
        p.stdin.write('send "\n"\n')
      p.stdin.write('expect eof\n')
      p.stdin.write('lassign [wait] pid spawnid os_error_flag value\n')
      p.stdin.write('puts "exit status: $value"\n')
    child_result_code = None
    with p.stdout:
      output = p.stdout.read()
      m = re.match('^exit status: ([0-9]+)$', output.strip())
      assert m
      child_result_code = int(m.group(1))
    if p.wait():
      raise Exception('expect command failed')
    if child_result_code:
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))
    if self.encrypt:
      _, image_uuid = lib.GetDiskImageHelper().GetImageEncryptionDetails(output_path)
      assert image_uuid
      self.encryption_manager.SavePassword(self.password, image_uuid)

  def _QuoteTclString(self, s):
    return '"%s"' % s.replace('\\', '\\\\').replace('[', '\\[').replace('$', '\\$').replace('"', '\\"')

  def _CreateRoImageLinux(self, source_path, output_path):
    assert not self.dry_run
    assert not os.path.lexists(output_path)

    print('Converting to read only image %s...'
          % lib.EscapePath(output_path), file=self.output)

    old_stat = os.lstat(source_path)

    compactor = lib.ImageCompactor(
      source_path, output=self.output, dry_run=False, verbose=self.verbose,
      encryption_manager=self.encryption_manager)
    if not compactor.Compact():
      raise Exception('Failed to compact image %r' % source_path)

    shutil.copyfile(source_path, output_path)

    mode = os.stat(source_path).st_mode
    ro_mask = 0o777 ^ (stat.S_IWRITE | stat.S_IWGRP | stat.S_IWOTH)
    os.chmod(output_path, mode & ro_mask)


class SafeCopyOrMover(object):
  FORCE_FROM_PARENT_DIR_MTIME_CHANGE_FOR_TEST = False

  def __init__(self, from_path, to_path, output,
               move=False, dry_run=False, verbose=False):
    if from_path is None:
      raise Exception('from_path cannot be None')
    if to_path is None:
      raise Exception('to_path cannot be None')
    self.from_path = from_path
    self.to_path = to_path
    self.output = output
    self.move = move
    self.dry_run = dry_run
    self.verbose = verbose

  def SafeCopyOrMove(self):
    if os.path.isdir(self.to_path):
      self.to_path = os.path.join(self.to_path, os.path.basename(self.from_path))

    abs_from_path = os.path.abspath(self.from_path)
    abs_to_path = os.path.abspath(self.to_path)

    from_root_path = self._FindRootPath(abs_from_path)
    to_root_path = self._FindRootPath(abs_to_path)
    if from_root_path == abs_from_path:
      print('*** Error: Cannot move manifest root path %s' % lib.EscapePath(self.from_path), file=self.output)
      return False
    assert abs_to_path != to_root_path
    if from_root_path is None:
      print('*** Error: Could not find manifest for from path %s' % lib.EscapePath(self.from_path), file=self.output)
      return False
    if to_root_path is None:
      print('*** Error: Could not find manifest for to path %s' % lib.EscapePath(self.to_path), file=self.output)
      return False

    from_rel_path = os.path.relpath(abs_from_path, from_root_path)
    to_rel_path = os.path.relpath(abs_to_path, to_root_path)
    if os.path.commonprefix([lib.METADATA_DIR_NAME, from_rel_path]):
      print('*** Error: From path %s cannot be within metadata dir' % lib.EscapePath(self.from_path), file=self.output)
      return False
    if os.path.commonprefix([lib.METADATA_DIR_NAME, to_rel_path]):
      print('*** Error: To path %s cannot be within metadata dir' % lib.EscapePath(self.to_path), file=self.output)
      return False

    if not os.path.lexists(abs_from_path):
      print('*** Error: From path %s does not exist' % lib.EscapePath(self.from_path), file=self.output)
      return False
    if os.path.lexists(abs_to_path):
      print('*** Error: To path %s already exists' % lib.EscapePath(self.to_path), file=self.output)
      return False
    if not os.path.isdir(os.path.dirname(abs_to_path)):
      print('*** Error: To path %s\'s parent dir does not exist' % lib.EscapePath(self.to_path), file=self.output)
      return False

    print('Verifying manifest for from root %s...' % lib.EscapePath(from_root_path), file=self.output)
    verify_output = io.StringIO()
    checksums_verifier = ChecksumsVerifier(
      from_root_path, output=verify_output,
      checksum_path_matcher=lib.PathMatcherNone(), dry_run=self.dry_run, verbose=self.verbose)
    if not checksums_verifier.Verify():
      print(verify_output.getvalue(), file=self.output)
      return False

    if from_root_path != to_root_path:
      print('Verifying manifest for to root %s...' % lib.EscapePath(to_root_path), file=self.output)
      verify_output = io.StringIO()
      checksums_verifier = ChecksumsVerifier(
        to_root_path, output=verify_output,
        checksum_path_matcher=lib.PathMatcherNone(), dry_run=self.dry_run, verbose=self.verbose)
      if not checksums_verifier.Verify():
        print(verify_output.getvalue(), file=self.output)
        return False

    print('Copying %s to %s...'
          % (lib.EscapePath(self.from_path), lib.EscapePath(self.to_path)), file=self.output)

    lib.Rsync(abs_from_path, abs_to_path, output=self.output,
              force_directories=os.path.isdir(abs_from_path),
              dry_run=self.dry_run, verbose=True)

    try:
      from_checksums = Checksums.Open(from_root_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    if from_root_path != to_root_path:
      try:
        to_checksums = Checksums.Open(to_root_path, dry_run=self.dry_run)
      except (ChecksumsError, lib.ManifestError) as e:
        print('*** Error: %s' % e.args[0], file=self.output)
        return False
    else:
      to_checksums = from_checksums

    print('Adding manifest entries...', file=self.output)

    from_manifest = from_checksums.GetManifest()
    to_manifest = to_checksums.GetManifest()

    to_parent_dir_path_info = lib.PathInfo.FromPath(
      os.path.dirname(to_rel_path) or '.', os.path.dirname(abs_to_path))
    assert to_parent_dir_path_info.path_type == lib.PathInfo.TYPE_DIR
    existing_to_parent_dir_path_info = to_manifest.GetPathInfo(to_parent_dir_path_info.path)
    to_manifest.AddPathInfo(to_parent_dir_path_info, allow_replace=True)
    itemized = lib.PathInfo.GetItemizedDiff(to_parent_dir_path_info, existing_to_parent_dir_path_info)
    if itemized.HasDiffs():
      print(itemized, file=self.output)

    sha256_to_to_pathinfos = to_manifest.CreateSha256ToPathInfosMap(
      min_file_size=MIN_RENAME_DETECTION_FILE_SIZE)

    from_path_matcher = lib.PathMatcherPathsAndPrefix([from_rel_path])
    for path in from_manifest.GetPaths():
      if from_path_matcher.Matches(path):
        path_info = from_manifest.GetPathInfo(path).Clone()
        if path_info.path != from_rel_path:
          path_info.path = os.path.join(to_rel_path, os.path.relpath(path_info.path, from_rel_path))
        else:
          path_info.path = to_rel_path
        to_manifest.AddPathInfo(path_info)

        itemized = path_info.GetItemized()
        itemized.new_path = True
        print(itemized, file=self.output)

        if path_info.HasFileContents() and path_info.size >= MIN_RENAME_DETECTION_FILE_SIZE:
          dup_path_infos = sha256_to_to_pathinfos.get(path_info.sha256, [])
          analyze_result = lib.AnalyzePathInfoDups(
            path_info, dup_path_infos, replacing_previous=True, verbose=self.verbose)
          for dup_output_line in analyze_result.dup_output_lines:
            print(dup_output_line, file=self.output)

    if not self.dry_run:
      to_manifest.Write()

    print('Verifying copied files...', file=self.output)

    checksums_verifier = ChecksumsVerifier(
      to_root_path, output=self.output,
      checksum_path_matcher=lib.PathMatcherPathsAndPrefix([to_rel_path]),
      dry_run=self.dry_run, verbose=self.verbose)

    if not checksums_verifier.Verify():
      return False
    if not self.move:
      return True

    print('Removing from files and manifest entries...', file=self.output)

    for path in reversed(from_manifest.GetPaths()):
      if from_path_matcher.Matches(path):
        path_info = from_manifest.GetPathInfo(path)
        from_manifest.RemovePathInfo(path_info.path)

        itemized = path_info.GetItemized()
        itemized.delete_path = True
        print(itemized, file=self.output)

        if not self.dry_run:
          full_path = os.path.join(from_root_path, path_info.path)
          if path_info.path_type == lib.PathInfo.TYPE_DIR:
            os.rmdir(full_path)
          else:
            os.unlink(full_path)

    from_parent_dir_path_info = lib.PathInfo.FromPath(
      os.path.dirname(from_rel_path) or '.', os.path.dirname(abs_from_path))
    assert from_parent_dir_path_info.path_type == lib.PathInfo.TYPE_DIR
    existing_from_parent_dir_path_info = from_manifest.GetPathInfo(from_parent_dir_path_info.path)
    from_manifest.AddPathInfo(from_parent_dir_path_info, allow_replace=True)
    itemized = lib.PathInfo.GetItemizedDiff(from_parent_dir_path_info, existing_from_parent_dir_path_info)
    if SafeCopyOrMover.FORCE_FROM_PARENT_DIR_MTIME_CHANGE_FOR_TEST:
      itemized.time_diff = True
    if itemized.HasDiffs():
      print(itemized, file=self.output)

    if not self.dry_run:
      from_manifest.Write()

    print('Verifying from checksums...', file=self.output)

    checksums_verifier = ChecksumsVerifier(
      from_root_path, output=self.output,
      checksum_path_matcher=lib.PathMatcherNone(),
      dry_run=self.dry_run, verbose=self.verbose)
    return checksums_verifier.Verify()

  def _FindRootPath(self, path):
    check_dir = path
    while check_dir not in ['', '/']:
      if os.path.isfile(os.path.join(check_dir, lib.METADATA_DIR_NAME, lib.MANIFEST_FILENAME)):
        assert check_dir.startswith('/')
        return check_dir
      check_dir = os.path.dirname(check_dir)


class MetadataRestorer(object):
  def __init__(self, root_path, output, manifest_path=None, mtimes=False,
               path_matcher=lib.PathMatcherAll(), dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.manifest_path = manifest_path
    self.mtimes = mtimes
    self.path_matcher = path_matcher
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.manifest = None
    self.path_enumerator = lib.PathEnumerator(root_path, output, filters=CHECKSUM_FILTERS, verbose=verbose)
    self.total_paths = 0
    self.total_updated_paths = 0
    self.total_unknown_paths = 0
    self.total_skipped_paths = 0

  def RestoreMetadata(self):
    assert self.mtimes

    try:
      self.checksums = Checksums.Open(self.root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    self.manifest = self.checksums.GetManifest()

    meta_strs = []
    if self.mtimes:
      meta_strs.append('mtimes')
    print('Restoring metadata (%s)...' % ', '.join(meta_strs), file=self.output)

    for enumerated_path in self.path_enumerator.Scan():
      self.total_paths += 1

      path = enumerated_path.GetPath()
      if not self.path_matcher.Matches(path):
        self.total_skipped_paths += 1
        continue

      basis_path_info = self.manifest.GetPathInfo(path)
      if basis_path_info is None:
        self.total_unknown_paths += 1
        continue

      full_path = os.path.join(self.root_path, path)
      path_info = lib.PathInfo.FromPath(path, full_path)

      itemized = path_info.GetItemized()
      if self.mtimes and path_info.mtime != basis_path_info.mtime:
        itemized.time_diff = True
        if not self.dry_run:
          os.utime(full_path, (basis_path_info.mtime, basis_path_info.mtime), follow_symlinks=False)

      if itemized.HasDiffs():
        self.total_updated_paths += 1
        print(itemized, file=self.output)
        if self.verbose:
          if path_info is not None:
            print('<', path_info.ToString(
              shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
          if basis_path_info is not None:
            print('>', basis_path_info.ToString(
              shorten_sha256=True, shorten_xattr_hash=True), file=self.output)

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


def DoCreate(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_creator = ChecksumsCreator(
    cmd_args.root_path, manifest_path=cmd_args.manifest_path, output=output, dry_run=args.dry_run,
    verbose=args.verbose)
  return checksums_creator.Create()


def DoDiff(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('path1')
  parser.add_argument('path2')
  parser.add_argument('--root-path1')
  parser.add_argument('--root-path2')
  parser.add_argument('--manifest-path1')
  parser.add_argument('--manifest-path2')
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_differ = ChecksumsDiffer(
    cmd_args.path1, cmd_args.path2, root_path1=cmd_args.root_path1, root_path2=cmd_args.root_path2,
    manifest_path1=cmd_args.manifest_path1, manifest_path2=cmd_args.manifest_path2,
    output=output, dry_run=args.dry_run, verbose=args.verbose)
  return checksums_differ.Diff()


def DoVerify(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_or_image_path')
  parser.add_argument('--manifest-path')
  parser.add_argument('--checksum-all', action='store_true')
  parser.add_argument('--no-hdiutil-verify', dest='hdiutil_verify', action='store_false')
  lib.AddPathsArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  path_matcher = lib.GetPathMatcherFromArgs(cmd_args)

  checksums_verifier = ChecksumsVerifier(
    cmd_args.root_or_image_path, output=output, manifest_path=cmd_args.manifest_path,
    checksum_path_matcher=lib.PathMatcherAllOrNone(cmd_args.checksum_all),
    path_matcher=path_matcher, dry_run=args.dry_run,
    verbose=args.verbose, encryption_manager=lib.EncryptionManager(output=output),
    hdiutil_verify=cmd_args.hdiutil_verify)
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


def DoImageFromFolder(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--output-path', required=True)
  parser.add_argument('--volume-name')
  parser.add_argument('--no-compressed', dest='compressed', action='store_false')
  parser.add_argument('--encrypt', action='store_true')
  parser.add_argument('--temp-dir')
  cmd_args = parser.parse_args(args.cmd_args)

  image_from_folder_creator = ImageFromFolderCreator(
    cmd_args.root_path, output_path=cmd_args.output_path, volume_name=cmd_args.volume_name,
    compressed=cmd_args.compressed, temp_dir=cmd_args.temp_dir, output=output,
    dry_run=args.dry_run, verbose=args.verbose, encryption_manager=lib.EncryptionManager(output=output),
    encrypt=cmd_args.encrypt)
  return image_from_folder_creator.CreateImage()


def DoSafeCopy(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('from_path')
  parser.add_argument('to_path')
  cmd_args = parser.parse_args(args.cmd_args)

  safe_copy_or_mover = SafeCopyOrMover(
    cmd_args.from_path, cmd_args.to_path, move=False, output=output,
    dry_run=args.dry_run, verbose=args.verbose)
  return safe_copy_or_mover.SafeCopyOrMove()


def DoSafeMove(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('from_path')
  parser.add_argument('to_path')
  cmd_args = parser.parse_args(args.cmd_args)

  safe_copy_or_mover = SafeCopyOrMover(
    cmd_args.from_path, cmd_args.to_path, move=True, output=output,
    dry_run=args.dry_run, verbose=args.verbose)
  return safe_copy_or_mover.SafeCopyOrMove()


def DoRestoreMeta(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  parser.add_argument('--mtimes', action='store_true')
  lib.AddPathsArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  path_matcher = lib.GetPathMatcherFromArgs(cmd_args)

  if not cmd_args.mtimes:
    print('*** Error: --mtimes arg is required', file=output)
    return False

  metadata_restorer = MetadataRestorer(
    cmd_args.root_path, output=output, manifest_path=cmd_args.manifest_path,
    mtimes=cmd_args.mtimes, path_matcher=path_matcher,
    dry_run=args.dry_run, verbose=args.verbose)
  return metadata_restorer.RestoreMetadata()


def DoCommand(args, output):
  if args.command == COMMAND_CREATE:
    return DoCreate(args, output=output)
  elif args.command == COMMAND_DIFF:
    return DoDiff(args, output=output)
  elif args.command == COMMAND_VERIFY:
    return DoVerify(args, output=output)
  elif args.command == COMMAND_SYNC:
    return DoSync(args, output=output)
  elif args.command == COMMAND_RENAME_PATHS:
    return DoRenamePaths(args, output=output)
  elif args.command == COMMAND_IMAGE_FROM_FOLDER:
    return DoImageFromFolder(args, output=output)
  elif args.command == COMMAND_SAFE_COPY:
    return DoSafeCopy(args, output=output)
  elif args.command == COMMAND_SAFE_MOVE:
    return DoSafeMove(args, output=output)
  elif args.command == COMMAND_RESTORE_META:
    return DoRestoreMeta(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
