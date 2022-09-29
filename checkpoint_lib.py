import argparse
import json
import os
import re
import shutil
import tempfile
import time
import traceback

from . import lib


COMMAND_CREATE_CHECKPOINT = 'create-checkpoint'
COMMAND_APPLY_CHECKPOINT = 'apply-checkpoint'
COMMAND_STRIP_CHECKPOINT = 'strip-checkpoint'

COMMANDS = [
  COMMAND_CREATE_CHECKPOINT,
  COMMAND_APPLY_CHECKPOINT,
  COMMAND_STRIP_CHECKPOINT,
]


STAGED_BACKUP_DIR_MERGE_FILENAME = '.staged_backup_filter'

STAGED_BACKUP_DEFAULT_FILTERS = [lib.FilterRuleDirMerge(STAGED_BACKUP_DIR_MERGE_FILENAME)]


class CheckpointPathParts(object):
  PATTERN = re.compile('^((?:(?!-manifest).)*)(-manifest)?([.]sparseimage)$')

  @staticmethod
  def IsMatchingPath(path):
    return CheckpointPathParts.PATTERN.match(os.path.basename(path)) is not None

  def __init__(self, path):
    m = CheckpointPathParts.PATTERN.match(path)
    if not m:
      raise Exception('Invalid checkpint path %s' % path)
    self.prefix = m.group(1)
    self.is_manifest_only = m.group(2) is not None
    self.extension = m.group(3)

  def GetPath(self):
    path = self.prefix
    if self.is_manifest_only:
      path += '-manifest'
    path += self.extension
    return path

  def IsManifestOnly(self):
    return self.is_manifest_only

  def SetIsManifestOnly(self, is_manifest_only):
    self.is_manifest_only = is_manifest_only


class Checkpoint(object):
  STATE_NEW = 'NEW'
  STATE_IN_PROGRESS = 'IN_PROGRESS'
  STATE_DONE = 'DONE'
  STATE_DELETED = 'DELETED'

  @staticmethod
  def New(base_path, name, encryption_manager=None, manifest_only=False, encrypt=False, dry_run=False):
    if name is None:
      name = time.strftime('%Y-%m-%d-%H%M%S')
      if manifest_only:
        name += '-manifest'
    return Checkpoint(base_path, name, Checkpoint.STATE_NEW, encryption_manager=encryption_manager,
                      encrypt=encrypt, manifest_only=manifest_only, readonly=False, dry_run=dry_run)

  @staticmethod
  def Open(path, encryption_manager=None, readonly=True, dry_run=False):
    path = os.path.normpath(path)
    base_path = os.path.dirname(path)
    name = os.path.basename(path)
    if not name.endswith('.sparseimage'):
      raise Exception('Expected a sparseimage file')
    name = name[:-len('.sparseimage')]
    if not os.path.isfile(path):
      raise Exception('Expected %s to exist' % path)
    return Checkpoint(base_path, name, Checkpoint.STATE_DONE, encryption_manager=encryption_manager,
                      readonly=readonly, dry_run=dry_run)

  def __init__(self, base_path, name, state, encryption_manager=None, manifest_only=False,
               encrypt=False, readonly=True, dry_run=False):
    self.base_path = base_path
    self.name = name
    self.state = state
    self.encrypt = encrypt
    self.manifest_only = manifest_only
    self.encryption_manager = encryption_manager
    self.readonly = readonly
    self.dry_run = dry_run
    self.mounted = False
    self.attacher = None
    if self.state == Checkpoint.STATE_NEW:
      if self.readonly:
        raise Exception('Cannot create a new checkpoint readonly')
      self._StartNew()
    elif self.state == Checkpoint.STATE_DONE:
      self._Open()
    else:
      raise Exception('Unexpected state')

  def GetName(self):
    return self.name

  def GetImagePath(self):
    return os.path.join(self.base_path, self.name + '.sparseimage')

  def GetMountPoint(self):
    if self.attacher is not None:
      return self.attacher.GetMountPoint()

  def GetContentRootPath(self):
    return os.path.join(self.GetMountPoint(), lib.CONTENT_DIR_NAME)

  def GetMetadataPath(self):
    return os.path.join(self.GetMountPoint(), lib.METADATA_DIR_NAME)

  def GetManifestPath(self):
    return os.path.join(self.GetMetadataPath(), lib.MANIFEST_FILENAME)

  def Close(self):
    assert self.state in [Checkpoint.STATE_DONE, Checkpoint.STATE_IN_PROGRESS]
    if self.mounted:
      self._UnmountImage()
    assert self.GetMountPoint() is None
    self.state = Checkpoint.STATE_DONE

  def _StartNew(self):
    assert self.state == Checkpoint.STATE_NEW
    assert not self.mounted
    if not self.dry_run:
      self._CreateImage()
      self._MountImage()
      assert os.path.exists(self.GetMountPoint())
      if not self.manifest_only and not os.path.exists(self.GetContentRootPath()):
        os.mkdir(self.GetContentRootPath())
      if not os.path.exists(self.GetMetadataPath()):
        os.mkdir(self.GetMetadataPath())
    self.state = Checkpoint.STATE_IN_PROGRESS

  def _Open(self):
    assert self.state == Checkpoint.STATE_DONE
    assert not self.mounted
    self._MountImage()

  def Delete(self):
    if self.mounted:
      self._UnmountImage()
    image_path = self.GetImagePath()
    if not self.dry_run:
      if os.path.exists(image_path):
        os.unlink(image_path)
    self.state = Checkpoint.STATE_DELETED

  def MoveToDir(self, new_base_path):
    if not self.dry_run:
      assert self.state == Checkpoint.STATE_DONE and not self.mounted
      new_path = os.path.join(new_base_path, os.path.basename(self.GetImagePath()))
      assert not os.path.lexists(new_path)
      lib.GetDiskImageHelper().MoveImage(self.GetImagePath(), new_path)
      self.base_path = new_base_path

  def _CreateImage(self):
    lib.CreateDiskImage(self.GetImagePath(), volume_name=self.name, encrypt=self.encrypt,
                        encryption_manager=self.encryption_manager, dry_run=self.dry_run)

  def _MountImage(self):
    assert not self.mounted
    self.attacher = lib.ImageAttacher.Open(
      self.GetImagePath(), encryption_manager=self.encryption_manager,
      readonly=(self.readonly or self.dry_run))
    self.mounted = True

  def _UnmountImage(self):
    assert self.mounted
    self.attacher.Close()
    self.attacher = None
    self.mounted = False


class CheckpointCreator(object):
  PRE_SYNC_CONTENTS_TEST_HOOK = None

  def __init__(self, src_root_dir, checkpoints_root_dir, name, output, basis_path=None, basis_manifest=None,
               dry_run=False, verbose=False, checksum_all=False, manifest_only=False, encrypt=True,
               encryption_manager=None, filters=STAGED_BACKUP_DEFAULT_FILTERS):
    if src_root_dir is None:
      raise Exception('src_root_dir cannot be None')
    self.src_root_dir = src_root_dir
    self.basis_path = basis_path
    self.basis_manifest = basis_manifest
    self.sha256_to_basis_pathinfos = {}
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksum_all = checksum_all
    self.manifest_only = manifest_only
    self.encrypt = encrypt
    self.encryption_manager = encryption_manager
    self.checkpoints_root_dir = checkpoints_root_dir
    self.name = name
    self.checkpoint = None
    self.manifest = None
    self.path_infos_to_sync = []
    self.path_enumerator = lib.PathEnumerator(src_root_dir, output, filters=filters, verbose=verbose)
    self.enumerated_path_map = {}
    self.total_paths = 0
    self.total_checkpoint_paths = 0
    self.total_size = 0
    self.total_checkpoint_size = 0
    self.pending_path_printouts = []

  def Create(self):
    checkpoint_temp_dir = tempfile.mkdtemp()
    try:
      return self._CreateInternalOuter(checkpoint_temp_dir)
    finally:
      shutil.rmtree(checkpoint_temp_dir)

  def _CreateInternalOuter(self, checkpoint_temp_dir):
    success = False
    try:
      self.checkpoint = Checkpoint.New(
        checkpoint_temp_dir, self.name, encryption_manager=self.encryption_manager,
        manifest_only=self.manifest_only, encrypt=self.encrypt, dry_run=self.dry_run)
      try:
        if self._CreateInternalInner():
          self.checkpoint.Close()
          self.checkpoint.MoveToDir(self.checkpoints_root_dir)
          self._PrintResults()
          success = True
      finally:
        self.checkpoint.Close()
    except Exception as e:
      success = False
      raise
    finally:
      if not success and self.checkpoint is not None:
        try:
          self.checkpoint.Delete()
        except Exception as e:
          print('Suppressed exception: %s' % e)
          traceback.print_exc()
        self.checkpoint = None
    return success

  def _CreateInternalInner(self):
    if not self.dry_run:
      self.manifest = lib.Manifest(self.checkpoint.GetManifestPath())
    else:
      self.manifest = lib.Manifest()

    if self.basis_manifest is not None:
      existing_paths = self.basis_manifest.GetPaths()
      self.sha256_to_basis_pathinfos = self.basis_manifest.CreateSha256ToPathInfosMap()
    else:
      existing_paths = []

    for enumerated_path in self.path_enumerator.Scan():
      path = enumerated_path.GetPath()
      self.enumerated_path_map[path] = enumerated_path
      self._HandleExistingPaths(existing_paths, next_new_path=path)
      self._AddPathIfChanged(enumerated_path)

    self._HandleExistingPaths(existing_paths, next_new_path=None)
    self._FlushPendingPathPrintouts()

    if not self.manifest_only:
      if not self._SyncContents():
        return False

    self._WriteBasisInfo()
    if not self.dry_run:
      self.manifest.Write()
    return True

  def _PrintResults(self):
    if self.basis_manifest is None:
      if self.total_paths > 0:
        print('Transferring %d paths (%s)' % (
          self.total_paths, lib.FileSizeToString(self.total_size)), file=self.output)
    elif self.total_checkpoint_paths > 0:
      print('Transferring %d of %d paths (%s of %s)' %
            (self.total_checkpoint_paths, self.total_paths,
             lib.FileSizeToString(self.total_checkpoint_size), lib.FileSizeToString(self.total_size)),
            file=self.output)
    if not self.dry_run:
      print('Created checkpoint at %s' % self.checkpoint.GetImagePath(), file=self.output)

  def _HandleExistingPaths(self, existing_paths, next_new_path=None):
    while existing_paths:
      next_existing_path = existing_paths[0]
      if next_new_path is not None and next_existing_path > next_new_path:
        break
      if next_new_path != next_existing_path:
        basis_path_info = self.basis_manifest.GetPathInfo(next_existing_path)
        itemized = basis_path_info.GetItemized()
        itemized.delete_path = True
        self.pending_path_printouts.append([itemized, basis_path_info, None])
      del existing_paths[0]

  def _AddPathIfChanged(self, enumerated_path, allow_replace=False):
    path = enumerated_path.GetPath()
    full_path = os.path.join(self.src_root_dir, path)
    path_info = lib.PathInfo.FromPath(path, full_path, follow_symlinks=enumerated_path.GetFollowSymlinks())
    self.total_paths += 1
    if path_info.size is not None:
      self.total_size += path_info.size

    basis_path_info = None
    if self.basis_manifest is not None:
      basis_path_info = self.basis_manifest.GetPathInfo(path)
    if basis_path_info is None:
      self._AddPath(path, full_path, path_info, allow_replace=allow_replace)
      return

    if path_info.HasFileContents():
      path_info.sha256 = basis_path_info.sha256
    self.manifest.AddPathInfo(path_info, allow_replace=allow_replace)

    itemized = lib.PathInfo.GetItemizedDiff(path_info, basis_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        self.pending_path_printouts.append([itemized, basis_path_info, path_info])
      return
    if path_info.HasFileContents():
      path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)
    if path_info.sha256 != basis_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        self.pending_path_printouts.append([itemized, basis_path_info, path_info])
      return

    self.pending_path_printouts.append([itemized, basis_path_info, path_info])

    self._AddPathContents(path_info)

  def _AddPath(self, path, full_path, path_info, allow_replace=False):
    if path_info.HasFileContents():
      path_info.sha256 = lib.Sha256WithProgress(full_path, path_info, output=self.output)

    itemized = path_info.GetItemized()
    itemized.new_path = True
    self.pending_path_printouts.append([itemized, None, path_info])

    self.manifest.AddPathInfo(path_info, allow_replace=allow_replace)
    self._AddPathContents(path_info)

  def _AddPathContents(self, path_info):
    self.path_infos_to_sync.append(path_info)
    self.total_checkpoint_paths += 1
    if path_info.size is not None:
      self.total_checkpoint_size += path_info.size

  def _SyncContents(self):
    if self.dry_run:
      return True

    max_retries = 5
    num_retries_left = max_retries
    while self.path_infos_to_sync:
      if not num_retries_left:
        print('*** Error: Failed to create checkpoint after %d retries' % max_retries, file=self.output)
        return False
      num_retries_left -= 1

      if CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK:
        CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK(self)

      paths_to_sync_set = set()
      for path_info in self.path_infos_to_sync:
        paths_to_sync_set.add(path_info.path)
        parent_dir = os.path.dirname(path_info.path)
        while parent_dir:
          paths_to_sync_set.add(parent_dir)
          parent_dir = os.path.dirname(parent_dir)
      if paths_to_sync_set:
        paths_to_sync_set.add('.')

      path_datas_to_sync = []
      for path in paths_to_sync_set:
        enumerated_path = self.enumerated_path_map[path]
        path_datas_to_sync.append(lib.PathSyncer.PathData(
          enumerated_path.GetPath(), follow_symlinks=enumerated_path.GetFollowSymlinks()))

      path_syncer = lib.PathSyncer(
        path_datas_to_sync,
        self.src_root_dir, self.checkpoint.GetContentRootPath(),
        output=self.output, dry_run=self.dry_run, verbose=self.verbose)
      path_syncer.Sync()

      paths_just_synced_set = paths_to_sync_set
      self.path_infos_to_sync = []

      first_requeued = True
      for path in sorted(paths_just_synced_set):
        enumerated_path = self.enumerated_path_map[path]
        if self._ReQueuePathsModifiedSinceManifest(enumerated_path, first_requeued):
          first_requeued = False

      self._FlushPendingPathPrintouts()
    return True

  def _ReQueuePathsModifiedSinceManifest(self, enumerated_path, first_requeued):
    path = enumerated_path.GetPath()
    expected_path_info = self.manifest.GetPathInfo(path)
    if expected_path_info.HasFileContents():
      assert expected_path_info.sha256
    full_path = os.path.join(self.checkpoint.GetContentRootPath(), path)
    checkpoint_path_info = lib.PathInfo.FromPath(path, full_path, follow_symlinks=enumerated_path.GetFollowSymlinks())
    if checkpoint_path_info.HasFileContents():
      checkpoint_path_info.sha256 = expected_path_info.sha256
    itemized = lib.PathInfo.GetItemizedDiff(checkpoint_path_info, expected_path_info)
    if not itemized.HasDiffs():
      if checkpoint_path_info.HasFileContents():
        checkpoint_path_info.sha256 = lib.Sha256WithProgress(
          full_path, checkpoint_path_info, output=self.output)
        if checkpoint_path_info.sha256 == expected_path_info.sha256:
          return False
      else:
        return False
    if first_requeued:
      print("*** Warning: Paths changed since syncing, checking...", file=self.output)
    self._AddPathIfChanged(enumerated_path, allow_replace=True)
    return True

  def _WriteBasisInfo(self):
    if not self.dry_run and self.basis_path is not None:
      basis_info_path = os.path.join(self.checkpoint.GetMetadataPath(), lib.BASIS_INFO_FILENAME)
      with open(basis_info_path, 'w') as out_file:
        out_file.write(json.dumps({
          'basis_filename': os.path.basename(self.basis_path)
        }, indent=2))
        out_file.write('\n')

  def _FlushPendingPathPrintouts(self):
    if not self.pending_path_printouts:
      return
    sha256_to_pathinfos = self.manifest.CreateSha256ToPathInfosMap()
    for itemized, basis_path_info, path_info in self.pending_path_printouts:
      dup_analyze_result = None
      if itemized.HasDiffs():
        if (itemized.new_path or itemized.checksum_diff) and path_info.HasFileContents():
          dup_analyze_result = lib.AnalyzePathInfoDups(
            path_info, self.sha256_to_basis_pathinfos.get(path_info.sha256, []),
            replacing_previous=True, verbose=self.verbose)
        elif itemized.delete_path and basis_path_info.HasFileContents():
          dup_analyze_result = lib.AnalyzePathInfoDups(
            basis_path_info, sha256_to_pathinfos.get(basis_path_info.sha256, []),
            replacing_previous=False, verbose=self.verbose)
      if dup_analyze_result is not None:
        itemized.Print(output=self.output, found_matching_rename=dup_analyze_result.found_matching_rename)
        for line in dup_analyze_result.dup_output_lines:
          print(line, file=self.output)
      else:
        itemized.Print(output=self.output)
      if self.verbose:
        if basis_path_info is not None:
          print('<', basis_path_info.ToString(
            shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
        if path_info is not None:
          print('>', path_info.ToString(
            shorten_sha256=True, shorten_xattr_hash=True), file=self.output)

    self.pending_path_printouts = []


class CheckpointApplier(object):
  def __init__(self, src_checkpoint_path, dest_root, output, dry_run=False, verbose=False,
               checksum_all=False, strict_replace=False, encryption_manager=None):
    self.src_checkpoint_path = src_checkpoint_path
    self.src_checkpoint = None
    self.src_manifest = None
    self.dest_root = dest_root
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksum_all = checksum_all
    self.strict_replace = strict_replace
    self.encryption_manager = encryption_manager
    self.paths_to_sync = []
    self.existing_files_to_sync = []
    self.paths_to_delete = []
    self.path_enumerator = lib.PathEnumerator(dest_root, output, verbose=verbose)
    self.errors_encountered = False

  def Apply(self):
    try:
      self.src_checkpoint = Checkpoint.Open(
        self.src_checkpoint_path, encryption_manager=self.encryption_manager, dry_run=self.dry_run)

      return self._ApplyInternal()
    finally:
      if self.src_checkpoint is not None:
        self.src_checkpoint.Close()
        self.src_checkpoint = None

  def _ApplyInternal(self):
    self.src_manifest = lib.Manifest.Load(self.src_checkpoint.GetManifestPath())

    new_paths = self.src_manifest.GetPaths()

    for enumerated_path in self.path_enumerator.Scan():
      path = enumerated_path.GetPath()
      self._HandleNewPaths(new_paths, next_existing_path=path)

      full_path = os.path.join(self.dest_root, path)
      dest_path_info = lib.PathInfo.FromPath(path, full_path)
      src_path_info = self.src_manifest.GetPathInfo(path)
      if src_path_info is None:
        self._AddDeleted(path, dest_path_info)
      else:
        self._AddIfChanged(path, src_path_info, dest_path_info)

    self._HandleNewPaths(new_paths, next_existing_path=None)

    if self.errors_encountered:
      print('*** Errors encountered before applying checkpoint', file=self.output)
      return False

    self._SyncContents()
    return True

  def _HandleNewPaths(self, new_paths, next_existing_path=None):
    while new_paths:
      next_new_path = new_paths[0]
      if next_existing_path is not None and next_new_path > next_existing_path:
        break
      if next_existing_path != next_new_path:
        if self._AddPathContents(next_new_path, existing_path_info=None):
          itemized = self.src_manifest.GetPathInfo(next_new_path).GetItemized()
          itemized.new_path = True
          itemized.Print(output=self.output)
      del new_paths[0]

  def _AddDeleted(self, path, dest_path_info):
    itemized = dest_path_info.GetItemized()
    itemized.delete_path = True
    itemized.Print(output=self.output)
    self.paths_to_delete.append(path)

  def _AddIfChanged(self, path, src_path_info, dest_path_info):
    full_path = os.path.join(self.dest_root, dest_path_info.path)

    itemized = lib.PathInfo.GetItemizedDiff(src_path_info, dest_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        itemized.Print(output=self.output)
      return
    if dest_path_info.HasFileContents():
      dest_path_info.sha256 = lib.Sha256WithProgress(full_path, dest_path_info, output=self.output)
    if dest_path_info.sha256 != src_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        itemized.Print(output=self.output)
      return

    if self._AddPathContents(path, existing_path_info=dest_path_info):
      itemized.Print(output=self.output)
    if self.verbose:
      if src_path_info is not None:
        print('<', src_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
      if dest_path_info is not None:
        print('>', dest_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True), file=self.output)

  def _AddPathContents(self, path, existing_path_info):
    if not os.path.lexists(os.path.join(self.src_checkpoint.GetContentRootPath(), path)):
      itemized = self.src_manifest.GetPathInfo(path).GetItemized()
      itemized.error_path = True
      itemized.Print(output=self.output)
      self.errors_encountered = True
      return False

    self.paths_to_sync.append(path)
    if existing_path_info is not None and existing_path_info.path_type == lib.PathInfo.TYPE_FILE:
      self.existing_files_to_sync.append(path)
    return True

  def _SyncContents(self):
    original_dest_mtime = None
    if not self.dry_run and os.path.isdir(self.dest_root):
      original_dest_mtime = int(os.lstat(self.dest_root).st_mtime)

    if self.paths_to_delete:
      for path in reversed(self.paths_to_delete):
        full_path = os.path.join(self.dest_root, path)
        if not self.dry_run:
          if os.path.isdir(full_path) and not os.path.islink(full_path):
            os.rmdir(full_path)
          else:
            os.unlink(full_path)

    if self.strict_replace and self.existing_files_to_sync:
      self._ClearHardlinks(self.existing_files_to_sync)
    if self.paths_to_sync:
      lib.RsyncPaths(self.paths_to_sync, self.src_checkpoint.GetContentRootPath(), self.dest_root,
                     output=self.output, dry_run=self.dry_run, verbose=self.verbose)

    # TODO: Fixing mtimes for all parent directories of synced files may be required.
    if not self.dry_run and original_dest_mtime is not None:
      src_mtime = int(os.lstat(self.src_checkpoint.GetContentRootPath()).st_mtime)
      updated_dest_mtime = int(os.lstat(self.dest_root).st_mtime)
      if updated_dest_mtime not in [src_mtime, original_dest_mtime]:
        os.utime(self.dest_root, (original_dest_mtime, original_dest_mtime), follow_symlinks=False)

  def _ClearHardlinks(self, paths):
    for path in paths:
      full_path = os.path.join(self.dest_root, path)
      lib.ClearPathHardlinks(full_path, dry_run=self.dry_run)


class CheckpointStripper(object):
  def __init__(self, checkpoint_path, output, defragment=False,
               defragment_iterations=lib.DEFAULT_DEFRAGMENT_ITERATIONS,
               dry_run=False, verbose=False, encryption_manager=None):
    self.checkpoint_path = checkpoint_path
    self.defragment = defragment
    self.defragment_iterations = defragment_iterations
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.encryption_manager = encryption_manager
    self.checkpoint = None

  def Strip(self):
    if self._CheckpointAlreadyStripped():
      print("Checkpoint already stripped", file=self.output)
      return True
    if not self._RenameCheckpointForStrip():
      return False
    self.checkpoint = Checkpoint.Open(
      self.checkpoint_path, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      if not self._StripInternal():
        return False
    finally:
      if self.checkpoint is not None:
        self.checkpoint.Close()
        self.checkpoint = None

    compactor = lib.ImageCompactor(
      self.checkpoint_path, output=self.output, defragment=self.defragment,
      defragment_iterations=self.defragment_iterations, dry_run=self.dry_run,
      verbose=self.verbose, encryption_manager=self.encryption_manager)
    return compactor.Compact()

  def _StripInternal(self):
    if not self.dry_run:
      shutil.rmtree(self.checkpoint.GetContentRootPath())

    print("Checkpoint stripped", file=self.output)
    return True

  def _CheckpointAlreadyStripped(self):
    path_parts = CheckpointPathParts(self.checkpoint_path)
    if path_parts.IsManifestOnly():
      return True

    test_open_checkpoint = Checkpoint.Open(
      self.checkpoint_path, encryption_manager=self.encryption_manager, readonly=True,
      dry_run=self.dry_run)
    try:
      if not os.path.exists(test_open_checkpoint.GetContentRootPath()):
        return True
    finally:
      test_open_checkpoint.Close()
    return False

  def _RenameCheckpointForStrip(self):
    path_parts = CheckpointPathParts(self.checkpoint_path)
    assert not path_parts.IsManifestOnly()
    path_parts.SetIsManifestOnly(True)
    new_path = path_parts.GetPath()
    assert self.checkpoint_path != new_path
    if os.path.lexists(new_path):
      print("*** Error: Path %s already exists" % new_path, file=self.output)
      return False
    if not self.dry_run:
      os.rename(self.checkpoint_path, new_path)
      self.checkpoint_path = new_path
    return True


def DoCreateCheckpoint(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--src-root', required=True)
  parser.add_argument('--checksum-all', action='store_true')
  parser.add_argument('--manifest-only', action='store_true')
  parser.add_argument('--no-encrypt', dest='encrypt', action='store_false')
  parser.add_argument('--no-filters', action='store_true')
  parser.add_argument('--filter-merge-path')
  parser.add_argument('--checkpoints-dir', required=True)
  parser.add_argument('--checkpoint-name')
  parser.add_argument('--last-manifest')
  parser.add_argument('--last-checkpoint')
  cmd_args = parser.parse_args(args.cmd_args)

  if cmd_args.last_manifest is not None and cmd_args.last_checkpoint is not None:
    raise Exception('Cannot use both --last-manifest and --last-checkpoint')

  filters = list(STAGED_BACKUP_DEFAULT_FILTERS)
  if cmd_args.no_filters:
    filters = []
  if cmd_args.filter_merge_path is not None:
    if not os.path.exists(cmd_args.filter_merge_path):
      raise Exception('Expected filter merge path %r to exist' % cmd_args.filter_merge_path)
    filters.append(lib.FilterRuleMerge(cmd_args.filter_merge_path))

  encryption_manager = lib.EncryptionManager()

  basis_path = cmd_args.last_manifest or cmd_args.last_checkpoint
  if basis_path:
    basis_manifest = lib.ReadManifestFromImageOrPath(
      basis_path, encryption_manager=encryption_manager, dry_run=args.dry_run)
  else:
    basis_manifest = None

  checkpoint_creator = CheckpointCreator(
    cmd_args.src_root, cmd_args.checkpoints_dir, name=cmd_args.checkpoint_name, output=output,
    basis_path=basis_path, basis_manifest=basis_manifest, dry_run=args.dry_run, verbose=args.verbose,
    checksum_all=cmd_args.checksum_all, manifest_only=cmd_args.manifest_only, encrypt=cmd_args.encrypt,
    encryption_manager=encryption_manager, filters=filters)
  return checkpoint_creator.Create()


def DoApplyCheckpoint(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--src-checkpoint-path', required=True)
  parser.add_argument('--dest-root', required=True)
  parser.add_argument('--checksum-all', action='store_true')
  parser.add_argument('--strict-replace', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  checkpoint_applier = CheckpointApplier(
    cmd_args.src_checkpoint_path, cmd_args.dest_root, output, dry_run=args.dry_run, verbose=args.verbose,
    checksum_all=cmd_args.checksum_all, strict_replace=cmd_args.strict_replace,
    encryption_manager=lib.EncryptionManager())
  return checkpoint_applier.Apply()


def DoStripCheckpoint(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--checkpoint-path', required=True)
  parser.add_argument('--no-defragment', dest='defragment', action='store_false')
  parser.add_argument('--defragment-iterations', default=str(lib.DEFAULT_DEFRAGMENT_ITERATIONS), type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  checkpoint_stripper = CheckpointStripper(
    cmd_args.checkpoint_path, defragment=cmd_args.defragment,
    defragment_iterations=cmd_args.defragment_iterations, output=output, dry_run=args.dry_run,
    verbose=args.verbose, encryption_manager=lib.EncryptionManager())
  return checkpoint_stripper.Strip()


def DoCommand(args, output):
  if args.command == COMMAND_CREATE_CHECKPOINT:
    return DoCreateCheckpoint(args, output=output)
  elif args.command == COMMAND_APPLY_CHECKPOINT:
    return DoApplyCheckpoint(args, output=output)
  elif args.command == COMMAND_STRIP_CHECKPOINT:
    return DoStripCheckpoint(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
