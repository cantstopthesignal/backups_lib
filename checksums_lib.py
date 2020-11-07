import argparse
import os

import lib


COMMAND_CREATE = 'create'
COMMAND_VERIFY = 'verify'
COMMAND_SYNC = 'sync'

COMMANDS = [
  COMMAND_CREATE,
  COMMAND_VERIFY,
  COMMAND_SYNC
]

FILTER_DIR_MERGE_FILENAME = '.adjoined_checksums_filter'

CHECKSUM_FILTERS = [lib.RsyncFilterDirMerge(FILTER_DIR_MERGE_FILENAME),
                    lib.RsyncExclude('/.metadata'),
                    lib.RsyncExclude('.DS_Store')]


class ChecksumsError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


class Checksums(object):
  @staticmethod
  def Create(root_path, dry_run=False):
    root_path = os.path.normpath(root_path)
    if not os.path.isdir(root_path):
      raise ChecksumsError('Expected %s to be a directory' % root_path)
    metadata_path = os.path.join(root_path, lib.METADATA_DIR_NAME)
    if os.path.lexists(metadata_path):
      raise ChecksumsError('Did not expect %s to exist' % metadata_path)
    manifest = lib.Manifest(os.path.join(metadata_path, lib.MANIFEST_FILENAME))
    if not dry_run:
      os.mkdir(metadata_path)
      manifest.Write()
    return Checksums(root_path, manifest, dry_run=dry_run)

  @staticmethod
  def Open(root_path, dry_run=False):
    root_path = os.path.normpath(root_path)
    metadata_path = os.path.join(root_path, lib.METADATA_DIR_NAME)
    manifest = lib.Manifest(os.path.join(metadata_path, lib.MANIFEST_FILENAME))
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
  def __init__(self, root_path, output, dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None

  def Create(self):
    try:
      self.checksums = Checksums.Create(self.root_path, dry_run=self.dry_run)
    except ChecksumsError, e:
      print >>self.output, '*** Error: %s' % e.message
      return False

    print >>self.output, 'Created checksums metadata for %s' % self.root_path
    return True


class ChecksumsVerifier(object):
  def __init__(self, root_path, output, checksum_all=False, dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.checksum_all = checksum_all
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.filters = CHECKSUM_FILTERS

  def Verify(self):
    try:
      self.checksums = Checksums.Open(self.root_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError), e:
      print >>self.output, '*** Error: %s' % e.message
      return False

    verifier = lib.ManifestVerifier(
      self.checksums.GetManifest(), self.root_path, output=self.output,
      filters=self.filters, manifest_on_top=False, checksum_all=self.checksum_all, verbose=self.verbose)
    return verifier.Verify()


class ChecksumsSyncer(object):
  PRE_SYNC_CONTENTS_TEST_HOOK = None

  def __init__(self, root_path, output, checksum_all=False, dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.checksum_all = checksum_all
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.manifest = None
    self.file_enumerator = lib.FileEnumerator(root_path, output, filters=CHECKSUM_FILTERS, verbose=verbose)
    self.total_paths = 0
    self.total_synced_paths = 0
    self.total_size = 0
    self.total_synced_size = 0
    self.total_checksummed = 0
    self.total_checksummed_size = 0

  def Sync(self):
    try:
      self.checksums = Checksums.Open(self.root_path, dry_run=self.dry_run)
    except (ChecksumsError, lib.ManifestError), e:
      print >>self.output, '*** Error: %s' % e.message
      return False

    self.manifest = self.checksums.GetManifest()
    existing_paths = self.manifest.GetPaths()

    for path in self.file_enumerator.Scan():
      self._HandleExistingPaths(existing_paths, next_new_path=path)
      self._SyncPathIfChanged(path)

    self._HandleExistingPaths(existing_paths, next_new_path=None)

    if not self.dry_run:
      self.manifest.Write()

    self._PrintResults()

    return True

  def _PrintResults(self):
    if self.total_synced_paths > 0:
      print >>self.output, 'Paths: %d synced of %d paths (%s of %s), %d checksummed (%s)' % (
        self.total_synced_paths, self.total_paths,
        lib.FileSizeToString(self.total_synced_size), lib.FileSizeToString(self.total_size),
        self.total_checksummed, lib.FileSizeToString(self.total_checksummed_size))

  def _HandleExistingPaths(self, existing_paths, next_new_path=None):
    while existing_paths:
      next_existing_path = existing_paths[0]
      if next_new_path is not None and next_existing_path > next_new_path:
        break
      if next_new_path != next_existing_path:
        itemized = self.manifest.GetPathInfo(next_existing_path).GetItemized()
        itemized.delete_path = True
        print >>self.output, itemized
        self.manifest.RemovePathInfo(next_existing_path)
      del existing_paths[0]

  def _SyncPathIfChanged(self, path):
    full_path = os.path.join(self.root_path, path)
    path_info = lib.PathInfo.FromPath(path, full_path)
    self.total_paths += 1
    if path_info.size is not None:
      self.total_size += path_info.size

    basis_path_info = self.manifest.GetPathInfo(path)
    if basis_path_info is None:
      self._SyncPath(path, full_path, path_info)
      return

    if path_info.path_type == lib.PathInfo.TYPE_FILE:
      path_info.sha256 = basis_path_info.sha256
    self.manifest.AddPathInfo(path_info, allow_replace=True)

    itemized = lib.PathInfo.GetItemizedDiff(path_info, basis_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        print >>self.output, itemized
      return
    if path_info.path_type == lib.PathInfo.TYPE_FILE:
      path_info.sha256 = lib.Sha256(full_path)
      self.total_checksummed += 1
      self.total_checksummed_size += path_info.size
    if path_info.sha256 != basis_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        print >>self.output, itemized
      return

    print >>self.output, itemized

    self._AddStatsForSyncedPath(path_info)

  def _SyncPath(self, path, full_path, path_info):
    if path_info.path_type == lib.PathInfo.TYPE_FILE:
      path_info.sha256 = lib.Sha256(full_path)
      self.total_checksummed += 1
      self.total_checksummed_size += path_info.size

    itemized = path_info.GetItemized()
    itemized.new_path = True
    print >>self.output, itemized

    self.manifest.AddPathInfo(path_info)
    self._AddStatsForSyncedPath(path_info)

  def _AddStatsForSyncedPath(self, path_info):
    self.total_synced_paths += 1
    if path_info.size is not None:
      self.total_synced_size += path_info.size


def DoCreate(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_creator = ChecksumsCreator(
    cmd_args.root_path, output=output, dry_run=args.dry_run, verbose=args.verbose)
  return checksums_creator.Create()


def DoVerify(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--checksum-all', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_verifier = ChecksumsVerifier(
    cmd_args.root_path, output=output, checksum_all=cmd_args.checksum_all,
    dry_run=args.dry_run, verbose=args.verbose)
  return checksums_verifier.Verify()


def DoSync(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--checksum-all', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  checksums_syncer = ChecksumsSyncer(
    cmd_args.root_path, output=output, checksum_all=cmd_args.checksum_all,
    dry_run=args.dry_run, verbose=args.verbose)
  return checksums_syncer.Sync()


def DoCommand(args, output):
  if args.command == COMMAND_CREATE:
    return DoCreate(args, output=output)
  elif args.command == COMMAND_VERIFY:
    return DoVerify(args, output=output)
  elif args.command == COMMAND_SYNC:
    return DoSync(args, output=output)

  print >>output, '*** Error: Unknown command %s' % args.command
  return False
