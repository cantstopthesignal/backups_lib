import argparse
import binascii
import time
import os
import re
import shutil
import stat
import sys
import time

from . import checksums_lib
from . import lib


COMMAND_ONEOFF_ADD_XATTR_KEYS = 'oneoff-add-xattr-keys'

COMMANDS = [
  COMMAND_ONEOFF_ADD_XATTR_KEYS,
]


class OneoffXattrsKeysAdder(object):
  def __init__(self, root_path, output, manifest_path=None, dry_run=False, verbose=False):
    if root_path is None:
      raise Exception('root_path cannot be None')
    self.root_path = root_path
    self.output = output
    self.manifest_path = manifest_path
    self.dry_run = dry_run
    self.verbose = verbose
    self.checksums = None
    self.basis_manifest = None
    self.manifest = None
    self.num_xattr_changed = 0

  def Apply(self):
    try:
      self.checksums = checksums_lib.Checksums.Open(
        self.root_path, manifest_path=self.manifest_path, dry_run=self.dry_run)
    except (checksums_lib.ChecksumsError, lib.ManifestError) as e:
      print('*** Error: %s' % e.args[0], file=self.output)
      return False

    self.basis_manifest = self.checksums.GetManifest()
    self.manifest = self.basis_manifest.Clone()
    self.manifest.SetPath(checksums_lib.GetManifestNewPath(self.manifest.GetPath()))

    self._ApplyInternal()

    if self.num_xattr_changed:
      if not self.dry_run:
        self.manifest.Write()
        os.rename(self.manifest.GetPath(), self.basis_manifest.GetPath())

    return True

  def _ApplyInternal(self):
    num_paths = 0
    num_xattr = 0
    self.num_xattr_changed = 0

    for path in self.manifest.GetPaths():
      num_paths += 1
      path_info = self.manifest.GetPathInfo(path)
      if path_info.xattr_hash is not None:
        num_xattr += 1
        full_path = os.path.join(self.root_path, path)
        old_path_info = lib.PathInfo.FromPath(path, full_path)
        old_path_info.xattr_keys = []
        new_path_info = lib.PathInfo.FromPath(path, full_path)
        old_itemized = lib.PathInfo.GetItemizedDiff(path_info, old_path_info)
        assert not old_itemized.HasDiffs()
        assert path_info.xattr_hash == new_path_info.xattr_hash
        if path_info.xattr_keys != new_path_info.xattr_keys:
          path_info.xattr_keys = new_path_info.xattr_keys
          print('Updated xattr list for %s from %r to %r' % (
            lib.EscapePath(path), old_path_info.xattr_keys, path_info.xattr_keys), file=self.output)
          self.num_xattr_changed += 1

    print('Paths: %d paths with xattrs, %d xattrs changed, %d paths' % (
      num_xattr, self.num_xattr_changed, num_paths), file=self.output)


def DoOneoffAddXattrKeys(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--manifest-path')
  lib.AddPathsArgs(parser)
  cmd_args = parser.parse_args(args.cmd_args)

  updater = OneoffXattrsKeysAdder(
    cmd_args.root_path, manifest_path=cmd_args.manifest_path, output=output,
    dry_run=args.dry_run, verbose=args.verbose)
  return updater.Apply()


def DoCommand(args, output):
  if args.command == COMMAND_ONEOFF_ADD_XATTR_KEYS:
    return DoOneoffAddXattrKeys(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
