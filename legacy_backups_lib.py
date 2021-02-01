import argparse
import binascii
import tempfile
import subprocess
import time
import os
import re
import shutil
import hashlib
import sys
import xml.dom.minidom
import unicodedata

from . import backups_lib
from . import lib


COMMAND_VERIFY_LEGACY_BACKUP_CHECKSUMS = 'verify-legacy-backup-checksums'

LEGACY_CHECKSUMS_FILENAME = '.checksums'
LEGACY_CHECKSUMS_IN_BACKUP_FILENAME = 'checksums'


def Md5(path):
  BLOCKSIZE = 65536
  hasher = hashlib.md5()
  with open(path, 'rb') as f:
    buf = f.read(BLOCKSIZE)
    while len(buf) > 0:
      hasher.update(buf)
      buf = f.read(BLOCKSIZE)
  return hasher.digest()


def XmlTextNodeToUtf8(textNode):
  return unicodedata.normalize('NFD', textNode.data).encode('utf8')


class LegacyChecksums(object):
  @staticmethod
  def LoadFromFile(checksums_path):
    path_to_md5_map = {}
    dom = xml.dom.minidom.parse(checksums_path)
    file_elements = dom.getElementsByTagName('file')
    for file_element in file_elements:
      path = XmlTextNodeToUtf8(
        file_element.getElementsByTagName('path')[0].firstChild)
      checksum = XmlTextNodeToUtf8(
        file_element.getElementsByTagName('checksum')[0].firstChild)
      path_to_md5_map[path] = checksum
    ignore_patterns = []
    ignore_pattern_elements = dom.getElementsByTagName('ignorepattern')
    for element in ignore_pattern_elements:
      ignore_patterns.append(XmlTextNodeToUtf8(element.firstChild))
    ignore_patterns.sort()
    return LegacyChecksums(path_to_md5_map, ignore_patterns)

  def __init__(self, path_to_md5_map={}, ignore_patterns=[]):
    self.path_to_md5_map = path_to_md5_map
    self.ignore_patterns = ignore_patterns

  def GetPathToMd5Map(self):
    return self.path_to_md5_map

  def AddPath(self, path, md5):
    assert path not in self.path_to_md5_map
    self.path_to_md5_map[path] = md5

  def GetIgnoresRegexp(self):
    return re.compile('^(%s)$' % '|'.join(self.ignore_patterns))


class LegacyChecksumsVerifier(object):
  def __init__(self, config, output, encryption_manager=None, dry_run=False, verbose=False):
    self.config = config
    self.output = output
    self.encryption_manager = encryption_manager
    self.dry_run = dry_run
    self.verbose = verbose
    self.manager = None

  def Verify(self):
    self.manager = backups_lib.BackupsManager.Open(
      self.config, encryption_manager=self.encryption_manager, readonly=True,
      dry_run=self.dry_run)
    try:
      last_manifest = None
      for backup in self.manager.GetBackupList():
        manifest = lib.Manifest()
        legacy_checksums = self._LoadLegacyChecksums(backup)
        if legacy_checksums is None:
          print('Legacy checksums do not exists for backup %s' % backup, file=self.output)
          last_manifest = None
          continue
        if not self._VerifyInternal(
            backup, manifest, last_manifest, legacy_checksums.GetPathToMd5Map(),
            legacy_checksums.GetIgnoresRegexp()):
          raise Exception('Failed to verify backup %s' % backup)
        last_manifest = manifest
      return True
    finally:
      self.manager.Close()

  def _LoadLegacyChecksums(self, backup):
    checksums_path = os.path.join(backup.GetMetadataPath(), LEGACY_CHECKSUMS_IN_BACKUP_FILENAME)
    if os.path.exists(checksums_path):
      return LegacyChecksums.LoadFromFile(checksums_path)

  def _VerifyInternal(self, backup, manifest, last_manifest, legacy_md5_map, legacy_ignore_pattern):
    print('Verify backup %s using legacy checksums...' % backup, file=self.output)

    legacy_md5_map = dict(legacy_md5_map)

    dev_inodes_done = {}
    if last_manifest is not None:
      for path in last_manifest.GetPaths():
        last_path_info = last_manifest.GetPathInfo(path)
        if last_path_info.dev_inode is not None:
          dev_inodes_done[last_path_info.dev_inode] = True

    num_misses = 0
    num_hits = 0
    num_errors = 0
    num_ignored = 0

    file_enumerator = lib.FileEnumerator(backup.GetContentRootPath(), self.output, verbose=self.verbose)
    for path in file_enumerator.Scan():
      full_path = os.path.join(backup.GetContentRootPath(), path)
      path_info = lib.PathInfo.FromPath(path, full_path)
      if path_info.path_type == lib.PathInfo.TYPE_FILE:
        assert path_info.dev_inode is not None
        if dev_inodes_done.get(path_info.dev_inode):
          if path in legacy_md5_map:
            del legacy_md5_map[path]
          num_hits += 1
        else:
          num_misses += 1
          legacy_md5 = legacy_md5_map.get(path)
          if legacy_md5 is None:
            if legacy_ignore_pattern.match(path):
              num_ignored += 1
            else:
              num_errors += 1
              print("*** Error: Missing md5 for %r" % path, file=self.output)
          else:
            del legacy_md5_map[path]
            while len(legacy_md5) < 32:
              legacy_md5 = '0' + legacy_md5
            legacy_md5_bin = binascii.a2b_hex(legacy_md5)
            md5 = Md5(full_path)
            if md5 != legacy_md5_bin:
              print(("*** Error: md5 mismatch for %r: %r != %r"
                                    % (path, binascii.b2a_hex(md5), legacy_md5)), file=self.output)
              num_errors += 1
      manifest.AddPathInfo(path_info)
    if legacy_md5_map:
      raise Exception('Some paths unverified: %r' % legacy_md5_map)
    print(('Verify cache: %d hits, %d misses, %d ignored'
                          % (num_hits, num_misses, num_ignored)), file=self.output)

    return (num_errors == 0)


def DoVerifyLegacyChecksums(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--backups-config', required=True)
  cmd_args = parser.parse_args(args.cmd_args)

  config = backups_lib.BackupsConfig.Load(cmd_args.backups_config)

  verifier = LegacyChecksumsVerifier(
    config, output=output, encryption_manager=lib.EncryptionManager(),
    dry_run=args.dry_run, verbose=args.verbose)
  return verifier.Verify()
