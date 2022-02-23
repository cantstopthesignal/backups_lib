import io
import os
import re

from . import backups_main
from . import checkpoint_lib
from . import lib

from .test_util import AssertEquals
from .test_util import AssertLinesEqual


def DoCreate(src_root, checkpoints_dir, checkpoint_name, expected_success=True, expected_output=[],
             last_checkpoint_path=None, manifest_only=False, checksum_all=True, filter_merge_path=None,
             encrypt=False, dry_run=False, readonly=True):
  args = []
  if dry_run:
    args.append('--dry-run')
  args.extend(['create-checkpoint',
               '--src-root', src_root,
               '--checkpoints-dir', checkpoints_dir,
               '--checkpoint-name', checkpoint_name])
  if manifest_only:
    args.append('--manifest-only')
  if last_checkpoint_path is not None:
    args.extend(['--last-checkpoint', last_checkpoint_path])
  if checksum_all:
    args.append('--checksum-all')
  if filter_merge_path:
    args.extend(['--filter-merge-path', filter_merge_path])
  if not encrypt:
    args.append('--no-encrypt')
  output = io.StringIO()
  AssertEquals(backups_main.Main(args, output), expected_success)
  output_lines = []
  checkpoint_path = None
  for line in output.getvalue().strip().split('\n'):
    m = re.match('^Created checkpoint at (.+[.]sparseimage)$', line)
    if m:
      checkpoint_path = m.group(1)
      continue
    output_lines.append(line)
  output.close()
  AssertLinesEqual(output_lines, expected_output)
  if not dry_run:
    assert checkpoint_path
    checkpoint, manifest = GetCheckpointData(
      checkpoint_path, readonly=readonly, manifest_only=manifest_only)
    try:
      return checkpoint, manifest
    except:
      if checkpoint:
        checkpoint.Close()
      raise


def GetCheckpointData(checkpoint_path, readonly=True, manifest_only=False):
  checkpoint = checkpoint_lib.Checkpoint.Open(
    checkpoint_path, readonly=readonly, encryption_manager=lib.EncryptionManager())
  try:
    manifest_path = os.path.join(checkpoint.GetMetadataPath(), lib.MANIFEST_FILENAME)
    if manifest_only:
      assert not os.path.lexists(checkpoint.GetContentRootPath())
    else:
      assert os.path.isdir(checkpoint.GetContentRootPath())
    manifest = lib.Manifest.Load(manifest_path)
    return (checkpoint, manifest)
  except:
    if checkpoint:
      checkpoint.Close()
    raise
