import contextlib
import io
import os
import re
import subprocess

from . import checksums_lib
from . import lib
from . import checksums_main

from .test_util import AssertEquals
from .test_util import AssertLinesEqual
from .test_util import CreateDir
from .test_util import CreateFile


@contextlib.contextmanager
def SetMaxRenameDetectionMatchingSizeFileCount(new_file_count):
  old_value = checksums_lib.MAX_RENAME_DETECTION_MATCHING_SIZE_FILE_COUNT
  checksums_lib.MAX_RENAME_DETECTION_MATCHING_SIZE_FILE_COUNT = new_file_count
  try:
    yield
  finally:
    checksums_lib.MAX_RENAME_DETECTION_MATCHING_SIZE_FILE_COUNT = old_value


@contextlib.contextmanager
def SafeMoveOrCopyForceFromParentDirMtimeChangeForTest():
  old_value = checksums_lib.SafeCopyOrMover.FORCE_FROM_PARENT_DIR_MTIME_CHANGE_FOR_TEST
  checksums_lib.SafeCopyOrMover.FORCE_FROM_PARENT_DIR_MTIME_CHANGE_FOR_TEST = True
  try:
    yield
  finally:
    checksums_lib.SafeCopyOrMover.FORCE_FROM_PARENT_DIR_MTIME_CHANGE_FOR_TEST = old_value


def DoChecksumsMain(cmd_args, dry_run=False, verbose=False, expected_success=True, expected_output=[]):
  args = []
  if dry_run:
    args.append('--dry-run')
  if verbose:
    args.append('--verbose')
  args.extend(cmd_args)
  output = io.StringIO()
  try:
    success = checksums_main.Main(args, output)
  except:
    output_stripped = output.getvalue().rstrip()
    if output_stripped:
      print(output_stripped)
    raise
  output_lines = []
  for line in output.getvalue().rstrip().split('\n'):
    if not line:
      continue
    output_lines.append(line)
  output.close()
  if expected_output is not None:
    AssertLinesEqual(output_lines, expected_output)
  if success != expected_success:
    raise Exception('Expected main to return %s but returned %s; output=%r'
                    % (expected_success, success, output_lines))
  return output_lines


def DoCreate(root_path, manifest_path=None, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['create', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoDiff(path1, path2, root_path1=None, root_path2=None, manifest_path1=None, manifest_path2=None,
           dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['diff', path1, path2]
  if root_path1 is not None:
    cmd_args.extend(['--root-path1', root_path1])
  if root_path2 is not None:
    cmd_args.extend(['--root-path2', root_path2])
  if manifest_path1 is not None:
    cmd_args.extend(['--manifest-path1', manifest_path1])
  if manifest_path2 is not None:
    cmd_args.extend(['--manifest-path2', manifest_path2])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoVerify(root_path, manifest_path=None, dry_run=False, verbose=False, checksum_all=False,
             paths=[], expected_success=True, expected_output=[]):
  cmd_args = ['verify', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if checksum_all:
    cmd_args.append('--checksum-all')
  for path in paths:
    cmd_args.extend(['--path', path])
  DoChecksumsMain(cmd_args, dry_run=dry_run, verbose=verbose, expected_success=expected_success,
                  expected_output=expected_output)


def DoSync(root_path, manifest_path=None, dry_run=False, checksum_all=False, interactive=False,
           detect_renames=True, paths=[], expected_success=True, expected_output=[]):
  cmd_args = ['sync', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if checksum_all:
    cmd_args.append('--checksum-all')
  if interactive:
    cmd_args.append('--interactive')
  if not detect_renames:
    cmd_args.append('--no-detect-renames')
  for path in paths:
    cmd_args.extend(['--path', path])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoRenamePaths(root_path, manifest_path=None, path_regex_from=None, path_regex_to=None, dry_run=False,
                  expected_success=True, expected_output=[]):
  cmd_args = ['rename-paths', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if path_regex_from is not None:
    cmd_args.extend(['--path-regex-from', path_regex_from])
  if path_regex_to is not None:
    cmd_args.extend(['--path-regex-to', path_regex_to])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoImageFromFolder(root_path, output_path=None, volume_name=None, compressed=True, temp_dir=None,
                      encrypt=False, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['image-from-folder', root_path]
  if output_path is not None:
    cmd_args.extend(['--output-path', output_path])
  if volume_name is not None:
    cmd_args.extend(['--volume-name', volume_name])
  if not compressed:
    cmd_args.append('--no-compressed')
  if encrypt:
    cmd_args.append('--encrypt')
  if temp_dir is not None:
    cmd_args.extend(['--temp-dir', temp_dir])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoSafeCopy(from_path, to_path, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['safe-copy', from_path, to_path]
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoSafeMove(from_path, to_path, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['safe-move', from_path, to_path]
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoRestoreMeta(root_path, manifest_path=None, dry_run=False, mtimes=False, paths=[],
                  expected_success=True, expected_output=[]):
  cmd_args = ['restore-meta', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if mtimes:
    cmd_args.append('--mtimes')
  for path in paths:
    cmd_args.extend(['--path', path])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoDeleteDuplicateFiles(root_path, manifest_path=None, dry_run=False, source_manifest_path=None,
                           allow_source_path_match=False, ignore_mtimes=False, paths=[],
                           expected_success=True, expected_output=[]):
  cmd_args = ['delete-duplicate-files', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if source_manifest_path is not None:
    cmd_args.extend(['--source-manifest-path', source_manifest_path])
  if allow_source_path_match:
    cmd_args.append('--allow-source-path-match')
  if ignore_mtimes:
    cmd_args.append('--ignore-mtimes')
  for path in paths:
    cmd_args.extend(['--path', path])
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)
