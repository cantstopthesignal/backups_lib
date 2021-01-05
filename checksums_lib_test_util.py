import StringIO
import contextlib
import os
import re
import subprocess

import checksums_lib
import lib
import checksums_main

from test_util import AssertEquals
from test_util import AssertLinesEqual
from test_util import CreateDir
from test_util import CreateFile


@contextlib.contextmanager
def InteractiveCheckerReadyResults(interactive_checker):
  try:
    yield interactive_checker
  finally:
    interactive_checker.ClearReadyResults()


def DoChecksumsMain(cmd_args, dry_run=False, verbose=False, expected_success=True, expected_output=[]):
  args = []
  if dry_run:
    args.append('--dry-run')
  if verbose:
    args.append('--verbose')
  args.extend(cmd_args)
  output = StringIO.StringIO()
  try:
    success = checksums_main.Main(args, output)
  except:
    output_stripped = output.getvalue().rstrip()
    if output_stripped:
      print output_stripped
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


def DoVerify(root_path, manifest_path=None, dry_run=False, checksum_all=False,
             expected_success=True, expected_output=[]):
  cmd_args = ['verify', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if checksum_all:
    cmd_args.append('--checksum-all')
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoSync(root_path, manifest_path=None, dry_run=False, checksum_all=False, interactive=False,
           detect_renames=True, expected_success=True, expected_output=[]):
  cmd_args = ['sync', root_path]
  if manifest_path is not None:
    cmd_args.extend(['--manifest-path', manifest_path])
  if checksum_all:
    cmd_args.append('--checksum-all')
  if interactive:
    cmd_args.append('--interactive')
  if not detect_renames:
    cmd_args.append('--no-detect-renames')
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
