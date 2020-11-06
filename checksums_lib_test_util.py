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
    print output.getvalue().rstrip()
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


def DoVerify(root_path, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['verify', root_path]
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)


def DoSync(root_path, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['sync', root_path]
  DoChecksumsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                  expected_output=expected_output)