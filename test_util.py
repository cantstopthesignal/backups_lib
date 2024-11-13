import argparse
import contextlib
import io
import os
import platform
import plistlib
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import xattr

from . import backups_main
from . import lib


VERBOSE_TESTS = False


@contextlib.contextmanager
def TempDir():
  path = tempfile.mkdtemp()
  try:
    yield path
  finally:
    try:
      shutil.rmtree(path)
    except:
      print('Test: Failed to remove tree %s' % path)


def AssertEquals(a, b, allow_regex_match=False):
  if allow_regex_match and type(a) == re.Pattern:
    if not a.match(b):
      raise Exception('AssertEquals failed: re.compile(%r) does not match %r'
                      % (a.pattern, b))
  elif a != b:
    raise Exception('AssertEquals failed: %r != %r' % (a, b))


def AssertNotEquals(a, b):
  if a == b:
    raise Exception('AssertNotEquals failed: %r == %r' % (a, b))


def AssertLinesEqual(a_lines, b_lines):
  def RaiseNotEqual(hint):
    def LineToStr(line):
      if type(line) == str:
        return repr(line)
      return 're.compile(%r)' % line.pattern
    a_str = ',\n   '.join([ LineToStr(a_line) for a_line in a_lines])
    b_str = ',\n   '.join([ LineToStr(b_line) for b_line in b_lines])
    raise Exception('AssertLinesEqual failed (%s):\n  [%s] !=\n  [%s]' % (hint, a_str, b_str))

  if len(a_lines) != len(b_lines):
    RaiseNotEqual('len %d != len %d' % (len(a_lines), len(b_lines)))
  for i in range(len(a_lines)):
    a_line = a_lines[i]
    b_line = b_lines[i]
    if type(b_line) == str:
      if a_line != b_line:
        RaiseNotEqual('line %r != line %r' % (a_line, b_line))
    elif not b_line.match(a_line):
      RaiseNotEqual('line %r does not match %r' % (a_line, b_line.pattern))


def AssertDiskImageFormat(image_format, image_path, password=None):
  if platform.system() == lib.PLATFORM_DARWIN:
    cmd = ['hdiutil', 'imageinfo', '-plist']
    if password is not None:
      cmd.append('-stdinpass')
    cmd.append(image_path)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    with p.stdin:
      if password is not None:
        p.stdin.write(password.encode('utf8'))
    with p.stdout:
      output = p.stdout.read()
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))
    plist_data = plistlib.loads(output)
    AssertEquals(image_format, plist_data['Format'])
    if password is not None:
      _, image_uuid = lib.GetDiskImageHelper().GetImageEncryptionDetails(image_path)
      assert image_uuid
  else:
    output = subprocess.check_output(
      ['blkid', '-o', 'value', '-s', 'TYPE', image_path], text=True)
    AssertEquals(image_format, output.strip())


def SetMTime(path, mtime=1500000000):
  if mtime is None:
    mtime = 1600000000
  os.utime(path, (mtime, mtime), follow_symlinks=False)


def CreateDir(parent_dir, child_dir, mtime=1500000000):
  parent_mtime = os.lstat(parent_dir).st_mtime
  path = os.path.join(parent_dir, child_dir)
  DeleteFileOrDir(path)
  os.mkdir(path)
  SetMTime(path, mtime)
  SetMTime(parent_dir, parent_mtime)
  return path


def CreateDirs(parent_dir, child_path, mtime=1500000000):
  child_pieces = []
  child_dirname, child_basename = os.path.split(child_path)
  child_pieces.append(child_basename)
  while child_dirname:
    child_dirname, child_basename = os.path.split(child_dirname)
    child_pieces.append(child_basename)
  child_pieces.reverse()

  for child_piece in child_pieces:
    parent_dir = CreateDir(parent_dir, child_piece, mtime=mtime)


def CreateFile(parent_dir, filename, mtime=1500000000, contents=''):
  parent_mtime = os.lstat(parent_dir).st_mtime
  path = os.path.join(parent_dir, filename)
  DeleteFileOrDir(path)
  if type(contents) == list:
    contents = '\n'.join(contents + [''])
  with open(path, 'w') as f:
    f.write(contents)
  SetMTime(path, mtime)
  SetMTime(parent_dir, parent_mtime)
  return path


def CreateSymlink(parent_dir, filename, link_dest, mtime=1500000000):
  parent_mtime = os.lstat(parent_dir).st_mtime
  path = os.path.join(parent_dir, filename)
  DeleteFileOrDir(path)
  os.symlink(link_dest, path)
  SetMTime(path, mtime)
  SetMTime(parent_dir, parent_mtime)
  return path


def DeleteFileOrDir(path):
  if not os.path.lexists(path):
    return
  parent_dir = os.path.dirname(os.path.normpath(path))
  parent_mtime = os.lstat(parent_dir).st_mtime
  if os.path.islink(path) or os.path.isfile(path):
    os.unlink(path)
  else:
    os.rmdir(path)
  SetMTime(parent_dir, parent_mtime)


def RenameFile(old_path, new_path):
  old_parent_dir = os.path.dirname(os.path.normpath(old_path))
  old_parent_mtime = os.lstat(old_parent_dir).st_mtime
  new_parent_dir = os.path.dirname(os.path.normpath(new_path))
  new_parent_mtime = os.lstat(new_parent_dir).st_mtime
  os.rename(old_path, new_path)
  SetMTime(old_parent_dir, old_parent_mtime)
  SetMTime(new_parent_dir, new_parent_mtime)


def SetPacificTimezone():
  os.environ['TZ'] = 'US/Pacific'
  time.tzset()


def DoBackupsMain(cmd_args, dry_run=False, verbose=False, expected_success=True, expected_output=[]):
  args = []
  if dry_run:
    args.append('--dry-run')
  if verbose:
    args.append('--verbose')
  args.extend(cmd_args)
  output = io.StringIO()
  try:
    success = backups_main.Main(args, output)
  except:
    print(output.getvalue().rstrip())
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


class BaseTestCase(unittest.TestCase):
  def setUp(self):
    self.start_time = time.time()

  def tearDown(self):
    run_time = time.time() - self.start_time
    if VERBOSE_TESTS:
      print('ran in %.3fs: ' % run_time, end='')


@contextlib.contextmanager
def OverrideUmask(umask_value):
  old_umask_value = os.umask(umask_value)
  try:
    yield old_umask_value
  finally:
    os.umask(old_umask_value)


def GetRsyncCreatedDirectoryOutputLines():
  if platform.system() == lib.PLATFORM_LINUX:
    return []
  return [re.compile('^created directory .*$')]
