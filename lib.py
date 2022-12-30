import argparse
import binascii
import contextlib
import difflib
import errno
import fcntl
import getpass
import hashlib
import io
import json
import os
import pipes
import plistlib
import pwd
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tty
import xattr

from . import staged_backup_pb2


COMMAND_COMPACT_IMAGE = 'compact-image'
COMMAND_DUMP_MANIFEST = 'dump-manifest'
COMMAND_DIFF_MANIFESTS = 'diff-manifests'
COMMAND_VERIFY_MANIFEST = 'verify-manifest'

COMMANDS = [
  COMMAND_DUMP_MANIFEST,
  COMMAND_DIFF_MANIFESTS,
  COMMAND_VERIFY_MANIFEST,
  COMMAND_COMPACT_IMAGE,
]


MANIFEST_FILENAME = 'manifest.pbdata'
BASIS_INFO_FILENAME = 'basis_info.json'

IGNORE_UID_DIFFS = True
IGNORE_GID_DIFFS = True

HDIUTIL_COMPACT_ON_BATTERY_ALLOWED = False

OMIT_UID_AND_GID_IN_PATH_INFO_TO_STRING = False

METADATA_DIR_NAME = '.metadata'
CONTENT_DIR_NAME = 'Root'

MAX_DUP_FIND_COUNT = 10
MAX_DUP_PRINTOUT_COUNT = 5

MIN_SIZE_FOR_SHA256_PROGRESS = 1024 * 1024 * 10
PRINT_PROGRESS_MIN_INTERVAL = .05

DEFAULT_DEFRAGMENT_ITERATIONS = 5

# resize during compaction on Big Sur seems to error
DEFRAGMENT_WITH_COMPACT_WITH_RESIZE = False

GOOGLE_DRIVE_FILE_XATTR_KEY = 'com.google.drivefs.item-id#S'

GOOGLE_DRIVE_FILE_EXTENSIONS_WITH_MISMATCHED_FILE_SIZES = [
  '.gdoc', '.gsheet', '.gform', '.gmap', '.gdraw', '.gslides', '.gsite'
]

OPEN_CONTENT_FUNCTION = open

GETPASS_FUNCTION = getpass.getpass

KEYCHAIN_PASSWORDS_ENABLED = True

DISK_IMAGE_HELPER_OVERRIDE = None

DISK_IMAGE_DEFAULT_CAPACITY = '1T'

TERM_COLOR_BLUE = '1;34m'
TERM_COLOR_CYAN = '1;36m'
TERM_COLOR_GREEN = '1;32m'
TERM_COLOR_PURPLE = '1;35m'
TERM_COLOR_RED = '1;31m'
TERM_COLOR_YELLOW = '1;33m'
TERM_COLOR_RESET = '1;m'


class PathMatcher(object):
  def Matches(self, path):
    raise Exception('Must be implemented by subclass')


class PathMatcherAllOrNone(PathMatcher):
  def __init__(self, match_all):
    self.match_all = match_all

  def Matches(self, path):
    return self.match_all


def PathMatcherAll():
  return PathMatcherAllOrNone(True)


def PathMatcherNone():
  return PathMatcherAllOrNone(False)


class PathMatcherSet(PathMatcher):
  def __init__(self, paths, include=True):
    self.paths = set(paths)
    self.include = include

  def Matches(self, path):
    return self.include == (path in self.paths)


class PathMatcherPathsAndPrefix(PathMatcher):
  def __init__(self, paths):
    self.match_paths = set()
    for path in paths:
      path = os.path.normpath(path)
      if path.startswith('/') or not path:
        raise Exception('Invalid path for matcher: %s' % path)
      self.match_paths.add(path)

  def Matches(self, path):
    path = os.path.normpath(path)
    if path.startswith('/'):
      return False
    while path:
      if path in self.match_paths:
        return True
      path = os.path.dirname(path)
    return False


def AddPathsArgs(parser):
  parser.add_argument('--path', dest='paths', action='append', default=[])
  parser.add_argument('--paths-from')


def GetPathsFromArgs(args, required=True):
  paths = args.paths or []
  if args.paths_from:
    with open(args.paths_from, 'r') as f:
      for path_line in f.read().split('\n'):
        if not path_line:
          continue
        paths.append(DeEscapePath(path_line))
  if required and not paths:
    raise Exception('--path args or --paths-from arg required')
  return sorted(paths)


def GetPathMatcherFromArgs(args, match_all_by_default=True):
  paths = GetPathsFromArgs(args, required=not match_all_by_default)
  if paths:
    return PathMatcherPathsAndPrefix(paths)
  else:
    assert match_all_by_default
    return PathMatcherAll()


def IsRunningAsRoot():
  return os.geteuid() == 0


def EnsureRunningAsRoot():
  if not IsRunningAsRoot():
    raise Exception('This script must be run with sudo')


def GetManifestBackupPath(manifest_path):
  path = '%s.bak' % manifest_path
  assert path.endswith('.pbdata.bak')
  return path


def FileSizeStringToBytes(size_str):
  if size_str.endswith('gb'):
    return int(float(size_str[:-2]) * 1024 * 1024 * 1024)
  elif size_str.endswith('mb'):
    return int(float(size_str[:-2]) * 1024 * 1024)
  elif size_str.endswith('kb'):
    return int(float(size_str[:-2]) * 1024)
  assert size_str.endswith('b')
  return int(size_str[:-1])


def FileSizeToString(size, strip_trailing_zero=True):
  def SizeFormat(sz, suffix):
    sz_str = '%.1f' % sz
    if sz_str.endswith('.0') and strip_trailing_zero:
      sz_str = sz_str[:-2]
    return sz_str + suffix
  if size < 1024 and size > -1024:
    return '%db' % size
  size /= 1024.0
  if size < 1024 and size > -1024:
    return SizeFormat(size, 'kb')
  size /= 1024.0
  if size < 1024 and size > -1024:
    return SizeFormat(size, 'mb')
  size /= 1024.0
  return SizeFormat(size, 'gb')


def UnixTimeToSecondsString(unix_time):
  return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(unix_time))


def GetRsyncBin():
  home = os.getenv('HOME')
  assert os.path.exists(home)
  return os.path.join(home, 'bin/rsync')


def MakeRsyncDirname(dirname, absolute=False):
  assert dirname
  if not dirname.endswith('/'):
    dirname = dirname + '/'
  if absolute and not dirname.startswith('/'):
    dirname = '/' + dirname
  return dirname


def EscapeString(s):
  return s.encode('unicode_escape').decode('ascii')


def EscapePath(path):
  return EscapeString(path)


def DeEscapeString(s):
  return s.encode('ascii').decode('unicode_escape')


def DeEscapePath(path):
  return DeEscapeString(path)


class UnsupportedMatcherError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


class FilterRule(object):
  @staticmethod
  def MatchesPath(matcher, path, path_stat):
    if stat.S_ISDIR(path_stat.st_mode):
      path += '/'
    return not not matcher.match(path)

  @staticmethod
  def CompileRegex(matcher):
    matcher = DeEscapePath(matcher)
    regex_pieces = []
    if matcher.startswith('/'):
      regex_pieces.append('^')
      matcher_i = 1
    else:
      regex_pieces.append('^(?:.*/)?')
      matcher_i = 0
    matcher_len = len(matcher)
    while matcher_i < matcher_len:
      c = matcher[matcher_i]
      if c == '*':
        if matcher_i + 1 < matcher_len and matcher[matcher_i + 1] == '*':
          regex_pieces.append('.*')
          matcher_i += 2
          continue
        regex_pieces.append('[^/]*')
        matcher_i += 1
        continue
      if c in '?[\\':
        raise UnsupportedMatcherError('Matcher %r not yet supported' % matcher)
      regex_pieces.append(re.escape(c))
      matcher_i += 1
    if matcher[matcher_len - 1] != '/':
      regex_pieces.append('/?')
    regex_pieces.append('$')

    return re.compile(''.join(regex_pieces))

  def GetRsyncArg(self):
    raise Exception('Not implemented')


class FilterRuleInclude(FilterRule):
  def __init__(self, path):
    self.path = path
    self.regex = FilterRule.CompileRegex(self.path)

  def MatchesPath(self, test_path, test_path_stat):
    return FilterRule.MatchesPath(self.regex, test_path, test_path_stat)

  def GetRsyncArg(self):
    return '--include=%s' % self.path

  def __str__(self):
    return '<FilterRuleInclude %r>' % self.path


class FilterRuleExclude(FilterRule):
  def __init__(self, path):
    self.path = path
    self.regex = FilterRule.CompileRegex(self.path)

  def MatchesPath(self, test_path, test_path_stat):
    return FilterRule.MatchesPath(self.regex, test_path, test_path_stat)

  def GetRsyncArg(self):
    return '--exclude=%s' % self.path

  def __str__(self):
    return '<FilterRuleExclude %r>' % self.path


class FilterRuleFollowSymlink(FilterRule):
  def __init__(self, path):
    self.path = path
    self.regex = FilterRule.CompileRegex(self.path)

  def MatchesPath(self, test_path, test_path_stat):
    return FilterRule.MatchesPath(self.regex, test_path, test_path_stat)

  def __str__(self):
    return '<FilterRuleFollowSymlink %r>' % self.path


class FilterRuleDirMerge(FilterRule):
  def __init__(self, filename):
    self.filename = filename

  def GetFilename(self):
    return self.filename

  def GetRsyncArg(self):
    return '--filter=dir-merge /%s' % self.filename

  def __str__(self):
    return '<FilterRuleDirMerge %r>' % self.filename


class FilterRuleMerge(object):
  def __init__(self, path):
    self.path = path

  def GetPath(self):
    return self.path

  def GetRsyncArg(self):
    return '--filter=merge %s' % self.path

  def __str__(self):
    return '<FilterRuleMerge %r>' % self.path


IGNORED_XATTR_KEYS = [
  'com.apple.avkit.thumbnailCacheEncryptionKey',
  'com.apple.avkit.thumbnailCacheIdentifier',
  'com.apple.diskimages.recentcksum',
  'com.apple.lastuseddate#PS',
  'com.apple.macl',
  'com.apple.quarantine',
  'user.drive.can_manage_team_drive_members',
  'user.drive.md5',
  'user.drive.shortcut.target.stableid',
  'user.drive.stableid',
]


@contextlib.contextmanager
def Chdir(new_cwd):
  old_cwd = os.getcwd()
  try:
    os.chdir(new_cwd)
    yield
  finally:
    os.chdir(old_cwd)


class InteractiveChecker:
  def __init__(self):
    self.ready_results = []

  def AddReadyResult(self, result):
    self.ready_results.append(result)

  def ClearReadyResults(self):
    self.ready_results = []

  def Confirm(self, message, output):
    if self.ready_results:
      result = self.ready_results[0]
      del self.ready_results[0]
      print('%s (y/N): %s' % (message, result and 'y' or 'n'), file=output)
      return result

    print('%s (y/N):' % message, end=' ', file=output)
    return input() == 'y'


class MtimePreserver(object):
  def __init__(self):
    self.preserved_path_mtimes = {}

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc, exc_traceback):
    for path, mtime in list(self.preserved_path_mtimes.items()):
      try:
        os.utime(path, (mtime, mtime), follow_symlinks=False)
      except FileNotFoundError:
        pass

  def PreserveMtime(self, path):
    path = os.path.normpath(path)
    if path not in self.preserved_path_mtimes:
      self.preserved_path_mtimes[path] = os.lstat(path).st_mtime

  def PreserveParentMtime(self, path):
    path = os.path.normpath(path)
    self.PreserveMtime(os.path.dirname(path))

  def RemovePreservationForPath(self, path):
    path = os.path.normpath(path)
    self.preserved_path_mtimes.pop(path, None)


@contextlib.contextmanager
def PreserveParentMtime(path):
  parent_dir = os.path.dirname(path)
  parent_stat = os.lstat(parent_dir)
  yield
  os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime), follow_symlinks=False)


def ClearPathHardlinks(path, dry_run=False):
  stat = os.lstat(path)
  if stat.st_nlink == 1:
    return
  parent_dir = os.path.dirname(path)
  parent_stat = os.lstat(parent_dir)
  if not dry_run:
    tmp = tempfile.NamedTemporaryFile(dir=parent_dir, delete=False)
    try:
      tmp.close()
      subprocess.check_call(['cp', '-a', path, tmp.name])
      os.rename(tmp.name, path)
      os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime), follow_symlinks=False)
    except:
      os.unlink(tmp.name)
      raise


class EscapeKeyDetector(threading.Thread):
  INSTANCE = None
  CANCEL_AT_INVOCATION = None

  @staticmethod
  def SetCancelAtInvocation(invocation_num):
    EscapeKeyDetector.CANCEL_AT_INVOCATION = invocation_num

  @staticmethod
  def ClearCancelAtInvocation():
    EscapeKeyDetector.CANCEL_AT_INVOCATION = None

  def __init__(self, input_stream=sys.stdin):
    assert EscapeKeyDetector.INSTANCE is None
    EscapeKeyDetector.INSTANCE = self

    threading.Thread.__init__(self)
    self.condition = threading.Condition()
    self.input_stream = input_stream
    self.shutdown = False
    self.escape_pressed = False
    self.start()

  def run(self):
    if not self.input_stream.isatty():
      return
    stdin_fd = self.input_stream.fileno()
    old_terminal_settings = termios.tcgetattr(stdin_fd)
    try:
      tty.setcbreak(stdin_fd)

      with self.condition:
        while not self.shutdown and not self.escape_pressed:
          if select.select([stdin_fd], [], [], 0)[0] == [stdin_fd]:
            if ord(self.input_stream.read(1)) == 27:
              self.escape_pressed = True
          self.condition.wait(.1)
    finally:
      termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_terminal_settings)

  def WasEscapePressed(self):
    if EscapeKeyDetector.CANCEL_AT_INVOCATION is not None:
      if EscapeKeyDetector.CANCEL_AT_INVOCATION == 0:
        return True
      EscapeKeyDetector.CANCEL_AT_INVOCATION -= 1
      return False

    with self.condition:
      return self.escape_pressed

  def Shutdown(self):
    with self.condition:
      self.shutdown = True
      self.condition.notify()
    self.join()

    assert EscapeKeyDetector.INSTANCE == self
    EscapeKeyDetector.INSTANCE = None


def Sha256(path):
  BLOCKSIZE = 65536
  hasher = hashlib.sha256()
  with OPEN_CONTENT_FUNCTION(path, 'rb') as f:
    buf = f.read(BLOCKSIZE)
    while len(buf) > 0:
      hasher.update(buf)
      buf = f.read(BLOCKSIZE)
  return hasher.digest()


def GetTerminalSize(output):
  if output.isatty():
    cr = struct.unpack('hh', fcntl.ioctl(output, termios.TIOCGWINSZ, '1234'))
    return int(cr[1]), int(cr[0])


def Sha256WithProgress(full_path, path_info, output):
  try:
    BLOCKSIZE = 65536
    hasher = hashlib.sha256()
    read_bytes = 0
    read_bytes_str_max_len = 0
    print_progress = output.isatty() and path_info.size > MIN_SIZE_FOR_SHA256_PROGRESS
    last_progress_time = 0
    with OPEN_CONTENT_FUNCTION(full_path, 'rb') as f:
      buf = f.read(BLOCKSIZE)
      read_bytes += len(buf)
      while len(buf) > 0:
        hasher.update(buf)
        buf = f.read(BLOCKSIZE)
        read_bytes += len(buf)
        now = time.time()
        if print_progress and now > last_progress_time + PRINT_PROGRESS_MIN_INTERVAL:
          last_progress_time = now
          terminal_width = GetTerminalSize(output)[0]
          read_bytes_str = FileSizeToString(read_bytes, strip_trailing_zero=False)
          total_bytes_str = FileSizeToString(path_info.size, strip_trailing_zero=False)
          read_bytes_str_max_len = max(read_bytes_str_max_len, len(read_bytes_str))
          read_bytes_str_max_len = max(read_bytes_str_max_len, len(total_bytes_str))
          read_bytes_str = read_bytes_str + ' ' * (read_bytes_str_max_len - len(read_bytes_str))
          message = '[%s/%s] ' % (read_bytes_str, total_bytes_str)
          max_path_len = terminal_width - len(message) - 2
          if len(path_info.path) > max_path_len:
            message += '\u2026' + path_info.path[len(path_info.path)-max_path_len+1:]
          else:
            message += path_info.path
          output.write('\033[K%s\r' % message)
    if print_progress:
      output.write("\033[K")
    return hasher.digest()
  except Exception as e:
    print('*** Error reading %s' % EscapePath(full_path), file=output)
    raise


def Stat(path, follow_symlinks=False):
  if follow_symlinks:
    return os.stat(path)
  else:
    return os.lstat(path)


def Xattr(path, follow_symlinks=False):
  options = 0
  if not follow_symlinks:
    options = xattr.XATTR_NOFOLLOW
  return xattr.xattr(path, options=options)


def ParseXattrData(path, path_type, ignored_keys=[], follow_symlinks=False):
  xattr_hash = None
  xattr_keys = []

  xattr_data = Xattr(path, follow_symlinks=follow_symlinks)
  xattr_list = []
  for key in sorted(xattr_data.keys()):
    if key in ignored_keys:
      continue
    try:
      value = xattr_data[key]
    except KeyError as e:
      continue
    xattr_keys.append(key)
    xattr_list.append((key, value))
  if xattr_list:
    hasher = hashlib.sha256()
    byte_str_list = []
    for key, value in xattr_list:
      assert type(key) == str
      assert type(value) == bytes
      key_encoded = repr(key).encode('ascii')
      value_encoded = repr(value).encode('ascii')
      assert value_encoded[:1] == b'b'
      byte_str_list.append(b'(%b, %b)' % (key_encoded, value_encoded[1:]))
    byte_str = b'[%b]' % b', '.join(byte_str_list)
    hasher.update(byte_str)
    xattr_hash = hasher.digest()
  return xattr_hash, xattr_keys


def GetCorrectedGoogleDriveFileSize(path_stat, path):
  BLOCKSIZE = 65536

  assert stat.S_ISREG(path_stat.st_mode)
  _, ext = os.path.splitext(path)
  if ext not in GOOGLE_DRIVE_FILE_EXTENSIONS_WITH_MISMATCHED_FILE_SIZES:
    return path_stat.st_size
  with OPEN_CONTENT_FUNCTION(path, 'rb') as in_f:
    in_f.seek(0, io.SEEK_END)
    size = in_f.tell()
    buf = in_f.read(BLOCKSIZE)
    while len(buf) > 0:
      size += len(buf)
      buf = in_f.read(BLOCKSIZE)
    return size


def GetPathTreeSize(path, files_only=False, excludes=[]):
  path_stat = os.lstat(path)
  if stat.S_ISDIR(path_stat.st_mode):
    if files_only:
      total_size = 0
    else:
      total_size = path_stat.st_size
    for parent_path, child_dirs, child_files in os.walk(path):
      for child_name in child_dirs + child_files:
        if child_name in excludes:
          continue
        child_stat = os.lstat(os.path.join(parent_path, child_name))
        if not stat.S_ISDIR(child_stat.st_mode) or not files_only:
          total_size += child_stat.st_size
    return total_size
  else:
    return path_stat.st_size


def GetDriveAvailableSpace(path):
  output = subprocess.check_output(['df', '-k', path], text=True)
  (header_row, data_row) = output.strip().split('\n')
  assert header_row.split()[:4] == [
    'Filesystem', '1024-blocks', 'Used', 'Available']
  data_row = data_row.split()
  available_kbs = int(data_row[3])
  return available_kbs * 1024


class DiskImageHelperAuthenticationError(Exception):
  def __init__(self):
    Exception.__init__(self)


class DiskImageHelperAttachResult:
  def __init__(self):
    self.mount_point = None
    self.device = None


class DiskImageHelper:
  def __init__(self):
    pass

  def CreateImage(self, path, size=None, filesystem=None, image_type=None, volume_name=None,
                  encryption=None, password=None):
    assert not os.path.lexists(path)
    if encryption is not None:
      assert password is not None
    cmd = ['hdiutil', 'create']
    if size is not None:
      cmd.extend(['-size', size])
    if filesystem is not None:
      cmd.extend(['-fs', filesystem])
    if image_type is not None:
      cmd.extend(['-type', image_type])
    if volume_name is not None:
      cmd.extend(['-volname', 'Backups'])
    if encryption is not None:
      cmd.extend(['-encryption', encryption])
      if password is not None:
        cmd.append('-stdinpass')
    cmd.extend(['-quiet', '-atomic'])
    cmd.append(path)

    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
    if password is not None:
      p.stdin.write(password)
    p.stdin.close()
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))

    if IsRunningAsRoot():
      pwd_info = pwd.getpwnam(os.getlogin())
      os.chown(path, pwd_info.pw_uid, pwd_info.pw_gid, follow_symlinks=True)

  def AttachImage(self, path, encrypted=False, password=None, mount=False,
                  random_mount_point=False, mount_point=None,
                  readonly=True, browseable=False, verify=True):
    cmd = ['hdiutil', 'attach', path, '-owners', 'on', '-plist']
    if encrypted:
      cmd.append('-stdinpass')
    if mount:
      if random_mount_point:
        cmd.extend(['-mountrandom', tempfile.gettempdir()])
      else:
        cmd.extend(['-mountpoint', mount_point])
    else:
      cmd.append('-nomount')
    if readonly:
      cmd.append('-readonly')
    if mount and not browseable:
      cmd.append('-nobrowse')
    if not verify:
      cmd.append('-noverify')
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    if encrypted:
      p.stdin.write(password.encode('utf8'))
    p.stdin.close()
    with p.stdout:
      output = p.stdout.read()
    if p.wait():
      lines = output.decode('utf8').strip().split('\n')
      if len(lines) == 1 and lines[0].endswith('- Authentication error'):
        raise DiskImageHelperAuthenticationError()
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))

    result = DiskImageHelperAttachResult()
    plist_data = plistlib.loads(output)
    for entry in plist_data['system-entities']:
      if entry['content-hint'] == 'GUID_partition_scheme':
        assert result.device is None
        result.device = entry['dev-entry']
        assert result.device.startswith('/dev/')
      if 'mount-point' in entry:
        assert result.mount_point is None
        result.mount_point = entry['mount-point']
        assert os.path.isdir(result.mount_point)
        if not random_mount_point and mount_point is not None:
          assert os.path.samefile(mount_point, result.mount_point)
    if result.device is None or (mount and result.mount_point is None):
      raise Exception('Unexpected output from hdiutil attach:\n%s' % output.decode('utf8'))
    return result

  def DetachImage(self, device):
    cmd = ['hdiutil', 'detach', device]
    for i in range(20):
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
      with p.stdout:
        output = p.stdout.read().strip()
      if not p.wait():
        break
      if output.endswith('- No such file or directory'):
        break
      elif (not output.endswith('- Resource busy')
            and not output.endswith('\nhdiutil: detach: drive not detached')):
        raise Exception('Unexpected output from %r: %r' % (cmd, output))
      time.sleep(10)
    else:
      raise Exception('Command %r failed after retries' % cmd)

  def MoveImage(self, from_path, to_path):
    shutil.move(from_path, to_path)

  def GetImageEncryptionDetails(self, image_path):
    cmd = ['hdiutil', 'isencrypted', image_path]
    for i in range(5):
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
      with p.stdout:
        output = p.stdout.read().strip()
      if not p.wait():
        break
      if (not output.endswith('- Resource busy')
          and not output.endswith('- Resource temporarily unavailable')):
        raise Exception('Unexpected output from %r: %r' % (cmd, output))
      time.sleep(.5)
    else:
      raise Exception('Command %r failed after retries' % cmd)

    encrypted = None
    image_uuid = None
    for line in output.split('\n'):
      m = re.match('^encrypted: (YES|NO)$', line)
      if m:
        encrypted = m.group(1) == 'YES'
      m = re.match('^uuid: ([A-Z0-9-]+)$', line)
      if m:
        image_uuid = m.group(1)
    assert encrypted is not None
    if encrypted:
      assert image_uuid
    return (encrypted, image_uuid)


def GetDiskImageHelper():
  if DISK_IMAGE_HELPER_OVERRIDE is not None:
    return DISK_IMAGE_HELPER_OVERRIDE()
  else:
    return DiskImageHelper()


def CreateDiskImage(image_path, volume_name=None, size=DISK_IMAGE_DEFAULT_CAPACITY,
                    filesystem='APFS', image_type=None, encrypt=False, encryption_manager=None,
                    dry_run=False):
  encryption = None
  password = None
  if encrypt:
    password = encryption_manager.CreatePassword(image_path)
    encryption = 'AES-128'

  if not dry_run:
    GetDiskImageHelper().CreateImage(
      image_path, size=size, filesystem=filesystem, image_type=image_type, volume_name=volume_name,
      encryption=encryption, password=password)

    if password is not None:
      _, image_uuid = GetDiskImageHelper().GetImageEncryptionDetails(image_path)
      assert image_uuid
      encryption_manager.SavePassword(password, image_uuid)


def CompactImage(image_path, output, encryption_manager=None, encrypted=None, image_uuid=None,
                 dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(image_path)

  cmd = ['hdiutil', 'compact', image_path]
  if encrypted:
    cmd.append('-stdinpass')
  if HDIUTIL_COMPACT_ON_BATTERY_ALLOWED:
    cmd.append('-batteryallowed')

  if not dry_run:
    if encrypted:
      password = encryption_manager.GetPassword(
        image_path, image_uuid, try_last_password=False)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    if encrypted:
      p.stdin.write(password)
    p.stdin.close()
    with p.stdout:
      output.write(p.stdout.read())
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))


def ResizeImage(image_path, block_count, output, encryption_manager=None, encrypted=None,
                image_uuid=None, dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(image_path)

  cmd = ['hdiutil', 'resize', '-size', '%db' % block_count, image_path]
  if encrypted:
    cmd.append('-stdinpass')

  if not dry_run:
    if encrypted:
      password = encryption_manager.GetPassword(
        image_path, image_uuid, try_last_password=False)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    if encrypted:
      p.stdin.write(password)
    p.stdin.close()
    with p.stdout:
      output.write(p.stdout.read())
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))


def IsLikelyPathToDiskImage(path):
  ext = os.path.splitext(path)[1]
  if os.path.isfile(path) and ext in ['.dmg', '.sparseimage']:
    return True
  if os.path.isdir(path) and ext in ['.sparsebundle']:
    return True
  return False


class DiskPartitionInfo(object):
  def __init__(self):
    self.name = None
    self.start = None
    self.length = None
    self.hint = None

  def IsValid(self):
    return (self.name is not None and self.start is not None
            and self.length is not None and self.hint is not None)

  def __str__(self):
    out = []
    if self.name:
      out.append(repr(self.name))
    out.extend(['start=%d' % self.start,
                'length=%d' % self.length])
    if self.hint:
      out.append('hint=%r' % self.hint)
    return 'Partition<%s>' % ', '.join(out)


def CleanFreeSparsebundleBands(image_path, output, encryption_manager=None, encrypted=None,
                               image_uuid=None, dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(image_path)

  if not os.path.normpath(image_path).endswith('.sparsebundle'):
    raise Exception('Expected %s to be a sparsebundle image' % image_path)

  with open(os.path.join(image_path, 'Info.plist'), 'rb') as plist_file:
    plist_data = plistlib.load(plist_file)
  assert plist_data['CFBundleInfoDictionaryVersion'] == '6.0'
  assert plist_data['bundle-backingstore-version'] == 1
  assert plist_data['diskimage-bundle-type'] == 'com.apple.diskimage.sparsebundle'
  band_size = plist_data['band-size']

  cmd = ['hdiutil', 'imageinfo', image_path]
  if encrypted:
    cmd.append('-stdinpass')
    password = encryption_manager.GetPassword(
      image_path, image_uuid, try_last_password=False)
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
  if encrypted:
    p.stdin.write(password)
  p.stdin.close()
  with p.stdout:
    hdiutil_output = p.stdout.read()
  if p.wait():
    raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))

  block_size = None
  partitions = []

  current_partition = None
  in_partitions = False
  in_partitions_body = False
  for line in hdiutil_output.split('\n'):
    if line == 'partitions:':
      in_partitions = True
      continue
    if in_partitions and not line.startswith('\t'):
      break
    if not in_partitions:
      continue
    m = re.match('^\tblock-size: ([0-9]+)$', line)
    if m:
      block_size = int(m.group(1))
    if line == '\tpartitions:':
      in_partitions_body = True
      continue
    if not in_partitions_body:
      continue
    if not line.startswith('\t\t'):
      break
    m = re.match('^\t\t[0-9]+:$', line)
    if m:
      if current_partition is not None:
        assert current_partition.IsValid()
        partitions.append(current_partition)
        current_partition = None
      continue
    m = re.match('^\t\t\tpartition-(name|start|length|hint): (.*)$', line)
    if not m:
      continue
    (key, value) = m.group(1, 2)
    if current_partition is None:
      current_partition = DiskPartitionInfo()
    if key == 'name':
      current_partition.name = value
    elif key == 'start':
      current_partition.start = int(value)
    elif key == 'length':
      current_partition.length = int(value)
    elif key == 'hint':
      current_partition.hint = value

  if current_partition is not None:
    assert current_partition.IsValid()
    partitions.append(current_partition)

  assert block_size is not None

  bands_with_files = set()
  for band_name in os.listdir(os.path.join(image_path, 'bands')):
    bands_with_files.add(int(band_name, 16))

  for partition in partitions:
    if partition.name == '' and partition.hint == 'Apple_Free':
      start_band = int((partition.start * block_size) / band_size)
      end_band = int(((partition.start + partition.length) * block_size) / band_size)
      bands_to_delete = set()
      for band_id in range(start_band + 1, end_band):
        if band_id in bands_with_files:
          bands_to_delete.add(band_id)
      if bands_to_delete:
        print('Deleting %d bands between (%d,%d) for empty partition %s...' % (
          len(bands_to_delete), start_band, end_band, partition), file=output)
        for band_id in bands_to_delete:
          band_path = os.path.join(image_path, 'bands', hex(band_id)[2:])
          if not dry_run:
            os.unlink(band_path)


def CompactImageWithResize(image_path, output, encryption_manager=None, encrypted=None,
                           image_uuid=None, dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(image_path)

  (current_block_count, min_block_count) = GetDiskImageLimits(
    image_path, encryption_manager=encryption_manager, encrypted=encrypted, image_uuid=image_uuid)

  print('Resizing image to minimum size: %d -> %d blocks...' % (
    current_block_count, min_block_count), file=output)
  ResizeImage(image_path, block_count=min_block_count, output=output,
              encryption_manager=encryption_manager, encrypted=encrypted,
              image_uuid=image_uuid, dry_run=dry_run)

  if os.path.normpath(image_path).endswith('.sparsebundle'):
    CleanFreeSparsebundleBands(
      image_path, output=output, encryption_manager=encryption_manager, encrypted=encrypted,
      image_uuid=image_uuid, dry_run=dry_run)

  print('Restoring image size to %d blocks...' % current_block_count, file=output)
  ResizeImage(image_path, block_count=current_block_count, output=output,
              encryption_manager=encryption_manager, encrypted=encrypted,
              image_uuid=image_uuid, dry_run=dry_run)

  CompactImage(image_path, output=output, encryption_manager=encryption_manager, encrypted=encrypted,
               image_uuid=image_uuid, dry_run=dry_run)


def StripUtf8BidiCommandChars(s):
  return s.replace('\u2068', '').replace('\u2069', '')


def GetApfsDeviceFromAttachedImageDevice(image_device, output):
  assert image_device.startswith('/dev/')
  diskutil_output = subprocess.check_output(['diskutil', 'list', image_device], text=True)
  apfs_identifier = None
  for line in diskutil_output.split('\n'):
    pieces = [ StripUtf8BidiCommandChars(p) for p in line.strip().split() ]
    if pieces[1:3] == ['Apple_APFS', 'Container']:
      if apfs_identifier is not None:
        raise Exception('Multiple apfs containers found in diskutil output: %s' % diskutil_output)
      apfs_identifier = pieces[-1]
  if apfs_identifier is None:
    print('*** Warning: no apfs container found to defragment:', file=output)
    for line in diskutil_output.split('\n'):
      print(line, file=output)
    return

  apfs_device = os.path.join('/dev', apfs_identifier)
  assert apfs_device.startswith(image_device)

  return apfs_device


def GetApfsDeviceLimits(apfs_device):
  current_bytes = None
  min_bytes = None
  diskutil_output = subprocess.check_output(['diskutil', 'apfs', 'resizeContainer', apfs_device,
                                             'limits'], text=True)
  for line in diskutil_output.split('\n'):
    line = line.strip()
    m = re.match('^Current Physical Store partition size on map:.*[(]([0-9]+) Bytes[)]$', line)
    if m:
      current_bytes = int(m.group(1))
    m = re.match('^Minimum [(]constrained by file/snapshot usage[)]:.*[(]([0-9]+) Bytes[)]$', line)
    if m:
      min_bytes = int(m.group(1))
  if current_bytes is None or min_bytes is None:
    raise Exception('Could not determine minimum and current bytes for apfs device %s' % apfs_device)

  return (current_bytes, min_bytes)


def ResizeApfsContainer(apfs_device, new_size, output):
  cmd = ['diskutil', 'apfs', 'resizeContainer', apfs_device, str(new_size)]
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
  with p.stdout:
    for line in p.stdout:
      print(line.rstrip(), file=output)
  if p.wait():
    raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))


def GetDiskImageLimits(image_path, encryption_manager, encrypted=None, image_uuid=None):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(image_path)

  cmd = ['hdiutil', 'resize', '-limits', image_path]
  if encrypted:
    cmd.append('-stdinpass')

  if encrypted:
    password = encryption_manager.GetPassword(
      image_path, image_uuid, try_last_password=False)
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
  if encrypted:
    p.stdin.write(password)
  p.stdin.close()
  with p.stdout:
    hdiutil_output = p.stdout.read()
  if p.wait():
    raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))

  lines = hdiutil_output.strip().split('\n')
  if len(lines) != 1:
    raise Exception('Unexpected output from hdiutil resize -limits: %r' % hdiutil_output)
  min_blocks, current_blocks, _ = lines[0].split()
  min_blocks = int(min_blocks)
  current_blocks = int(current_blocks)

  return (current_blocks, min_blocks)


def CompactAndDefragmentImage(
    image_path, output, defragment=False, defragment_iterations=DEFAULT_DEFRAGMENT_ITERATIONS,
    encryption_manager=None, dry_run=False):
  (encrypted, image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(image_path)

  if not defragment:
    CompactImage(image_path, output=output, encryption_manager=encryption_manager,
                 encrypted=encrypted, image_uuid=image_uuid, dry_run=dry_run)
    return

  old_apfs_container_size = None
  with ImageAttacher(image_path, readonly=dry_run, mount=False,
                     encryption_manager=encryption_manager) as attacher:
    apfs_device = GetApfsDeviceFromAttachedImageDevice(attacher.GetDevice(), output)
    if apfs_device is None:
      raise Exception('No apfs device found for disk image')
    old_apfs_container_size, min_bytes = GetApfsDeviceLimits(apfs_device)

    print('Defragmenting %s; apfs min size %s, current size %s...' % (
      image_path, FileSizeToString(min_bytes), FileSizeToString(old_apfs_container_size)), file=output)
    if not dry_run:
      for i in range(defragment_iterations):
        if i:
          _, new_min_bytes = GetApfsDeviceLimits(apfs_device)
          if new_min_bytes >= min_bytes * 0.95:
            print('Iteration %d, new apfs min size %s has low savings' % (
              i+1, FileSizeToString(new_min_bytes)), file=output)
            break
          print('Iteration %d, new apfs min size %s...' % (
            i+1, FileSizeToString(new_min_bytes)), file=output)
          min_bytes = new_min_bytes
        ResizeApfsContainer(apfs_device, min_bytes, output=output)

  if DEFRAGMENT_WITH_COMPACT_WITH_RESIZE:
    CompactImageWithResize(image_path, output=output, encryption_manager=encryption_manager,
                           encrypted=encrypted, image_uuid=image_uuid, dry_run=dry_run)
  else:
    CompactImage(image_path, output=output, encryption_manager=encryption_manager,
                 encrypted=encrypted, image_uuid=image_uuid, dry_run=dry_run)

  if not dry_run:
    print('Restoring apfs container size to %s...' % (
      FileSizeToString(old_apfs_container_size)), file=output)
    with ImageAttacher(image_path, readonly=dry_run, mount=False,
                       encryption_manager=encryption_manager) as attacher:
      apfs_device = GetApfsDeviceFromAttachedImageDevice(attacher.GetDevice(), output)
      if apfs_device is None:
        raise Exception('No apfs device found for disk image, cannot restore to %d bytes'
                        % old_apfs_container_size)
      ResizeApfsContainer(apfs_device, old_apfs_container_size, output=output)

  CompactImage(image_path, output=output, encryption_manager=encryption_manager,
               encrypted=encrypted, image_uuid=image_uuid, dry_run=dry_run)


def DecodeRsyncEncodedString(s):
  def DecodeRsyncEscape(m):
    return chr(int(m.group(1), 8))
  return re.sub('\\\\#([0-9]{3})', DecodeRsyncEscape, s)


def RsyncDirectoryOnly(src_dir, dest_dir, output, dry_run=False, verbose=False):
  cmd = [GetRsyncBin(),
         '-aX',
         '--exclude=*',
         '--numeric-ids',
         '--no-specials',
         '--no-devices']

  if verbose:
    cmd.append('-i')
  else:
    cmd.append('-q')
  if dry_run:
    cmd.append('-n')

  cmd.append(MakeRsyncDirname(src_dir))
  cmd.append(MakeRsyncDirname(dest_dir))

  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
  with p.stdout:
    for line in p.stdout:
      print(line.strip(), file=output)
  if p.wait():
    raise Exception('Rsync failed')


def RsyncPaths(paths, src_root_path, dest_root_path, output, dry_run=False, verbose=False):
  sync_roots = '.' in paths
  if sync_roots:
    paths.remove('.')

  cmd = [GetRsyncBin(),
         '-aX',
         '--no-r',
         '--files-from=-',
         '--from0',
         '--checksum',
         '--numeric-ids',
         '--no-specials',
         '--no-devices']
  if verbose:
    cmd.append('-i')
  else:
    cmd.append('-q')
  if dry_run:
    cmd.append('-n')

  cmd.append(MakeRsyncDirname(src_root_path))
  cmd.append(MakeRsyncDirname(dest_root_path))

  if verbose:
    print(' '.join([ pipes.quote(c) for c in cmd ]), file=output)
    print('(%d paths)' % len(paths), file=output)
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
  for path in paths:
    p.stdin.write('%s\0' % path)
  p.stdin.close()
  with p.stdout:
    for line in p.stdout:
      print(line.strip(), file=output)
  if p.wait():
    raise Exception('Rsync failed')

  if sync_roots:
    RsyncDirectoryOnly(src_root_path, dest_root_path, output, dry_run=dry_run, verbose=verbose)


def RsyncList(src_path, output, filters=None, verbose=False):
  cmd = [GetRsyncBin(),
         '-a',
         '--list-only',
         '--no-specials',
         '--no-devices']

  if filters is not None:
    for a_filter in filters:
      cmd.append(a_filter.GetRsyncArg())

  cmd.append(MakeRsyncDirname(src_path))

  if verbose:
    print(' '.join([ pipes.quote(c) for c in cmd ]), file=output)
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True)
  out, err = p.communicate()
  for line in out.split('\n'):
    line = line.strip()
    if not line:
      continue
    path = line.split(None, 4)[4]
    if line[0] == 'l':
      symlink_parts = path.split(' -> ')
      assert len(symlink_parts) == 2
      path = symlink_parts[0]
    elif line[0] == 's':
      full_path = os.path.join(src_path, DecodeRsyncEncodedString(path))
      if stat.S_ISSOCK(os.lstat(full_path).st_mode):
        continue
      raise Exception('Unexpected path type for rsync line %r' % line)
    elif line[0] not in ['d', '-']:
      raise Exception('Unexpected path type for rsync line %r' % line)
    yield DecodeRsyncEncodedString(path)
  if p.wait():
    print(err.rstrip(), file=output)
    raise Exception('Rsync failed')


def Rsync(src_root_path, dest_root_path, output, dry_run=False, verbose=False, link_dest=None):
  cmd = [GetRsyncBin(),
         '-aX',
         '--numeric-ids',
         '--no-specials',
         '--no-devices']
  if verbose:
    cmd.append('-i')
  else:
    cmd.append('-q')
  if dry_run:
    cmd.append('-n')
  if link_dest is not None:
    cmd.append('--link-dest=%s' % MakeRsyncDirname(link_dest))

  cmd.append(MakeRsyncDirname(src_root_path))
  cmd.append(MakeRsyncDirname(dest_root_path))

  if verbose:
    print(' '.join([ pipes.quote(c) for c in cmd ]), file=output)
    print('(%d paths)' % len(paths), file=output)
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
  with p.stdout:
    for line in p.stdout:
      print(line.strip(), file=output)
  if p.wait():
    raise Exception('Rsync failed')


class PathSyncer(object):
  class PathData(object):
    def __init__(self, path, follow_symlinks=False):
      self.path = path
      self.follow_symlinks = follow_symlinks

    def GetPath(self):
      return self.path

    def GetFollowSymlinks(self):
      return self.follow_symlinks

    def __lt__(self, other):
      return self.path < other.path

  def __init__(self, path_datas, src_root_path, dest_root_path, output, dry_run=False, verbose=False):
    self.path_datas = path_datas
    self.src_root_path = src_root_path
    self.dest_root_path = dest_root_path
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.mtime_preserver = MtimePreserver()

  def Sync(self):
    with self.mtime_preserver:
      for path_data in sorted(self.path_datas):
        self._SyncPath(path_data)

  def _SyncPath(self, path_data):
    src_path = os.path.join(self.src_root_path, path_data.GetPath())
    path_info = PathInfo.FromPath(
      path_data.GetPath(), src_path, follow_symlinks=path_data.GetFollowSymlinks())
    dest_path = os.path.join(self.dest_root_path, path_data.GetPath())
    if os.path.lexists(dest_path):
      dest_path_info = PathInfo.FromPath(path_data.GetPath(), dest_path)
    else:
      dest_path_info = None
    itemized = PathInfo.GetItemizedDiff(path_info, dest_path_info)

    if self.verbose:
      itemized.Print(output=self.output)

    if self.dry_run:
      return

    if not dest_path_info:
      self._EnsureParentDirsSynced(path_data.GetPath())

    if path_info.path_type == PathInfo.TYPE_DIR:
      self._SyncDir(path_info, dest_path_info, src_path, dest_path,
                    follow_symlinks=path_data.GetFollowSymlinks())
    else:
      self._SyncFileOrSymlink(path_info, dest_path_info, src_path, dest_path,
                              follow_symlinks=path_data.GetFollowSymlinks())

  def _EnsureParentDirsSynced(self, path):
    parent_dir = os.path.dirname(path)
    parent_dest_dir = os.path.join(self.dest_root_path, parent_dir)
    parent_dirs_to_sync = []
    while parent_dir and not os.path.lexists(parent_dest_dir):
      parent_dirs_to_sync.append((parent_dir, parent_dest_dir))
      parent_dir = os.path.dirname(parent_dir)
      parent_dest_dir = os.path.join(self.dest_root_path, parent_dir)
    if not parent_dirs_to_sync:
      return
    for (parent_dir, parent_dest_dir) in reversed(parent_dirs_to_sync):
      parent_src_dir = os.path.join(self.src_root_path, parent_dir)
      parent_src_path_info = PathInfo.FromPath(parent_dir, parent_src_dir)
      self._SyncDir(parent_src_path_info, None, parent_src_dir, parent_dest_dir)

  def _SyncDir(self, path_info, dest_path_info, src_path, dest_path, follow_symlinks=False):
    if dest_path_info:
      assert dest_path_info.path_type == PathInfo.TYPE_DIR
    else:
      self.mtime_preserver.PreserveParentMtime(dest_path)
      os.mkdir(dest_path)
    self.mtime_preserver.RemovePreservationForPath(dest_path)
    self._SyncXattrs(src_path, dest_path, follow_symlinks=follow_symlinks)
    self._SyncMeta(path_info, src_path, dest_path, follow_symlinks=follow_symlinks)

  def _SyncFileOrSymlink(self, path_info, dest_path_info, src_path, dest_path,
                         follow_symlinks=False):
    assert dest_path_info is None or dest_path_info.path_type == path_info.path_type
    self.mtime_preserver.PreserveParentMtime(dest_path)
    dest_path_result = shutil.copyfile(src_path, dest_path, follow_symlinks=follow_symlinks)
    assert dest_path == dest_path_result
    self._SyncXattrs(src_path, dest_path, follow_symlinks=follow_symlinks)
    self._SyncMeta(path_info, src_path, dest_path, follow_symlinks=follow_symlinks)

  def _SyncMeta(self, path_info, src_path, dest_path, follow_symlinks=False):
    os.utime(dest_path, (path_info.mtime, path_info.mtime), follow_symlinks=follow_symlinks)
    shutil.copymode(src_path, dest_path, follow_symlinks=follow_symlinks)
    os.chown(dest_path, path_info.uid, path_info.gid, follow_symlinks=follow_symlinks)

  def _SyncXattrs(self, src_path, dest_path, follow_symlinks=False):
    src_xattr = Xattr(src_path, follow_symlinks=follow_symlinks)
    dest_xattr = Xattr(dest_path, follow_symlinks=follow_symlinks)
    src_xattr_keys = src_xattr.keys()
    for key in dest_xattr:
      if key not in src_xattr_keys:
        del dest_xattr[key]
    for key in src_xattr_keys:
      try:
        value = src_xattr[key]
      except KeyError as e:
        continue
      dest_xattr[key] = value


class AnalyzePathInfoDupsResult(object):
  def __init__(self):
    self.dup_output_lines = []
    self.found_matching_rename = False


def AnalyzePathInfoDups(
    path_info, dup_path_infos, replacing_previous=True, verbose=False,
    max_dup_find_count=None, max_dup_printout_count=None):
  result = AnalyzePathInfoDupsResult()

  if max_dup_find_count is None:
    max_dup_find_count = MAX_DUP_FIND_COUNT
  if max_dup_printout_count is None:
    max_dup_printout_count = MAX_DUP_PRINTOUT_COUNT

  if replacing_previous:
    verb = 'replacing'
  else:
    verb = 'replaced by'

  if len(dup_path_infos) < max_dup_find_count:
    dup_path_infos = PathInfo.SortedByPathSimilarity(path_info.path, dup_path_infos)
  similar_dup_info = []
  dup_info = []
  for dup_path_info in dup_path_infos:
    dup_itemized = PathInfo.GetItemizedDiff(dup_path_info, path_info, ignore_paths=True)
    if dup_itemized.HasDiffs():
      similar_dup_info.append((dup_itemized, dup_path_info))
    else:
      result.found_matching_rename = True
      dup_info.append((dup_itemized, dup_path_info))
  if len(dup_path_infos) < max_dup_find_count:
    for dup_itemized, dup_path_info in dup_info[:max_dup_printout_count]:
      result.dup_output_lines.append('  %s duplicate: %s' % (verb, dup_itemized))
      if verbose:
        result.dup_output_lines.append('    %s' % dup_path_info.ToString(
          include_path=False, shorten_sha256=True, shorten_xattr_hash=True))
    if len(dup_info) > max_dup_printout_count:
      result.dup_output_lines.append('  and %s %d other duplicates' % (
        verb, len(dup_info) - max_dup_printout_count))
    for dup_itemized, dup_path_info in similar_dup_info[:max_dup_printout_count]:
      result.dup_output_lines.append('  %s similar: %s' % (verb, dup_itemized))
      if verbose:
        result.dup_output_lines.append('    %s' % dup_path_info.ToString(
          include_path=False, shorten_sha256=True, shorten_xattr_hash=True))
    if len(similar_dup_info) > max_dup_printout_count:
      result.dup_output_lines.append('  and %s %d other similar' % (
        verb, len(similar_dup_info) - max_dup_printout_count))
  else:
    if dup_info:
      result.dup_output_lines.append('  %s %d duplicates' % (verb, len(dup_info)))
    if similar_dup_info:
      result.dup_output_lines.append('  %s %d similar' % (verb, len(similar_dup_info)))

  return result


class PasswordsDidNotMatchError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


class CreatePasswordCancelledError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


class EncryptionManager(object):
  INTERACTIVE_CHECKER = InteractiveChecker()

  def __init__(self, output):
    self.image_uuid_password_map = {}
    self.last_password = None
    self.output = output

  def CreatePassword(self, image_path):
    password = GETPASS_FUNCTION(
      prompt='Enter a new password to secure "%s": ' % os.path.basename(image_path))
    self._VerifyPasswordMatchesExistingIfPresent(password)
    password2 = GETPASS_FUNCTION(prompt='Re-enter new password: ')
    if password != password2:
      raise PasswordsDidNotMatchError('Entered passwords did not match')
    return password

  def _VerifyPasswordMatchesExistingIfPresent(self, password):
    if self.last_password is None or not self.image_uuid_password_map:
      return
    if password == self.last_password:
      return
    for image_uuid, other_password in self.image_uuid_password_map.items():
      if password == other_password:
        return
    if not self.INTERACTIVE_CHECKER.Confirm(
        'New password does not match any previous passwords, continue?', self.output):
      raise CreatePasswordCancelledError('*** Cancelled ***')

  def SavePassword(self, password, image_uuid):
    self.image_uuid_password_map[image_uuid] = password
    self.last_password = password

  def ClearPassword(self, image_uuid):
    if image_uuid in self.image_uuid_password_map:
      del self.image_uuid_password_map[image_uuid]

  def GetPassword(self, image_path, image_uuid, try_last_password=False):
    password = self.image_uuid_password_map.get(image_uuid)
    if password is None:
      password = self._LoadPasswordFromKeychain(image_uuid)
      if password is None:
        if try_last_password and self.last_password:
          return self.last_password
        password = GETPASS_FUNCTION(
          prompt='Enter password to access "%s": ' % os.path.basename(image_path))
      self.image_uuid_password_map[image_uuid] = password
      self.last_password = password
    return password

  def _LoadPasswordFromKeychain(self, image_uuid):
    if KEYCHAIN_PASSWORDS_ENABLED:
      cmd = ['security', 'find-generic-password', '-ga', image_uuid]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
      with p.stdout:
        output = p.stdout.read().strip().split('\n')
      p.wait()
      for line in output:
        if line.endswith('The specified item could not be found in the keychain.'):
          return
        m = re.match('^password: "(.*)"$', line)
        if m:
          return m.group(1)
      raise Exception('Unexpected output from %s' % ' '.join([ pipes.quote(a) for a in cmd ]))


class ImageAttacher(object):
  @staticmethod
  def Open(image_path, mount_point=None, readonly=True, browseable=False,
           mount=True, encryption_manager=None, hdiutil_verify=True):
    image_attacher = ImageAttacher(
      image_path, mount_point, readonly=readonly, browseable=browseable,
      mount=mount, encryption_manager=encryption_manager, hdiutil_verify=hdiutil_verify)
    image_attacher._Open()
    return image_attacher

  def __init__(self, image_path, mount_point=None, readonly=True, browseable=False,
               mount=True, encryption_manager=None, hdiutil_verify=True):
    self.image_path = image_path
    self.mount_point = mount_point
    self.random_mount_point = (self.mount_point is None)
    self.readonly = readonly
    self.browseable = browseable
    self.mount = mount
    self.attached = False
    self.image_uuid = None
    self.encrypted = False
    self.encryption_manager = encryption_manager
    self.hdiutil_verify = hdiutil_verify
    self.device = None

  def __enter__(self):
    self._Open()
    return self

  def __exit__(self, exc_type, exc, exc_traceback):
    self.Close()

  def GetMountPoint(self):
    return self.mount_point

  def GetImagePath(self):
    return self.image_path

  def GetDevice(self):
    return self.device

  def Close(self):
    assert self.attached
    assert self.device is not None
    GetDiskImageHelper().DetachImage(self.device)
    if self.mount:
      for i in range(10):
        if not os.path.exists(self.mount_point):
          break
        time.sleep(.1)
      else:
        raise Exception('Failed to unmount %s (%s)' % (self.device, self.mount_point))
    self.attached = False
    self.device = None
    if self.random_mount_point:
      self.mount_point = None

  def _Open(self):
    assert not self.attached
    assert os.path.exists(self.GetImagePath())
    if self.random_mount_point:
      assert self.mount_point is None
    else:
      assert not os.path.exists(self.mount_point)
    (self.encrypted, self.image_uuid) = GetDiskImageHelper().GetImageEncryptionDetails(
      self.GetImagePath())
    try:
      if not self._TryAttach(try_last_password=True):
        if not self.encrypted or not self._TryAttach(try_last_password=False):
          if not self.encrypted or not self._TryAttach(try_last_password=False):
            raise Exception('Failed to attach %s' % self.GetImagePath())
    except:
      if self.random_mount_point:
        self.mount_point = None
      self.device = None
      raise
    if self.mount:
      for i in range(10):
        if os.path.exists(self.mount_point):
          break
        time.sleep(.1)
      else:
        raise Exception('Failed to attach %s' % self.GetImagePath())
    assert self.device is not None
    self.attached = True

  def _TryAttach(self, try_last_password):
    if self.encrypted:
      password = self.encryption_manager.GetPassword(
        self.GetImagePath(), self.image_uuid, try_last_password=try_last_password)
    else:
      password = None

    try:
      attach_result = GetDiskImageHelper().AttachImage(
        self.GetImagePath(), encrypted=self.encrypted, password=password, mount=self.mount,
        random_mount_point=self.random_mount_point, mount_point=self.mount_point,
        readonly=self.readonly, browseable=self.browseable, verify=self.hdiutil_verify)
    except DiskImageHelperAuthenticationError:
      self.encryption_manager.ClearPassword(self.image_uuid)
      return False

    self.device = attach_result.device
    self.mount_point = attach_result.mount_point
    return True


class ItemizedPathChange:
  def __init__(self, path, path_type, new_path=False, replace_path=False, delete_path=False,
               error_path=False, checksum_diff=False, size_diff=False, time_diff=False,
               permission_diff=False, uid_diff=False, gid_diff=False, xattr_diff=False,
               link_dest=None):
    self.path = path
    self.path_type = path_type
    self.new_path = new_path
    self.replace_path = replace_path
    self.delete_path = delete_path
    self.error_path = error_path
    self.checksum_diff = checksum_diff
    self.size_diff = size_diff
    self.time_diff = time_diff
    self.permission_diff = permission_diff
    self.uid_diff = uid_diff
    self.gid_diff = gid_diff
    self.xattr_diff = xattr_diff
    self.link_dest = link_dest

  def HasDiffs(self, ignore_uid_diffs=IGNORE_UID_DIFFS, ignore_gid_diffs=IGNORE_GID_DIFFS):
    if not ignore_uid_diffs and self.uid_diff:
      return True
    if not ignore_gid_diffs and self.gid_diff:
      return True
    return (self.new_path or self.replace_path or self.delete_path or self.error_path
            or self.checksum_diff or self.size_diff or self.time_diff or self.permission_diff
            or self.xattr_diff)

  def GetItemizedShortCode(self):
    if self.path_type == PathInfo.TYPE_DIR:
      return 'd'
    elif self.path_type == PathInfo.TYPE_FILE:
      return 'f'
    elif self.path_type == PathInfo.TYPE_SYMLINK:
      return 'L'
    else:
      raise Exeption('Unexpected file type for %r' % path)

  def Print(self, output, found_matching_rename=False, warn_for_new_path=False):
    print(self.ToString(colorize=output.isatty(), found_matching_rename=found_matching_rename,
                        warn_for_new_path=warn_for_new_path), file=output)

  def __str__(self):
    return self.ToString(colorize=False)

  def ToString(self, colorize=False, found_matching_rename=False, warn_for_new_path=False):
    path_str = EscapePath(self.path)
    if colorize:
      if self.path_type == PathInfo.TYPE_DIR:
        path_str = self._Colorize(path_str, color=TERM_COLOR_CYAN)
      else:
        path_str_parts = os.path.split(path_str)
        if path_str_parts[0]:
          path_str = self._Colorize(path_str_parts[0] + '/', color=TERM_COLOR_CYAN)
        else:
          path_str = ''
        if self.path_type == PathInfo.TYPE_FILE:
          path_str += path_str_parts[1]
        else:
          assert self.path_type == PathInfo.TYPE_SYMLINK
          path_str += self._Colorize(path_str_parts[1], color=TERM_COLOR_PURPLE)
    if self.delete_path:
      color = ((found_matching_rename or self.path_type == PathInfo.TYPE_DIR)
               and TERM_COLOR_PURPLE or TERM_COLOR_RED)
      return '%s %s' % (
        self._Colorize(
          '*%s.delete' % self.GetItemizedShortCode(), color=color, colorize=colorize),
        path_str)
    if self.error_path:
      return '%s %s' % (
        self._Colorize(
          '*%s.error' % self.GetItemizedShortCode(), color=TERM_COLOR_RED, colorize=colorize),
        path_str)
    itemized_str = ['.', self.GetItemizedShortCode(), '.', '.', '.', '.', '.', '.', '.']
    color = TERM_COLOR_RESET
    if self.new_path:
      if warn_for_new_path:
        color = ((found_matching_rename or self.path_type == PathInfo.TYPE_DIR)
                 and TERM_COLOR_PURPLE or TERM_COLOR_RED)
      else:
        color = TERM_COLOR_GREEN
      itemized_str[0] = '>'
      for i in range(2, 9):
        itemized_str[i] = '+'
    else:
      if self.replace_path:
        itemized_str[0] = '>'
      if self.checksum_diff:
        itemized_str[2] = 'c'
        color = TERM_COLOR_PURPLE
      if self.size_diff:
        itemized_str[3] = 's'
        color = TERM_COLOR_PURPLE
      if self.time_diff:
        itemized_str[4] = 't'
        if color == TERM_COLOR_RESET:
          color = TERM_COLOR_YELLOW
      if self.permission_diff:
        itemized_str[5] = 'p'
        if color == TERM_COLOR_RESET:
          color = TERM_COLOR_YELLOW
      if self.uid_diff:
        itemized_str[6] = 'o'
      if self.gid_diff:
        itemized_str[7] = 'g'
      if self.xattr_diff:
        itemized_str[8] = 'x'
        color = TERM_COLOR_PURPLE
    link_dest_str = ''
    if self.link_dest is not None:
      link_dest_str = ' -> %s' % EscapePath(self.link_dest)
    return '%s %s%s' % (
      self._Colorize(''.join(itemized_str), color=color, colorize=colorize),
      path_str, link_dest_str)

  def _Colorize(self, s, color, colorize=True):
    if colorize:
      return '\033[%s%s\033[%s' % (color, s, TERM_COLOR_RESET)
    return s


class PathInfo(object):
  TYPE_DIR = staged_backup_pb2.PathInfoProto.PathType.DIR
  TYPE_FILE = staged_backup_pb2.PathInfoProto.PathType.FILE
  TYPE_SYMLINK = staged_backup_pb2.PathInfoProto.PathType.SYMLINK

  TYPES = [TYPE_DIR, TYPE_FILE, TYPE_SYMLINK]

  STAT_FUNCTION = Stat

  @staticmethod
  def FromProto(pb):
    path = pb.path
    assert pb.path_type in PathInfo.TYPES
    google_drive_remote_file = pb.google_drive_remote_file
    size = None
    if pb.path_type == PathInfo.TYPE_FILE:
      size = int(pb.size)
    uid = int(pb.uid)
    gid = int(pb.gid)
    mtime = int(pb.mtime)
    link_dest = None
    if pb.link_dest:
      link_dest = pb.link_dest
    sha256 = None
    if pb.sha256:
      sha256 = pb.sha256
    xattr_hash = None
    if pb.xattr_hash:
      xattr_hash = pb.xattr_hash
    xattr_keys = []
    if pb.xattr_keys:
      xattr_keys = list(pb.xattr_keys)
    return PathInfo(path, path_type=pb.path_type, mode=pb.mode, uid=uid, gid=gid, mtime=mtime,
                    size=size, link_dest=link_dest, sha256=sha256, xattr_hash=xattr_hash,
                    xattr_keys=xattr_keys, google_drive_remote_file=google_drive_remote_file)

  @staticmethod
  def FromPath(path, full_path, ignored_xattr_keys=None, follow_symlinks=False):
    if ignored_xattr_keys is None:
      ignored_xattr_keys = IGNORED_XATTR_KEYS
    stat_result = PathInfo.STAT_FUNCTION(full_path, follow_symlinks=follow_symlinks)
    size = None
    sha256 = None
    link_dest = None
    xattr_hash = None
    xattr_keys = []
    if stat.S_ISDIR(stat_result.st_mode):
      path_type = PathInfo.TYPE_DIR
      xattr_hash, xattr_keys = ParseXattrData(
        full_path, path_type, ignored_keys=ignored_xattr_keys, follow_symlinks=follow_symlinks)
    elif stat.S_ISREG(stat_result.st_mode):
      path_type = PathInfo.TYPE_FILE
      xattr_hash, xattr_keys = ParseXattrData(
        full_path, path_type, ignored_keys=ignored_xattr_keys, follow_symlinks=follow_symlinks)
      if GOOGLE_DRIVE_FILE_XATTR_KEY in xattr_keys:
        size = GetCorrectedGoogleDriveFileSize(stat_result, full_path)
      if size is None:
        size = stat_result.st_size
    elif stat.S_ISLNK(stat_result.st_mode):
      path_type = PathInfo.TYPE_SYMLINK
      link_dest = os.readlink(full_path)
    else:
      raise Exception('Unexpected file mode for %r: %d' % (full_path, stat_result.st_mode))
    return PathInfo(path, path_type=path_type, mode=stat_result.st_mode, uid=stat_result.st_uid,
                    gid=stat_result.st_gid, mtime=int(stat_result.st_mtime), size=size,
                    link_dest=link_dest, sha256=sha256, xattr_hash=xattr_hash, xattr_keys=xattr_keys,
                    google_drive_remote_file=False,
                    dev_inode=(stat_result.st_dev, stat_result.st_ino))

  @staticmethod
  def GetItemizedDiff(first, second, ignore_paths=False):
    path_info = first or second
    itemized = path_info.GetItemized()
    if second is None:
      itemized.new_path = True
      return itemized
    elif first is None:
      itemized.delete_path = True
      return itemized

    if not ignore_paths:
      assert first.path == second.path
    if stat.S_IFMT(first.mode) != stat.S_IFMT(second.mode):
      itemized.checksum_diff = True
      itemized.replace_path = True

    if stat.S_IMODE(first.mode) != stat.S_IMODE(second.mode):
      itemized.permission_diff = True
    if first.uid != second.uid:
      itemized.uid_diff = True
    if first.gid != second.gid:
      itemized.gid_diff = True
    if first.mtime != second.mtime:
      itemized.time_diff = True
    if first.size != second.size:
      itemized.size_diff = True
    if first.sha256 is not None and second.sha256 is not None and first.sha256 != second.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
    if first.link_dest != second.link_dest:
      itemized.checksum_diff = True
    if (first.xattr_hash != second.xattr_hash or first.xattr_keys != second.xattr_keys
        or first.google_drive_remote_file != second.google_drive_remote_file):
      itemized.xattr_diff = True
    return itemized

  @staticmethod
  def SortedByPathSimilarity(path, path_infos):
    sorting_list = []
    for path_info in path_infos:
      sorting_list.append(
        (-difflib.SequenceMatcher(a=path, b=path_info.path).ratio(), path_info.path, path_info))
    sorting_list.sort()
    return [ path_info for (ratio, path, path_info) in sorting_list ]

  def __init__(self, path, path_type, mode, uid, gid, mtime, size, link_dest, sha256, xattr_hash,
               xattr_keys, google_drive_remote_file, dev_inode=None):
    self.path = path
    self.path_type = path_type
    self.mode = mode
    self.uid = uid
    self.gid = gid
    self.mtime = mtime
    self.size = size
    self.link_dest = link_dest
    self.sha256 = sha256
    self.xattr_hash = xattr_hash
    self.xattr_keys = xattr_keys
    self.google_drive_remote_file = google_drive_remote_file
    self.dev_inode = dev_inode

  def GetItemized(self):
    return ItemizedPathChange(self.path, self.path_type, link_dest=self.link_dest)

  def Clone(self):
    return PathInfo(self.path, path_type=self.path_type, mode=self.mode, uid=self.uid, gid=self.gid,
                    mtime=self.mtime, size=self.size, link_dest=self.link_dest, sha256=self.sha256,
                    xattr_hash=self.xattr_hash, xattr_keys=self.xattr_keys,
                    google_drive_remote_file=self.google_drive_remote_file, dev_inode=self.dev_inode)

  def __str__(self):
    return self.ToString()

  def ToString(self, include_path=True, shorten_sha256=False, shorten_xattr_hash=False):
    if self.path_type == PathInfo.TYPE_FILE:
      out = 'file'
    elif self.path_type == PathInfo.TYPE_DIR:
      out = 'dir'
    elif self.path_type == PathInfo.TYPE_SYMLINK:
      out = 'symlink'
    else:
      raise Exeption('Unexpected path type')
    if include_path:
      out += ' path=%s,' % EscapePath(self.path)
    out += ' mode=%d' % self.mode
    if not OMIT_UID_AND_GID_IN_PATH_INFO_TO_STRING:
      out += ', uid=%d, gid=%d' % (self.uid, self.gid)
    out += ', mtime=%d (%s)' % (self.mtime, UnixTimeToSecondsString(self.mtime))
    if self.size is not None:
      out += ', size=%r' % self.size
    if self.link_dest is not None:
      out += ', link-dest=%r' % self.link_dest
    if self.sha256 is not None:
      if shorten_sha256:
        out += ', sha256=%r' % binascii.b2a_hex(self.sha256)[:6].decode('ascii')
      else:
        out += ', sha256=%r' % binascii.b2a_hex(self.sha256).decode('ascii')
    if self.xattr_hash is not None:
      if shorten_xattr_hash:
        out += ', xattr-hash=%r' % binascii.b2a_hex(self.xattr_hash)[:6].decode('ascii')
      else:
        out += ', xattr-hash=%r' % binascii.b2a_hex(self.xattr_hash).decode('ascii')
    if self.xattr_keys:
      out += ', xattr-keys=%r' % self.xattr_keys
    if self.google_drive_remote_file:
      out += ', google_drive_remote_file'
    if self.dev_inode is not None:
      out += ', dev-inode=%r' % (self.dev_inode,)
    return out

  def FindBestDup(self, sha256_to_pathinfos):
    if self.sha256 is None:
      return
    dup_path_infos = PathInfo.SortedByPathSimilarity(
      self.path, sha256_to_pathinfos.get(self.sha256, []))
    for dup_path_info in dup_path_infos:
      itemized = PathInfo.GetItemizedDiff(dup_path_info, self, ignore_paths=True)
      if not itemized.HasDiffs():
        return dup_path_info

  def HasFileContents(self):
    return self.path_type == PathInfo.TYPE_FILE

  def ToProto(self, pb=None):
    try:
      if pb is None:
        pb = staged_backup_pb2.PathInfoProto()
      pb.path = self.path
      pb.path_type = self.path_type
      pb.mode = self.mode
      pb.uid = self.uid
      pb.gid = self.gid
      pb.mtime = self.mtime
      if self.size is not None:
        pb.size = self.size
      if self.link_dest is not None:
        pb.link_dest = self.link_dest
      if self.sha256 is not None:
        pb.sha256 = self.sha256
      if self.xattr_hash is not None:
        pb.xattr_hash = self.xattr_hash
      pb.xattr_keys[:] = self.xattr_keys
      pb.google_drive_remote_file = self.google_drive_remote_file
    except ValueError:
      print('*** Error in ToProto for path %r' % self.path)
      raise
    return pb


class PathEnumerator(object):
  class PathData(object):
    def __init__(self, path, path_stat=None, follow_symlinks=False):
      self.path = path
      self.path_stat = path_stat
      self.follow_symlinks = follow_symlinks

    def GetPath(self):
      return self.path

    def GetFollowSymlinks(self):
      return self.follow_symlinks

  def __init__(self, root_dir, output, filters=[], verbose=False, use_rsync=False):
    self.root_dir = os.path.normpath(root_dir)
    self.output = output
    self.filters = filters
    self.verbose = verbose
    self.use_rsync = use_rsync

  def Scan(self):
    if self.use_rsync:
      return self._ScanWithRsync()
    else:
      return sorted(self._ScanInternal(self.root_dir, '.', self.filters), key=lambda p: p.GetPath())

  def _ScanWithRsync(self):
    for path in sorted(RsyncList(self.root_dir, self.output, filters=self.filters,
                                 verbose=self.verbose)):
      yield PathEnumerator.PathData(path)

  def _ScanInternal(self, root_dir, path, filters, path_stat=None, follow_symlinks=False):
    if path != '.':
      abs_path = os.path.join(root_dir, path)
    else:
      abs_path = root_dir
      path_stat = os.lstat(abs_path)

    if (stat.S_ISSOCK(path_stat.st_mode) or stat.S_ISCHR(path_stat.st_mode)
        or stat.S_ISBLK(path_stat.st_mode) or stat.S_ISFIFO(path_stat.st_mode)):
      return

    yield PathEnumerator.PathData(path, path_stat, follow_symlinks=follow_symlinks)

    if stat.S_ISDIR(path_stat.st_mode) and not stat.S_ISLNK(path_stat.st_mode):
      child_entries = list(os.scandir(abs_path))
      current_filters = self._UpdateFilters(root_dir, path, child_entries, filters)
      for child_entry in sorted(child_entries, key=lambda p: p.name):
        if path != '.':
          child_path = os.path.join(path, child_entry.name)
        else:
          child_path = child_entry.name
        matches, follow_symlinks = self._FiltersMatch(child_path, child_entry, current_filters)
        if not matches:
          continue
        for result in self._ScanInternal(
            root_dir, child_path, current_filters,
            path_stat=Stat(child_entry.path, follow_symlinks=follow_symlinks), follow_symlinks=follow_symlinks):
          yield result

  def _FiltersMatch(self, path, path_entry, filters):
    path_stat = os.lstat(path_entry.path)
    follow_symlinks = False
    for a_filter in filters:
      if isinstance(a_filter, FilterRuleInclude):
        if a_filter.MatchesPath(path, path_stat):
          return True, follow_symlinks
      elif isinstance(a_filter, FilterRuleExclude):
        if a_filter.MatchesPath(path, path_stat):
          return False, follow_symlinks
      elif isinstance(a_filter, FilterRuleFollowSymlink):
        if stat.S_ISLNK(path_stat.st_mode):
          try:
            path_stat_follow = os.stat(path_entry.path)
          except FileNotFoundError:
            continue
          if a_filter.MatchesPath(path, path_stat_follow):
            follow_symlinks=True
            path_stat = path_stat_follow
    return True, follow_symlinks

  def _UpdateFilters(self, root_dir, path, child_entries, filters):
    new_filters = []
    for a_filter in filters:
      if isinstance(a_filter, FilterRuleMerge):
        merge_file_path = os.path.join(root_dir, path, a_filter.GetPath())
        new_filters.extend(self._ParseFilterMergeFile(merge_file_path, path))
      elif isinstance(a_filter, FilterRuleDirMerge):
        for child_entry in child_entries:
          if a_filter.filename == child_entry.name:
            new_filters.extend(self._ParseFilterMergeFile(child_entry.path, path))
        new_filters.append(a_filter)
      else:
        new_filters.append(a_filter)
    return new_filters

  def _ParseFilterMergeFile(self, merge_file_path, path):
    filters = []
    with open(merge_file_path, 'r') as f:
      for line in f:
        if line.startswith('#'):
          continue
        elif line.startswith('include '):
          matcher = line[len('include '):].strip()
          if matcher.startswith('/') and path != '.':
            matcher = '/%s%s' % (path, matcher)
          filters.append(FilterRuleInclude(matcher))
        elif line.startswith('exclude '):
          matcher = line[len('exclude '):].strip()
          if matcher.startswith('/') and path != '.':
            matcher = '/%s%s' % (path, matcher)
          filters.append(FilterRuleExclude(matcher))
        elif line.startswith('follow-symlinks '):
          matcher = line[len('follow-symlinks '):].strip()
          if matcher.startswith('/') and path != '.':
            matcher = '/%s%s' % (path, matcher)
          filters.append(FilterRuleFollowSymlink(matcher))
        elif line.rstrip():
          raise Exception('Unknown filter rule %r' % line.rstrip())
    return filters


class ManifestError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)


class Manifest(object):
  @staticmethod
  def Load(path):
    manifest = Manifest(path)
    manifest.Read()
    return manifest

  def __init__(self, path=None):
    self.path = path
    self.path_map = {}

  def GetPath(self):
    return self.path

  def SetPath(self, path):
    self.path = path

  def Read(self):
    if not os.path.isfile(self.path):
      raise ManifestError('Manifest file %s should exist' % self.path)

    with open(self.path, 'rb') as f:
      pb = staged_backup_pb2.ManifestProto()
      pb.ParseFromString(f.read())

      for path_info_pb in pb.path_infos:
        path_info = PathInfo.FromProto(path_info_pb)
        self.path_map[path_info.path] = path_info

  def Write(self):
    pb = staged_backup_pb2.ManifestProto()
    for path in sorted(self.path_map.keys()):
      path_info = self.path_map[path]
      path_info.ToProto(pb.path_infos.add())

    pb_data = pb.SerializeToString()

    tmp_path = self.path + '.tmp'
    with open(tmp_path, 'wb') as f:
      f.write(pb_data)
    os.rename(tmp_path, self.path)

  def GetPaths(self):
    return sorted(self.path_map.keys())

  def GetPathInfo(self, path):
    return self.path_map.get(path)

  def HasPath(self, path):
    return path in self.path_map

  def GetPathMap(self):
    return self.path_map

  def AddPathInfo(self, path_info, allow_replace=False):
    if not allow_replace:
      if path_info.path in self.path_map:
        raise Exception('Cannot add path info (%s): already in map (%s)'
                        % (path_info, self.path_map[path_info.path]))
    self.path_map[path_info.path] = path_info

  def RemovePathInfo(self, path):
    path_info = self.path_map[path]
    del self.path_map[path]
    return path_info

  def GetPathCount(self):
    return len(self.path_map)

  def Clone(self):
    clone = Manifest(self.path)
    for path, path_info in list(self.path_map.items()):
      clone.path_map[path] = path_info.Clone()
    return clone

  def Dump(self, output, shorten_sha256=True, shorten_xattr_hash=True):
    for path in sorted(self.path_map.keys()):
      print(self.path_map[path].ToString(
        shorten_sha256=shorten_sha256, shorten_xattr_hash=shorten_xattr_hash), file=output)

  def GetItemized(self):
    itemizeds = []
    for path in self.GetPaths():
      itemized = self.path_map[path].GetItemized()
      itemized.new_path = True
      itemizeds.append(itemized)
    return itemizeds

  def GetDiffItemized(self, other_manifest, include_matching=False, ignore_uid_diffs=IGNORE_UID_DIFFS,
                      ignore_gid_diffs=IGNORE_GID_DIFFS):
    itemized_results = []
    all_paths = set(self.path_map.keys())
    all_paths.update(list(other_manifest.path_map.keys()))
    for path in sorted(all_paths):
      other_path_info = other_manifest.path_map.get(path)
      path_info = self.path_map.get(path)

      itemized = PathInfo.GetItemizedDiff(path_info, other_path_info)
      has_diffs = itemized.HasDiffs(ignore_uid_diffs=ignore_uid_diffs, ignore_gid_diffs=ignore_gid_diffs)
      if has_diffs or include_matching:
        itemized_results.append(itemized)
    return itemized_results

  def CreateSha256ToPathInfosMap(self, min_file_size=1):
    sha256_to_pathinfos = {}
    for path in self.GetPaths():
      path_info = self.GetPathInfo(path)
      if (path_info.HasFileContents() and path_info.size >= min_file_size):
        assert path_info.sha256 is not None
        if path_info.sha256 not in sha256_to_pathinfos:
          sha256_to_pathinfos[path_info.sha256] = []
        sha256_to_pathinfos[path_info.sha256].append(path_info)
    return sha256_to_pathinfos

  def CreateSizeToPathInfosMap(self, min_file_size=1):
    size_to_pathinfos = {}
    for path in self.GetPaths():
      path_info = self.GetPathInfo(path)
      if path_info.HasFileContents():
        assert path_info.size is not None
        if path_info.size >= min_file_size:
          if path_info.size not in size_to_pathinfos:
            size_to_pathinfos[path_info.size] = []
          size_to_pathinfos[path_info.size].append(path_info)
    return size_to_pathinfos


def ReadManifestFromImageOrPath(path, encryption_manager=None, dry_run=False):
  if path.endswith('.sparseimage') or path.endswith('.sparsebundle') or path.endswith('.dmg'):
    with ImageAttacher(path, encryption_manager=encryption_manager, readonly=True) as attacher:
      return Manifest.Load(os.path.join(attacher.GetMountPoint(), METADATA_DIR_NAME, MANIFEST_FILENAME))
  elif path.endswith('.pbdata') or path.endswith('.pbdata.bak') or path.endswith('.pbdata.new'):
    return Manifest.Load(path)
  else:
    raise Exception('Expected a .sparseimage, .sparsebundle, .dmg or .pbdata file but got %r', path)


class ImageCompactor(object):
  def __init__(self, image_path, output, defragment=False, defragment_iterations=DEFAULT_DEFRAGMENT_ITERATIONS,
               dry_run=False, verbose=False, encryption_manager=None):
    self.image_path = image_path
    self.defragment = defragment
    self.defragment_iterations = defragment_iterations
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.encryption_manager = encryption_manager

  def Compact(self):
    starting_size = GetPathTreeSize(self.image_path)
    CompactAndDefragmentImage(
      self.image_path, output=self.output, defragment=self.defragment,
      defragment_iterations=self.defragment_iterations, dry_run=self.dry_run,
      encryption_manager=self.encryption_manager)
    ending_size = GetPathTreeSize(self.image_path)
    print("Image size %s -> %s" % (
      FileSizeToString(starting_size), FileSizeToString(ending_size)), file=self.output)
    return True


class DiffDumperStats(object):
  def __init__(self):
    self.total_paths = 0
    self.total_matched_paths = 0
    self.total_matched_size = 0
    self.total_mismatched_paths = 0
    self.total_mismatched_size = 0


class ManifestDiffDumper(object):
  def __init__(self, first_manifest, second_manifest, output, ignore_matching_renames=False,
               ignore_uid_diffs=IGNORE_UID_DIFFS, ignore_gid_diffs=IGNORE_GID_DIFFS, verbose=False):
    self.first_manifest = first_manifest
    self.second_manifest = second_manifest
    self.output = output
    self.ignore_matching_renames = ignore_matching_renames
    self.ignore_uid_diffs = ignore_uid_diffs
    self.ignore_gid_diffs = ignore_gid_diffs
    self.verbose = verbose
    self.stats = DiffDumperStats()

  def DumpDiff(self):
    sha256_to_first_pathinfos = self.first_manifest.CreateSha256ToPathInfosMap()
    sha256_to_second_pathinfos = self.second_manifest.CreateSha256ToPathInfosMap()

    all_paths = set(self.second_manifest.GetPathMap().keys())
    all_paths.update(list(self.first_manifest.GetPathMap().keys()))
    for path in sorted(all_paths):
      self.stats.total_paths += 1

      first_path_info = self.first_manifest.GetPathInfo(path)
      second_path_info = self.second_manifest.GetPathInfo(path)

      itemized = PathInfo.GetItemizedDiff(second_path_info, first_path_info)
      has_diffs = itemized.HasDiffs(ignore_uid_diffs=self.ignore_uid_diffs, ignore_gid_diffs=self.ignore_gid_diffs)

      if has_diffs:
        self.stats.total_mismatched_paths += 1
        self.stats.total_mismatched_size += max(
          first_path_info and first_path_info.size or 0, second_path_info and second_path_info.size or 0)

      else:
        self.stats.total_matched_paths += 1
        if first_path_info.size:
          self.stats.total_matched_size += first_path_info.size

      if has_diffs or self.verbose:
        dup_analyze_result = None
        if second_path_info is None:
          if first_path_info.HasFileContents():
            dup_analyze_result = AnalyzePathInfoDups(
              first_path_info, sha256_to_second_pathinfos.get(first_path_info.sha256, []),
              replacing_previous=False, verbose=self.verbose)
        elif second_path_info.HasFileContents():
          dup_analyze_result = AnalyzePathInfoDups(
            second_path_info, sha256_to_first_pathinfos.get(second_path_info.sha256, []),
            replacing_previous=True, verbose=self.verbose)
        found_matching_rename = dup_analyze_result and dup_analyze_result.found_matching_rename

        if not self.ignore_matching_renames or not found_matching_rename or self.verbose:
          itemized.Print(output=self.output, found_matching_rename=found_matching_rename)
          if dup_analyze_result is not None:
            for line in dup_analyze_result.dup_output_lines:
              print(line, file=self.output)

    return True

  def GetStats(self):
    return self.stats


class ManifestVerifierStats(object):
  def __init__(self):
    self.total_paths = 0
    self.total_size = 0
    self.total_mismatched_paths = 0
    self.total_mismatched_size = 0
    self.total_checksummed_paths = 0
    self.total_checksummed_size = 0
    self.total_checksum_skipped_paths = 0
    self.total_checksum_skipped_size = 0
    self.total_skipped_paths = 0


class ManifestVerifier(object):
  def __init__(self, manifest, src_root, output, filters=[], manifest_on_top=True,
               checksum_path_matcher=PathMatcherNone(), escape_key_detector=None, path_matcher=PathMatcherAll(),
               verbose=False):
    self.manifest = manifest
    self.src_root = src_root
    self.output = output
    self.checksum_path_matcher = checksum_path_matcher
    self.escape_key_detector = escape_key_detector
    self.path_matcher = path_matcher
    self.verbose = verbose
    self.manifest_on_top = manifest_on_top
    self.path_enumerator = PathEnumerator(src_root, output, filters=filters, verbose=verbose)
    self.has_diffs = False
    self.stats = ManifestVerifierStats()

  def Verify(self):
    missing_paths = []
    for path in self.manifest.GetPaths():
      if self.path_matcher.Matches(path):
        missing_paths.append(path)

    for enumerated_path in self.path_enumerator.Scan():
      path = enumerated_path.GetPath()
      if not self.path_matcher.Matches(path):
        self.stats.total_skipped_paths += 1
        continue

      if self.escape_key_detector is not None and self.escape_key_detector.WasEscapePressed():
        print('*** Cancelled at path %s' % EscapePath(path), file=self.output)
        return False

      self._HandleMissingPaths(missing_paths, next_present_path=path)

      full_path = os.path.join(self.src_root, path)
      src_path_info = PathInfo.FromPath(path, full_path)
      self.stats.total_paths += 1
      if src_path_info.size is not None:
        self.stats.total_size += src_path_info.size

      manifest_path_info = self.manifest.GetPathInfo(path)
      if manifest_path_info is None:
        self._ExtraPath(src_path_info)
      else:
        self._CheckCommonPath(path, src_path_info, manifest_path_info)

    self._HandleMissingPaths(missing_paths, next_present_path=None)

    return not self.has_diffs

  def GetStats(self):
    return self.stats

  def _ExtraPath(self, src_path_info):
    self.has_diffs = True

    itemized = src_path_info.GetItemized()
    if self.manifest_on_top:
      itemized.delete_path = True
    else:
      itemized.new_path = True
    itemized.Print(output=self.output)
    self.stats.total_mismatched_paths += 1
    if src_path_info.size:
      self.stats.total_mismatched_size += src_path_info.size

  def _CheckCommonPath(self, path, src_path_info, manifest_path_info):
    full_path = os.path.join(self.src_root, src_path_info.path)

    itemized = PathInfo.GetItemizedDiff(src_path_info, manifest_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_path_matcher.Matches(path):
      if src_path_info.HasFileContents():
        self.stats.total_checksum_skipped_paths += 1
        self.stats.total_checksum_skipped_size += src_path_info.size
      if self.verbose:
        itemized.Print(output=self.output)
      return
    if src_path_info.HasFileContents():
      src_path_info.sha256 = Sha256WithProgress(full_path, src_path_info, output=self.output)
      self.stats.total_checksummed_paths += 1
      self.stats.total_checksummed_size += src_path_info.size
    if src_path_info.sha256 != manifest_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        itemized.Print(output=self.output)
      return

    itemized.Print(output=self.output)
    self.stats.total_mismatched_paths += 1
    if src_path_info.size:
      self.stats.total_mismatched_size += src_path_info.size
    if self.verbose:
      if src_path_info is not None:
        print('<', src_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
      if manifest_path_info is not None:
        print('>', manifest_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True), file=self.output)
    self.has_diffs = True

  def _HandleMissingPaths(self, missing_paths, next_present_path=None):
    while missing_paths:
      next_missing_path = missing_paths[0]
      if next_present_path is not None and next_missing_path > next_present_path:
        break
      if next_present_path != next_missing_path:
        self.has_diffs = True
        path_info = self.manifest.GetPathInfo(next_missing_path)
        itemized = path_info.GetItemized()
        if self.manifest_on_top:
          itemized.new_path = True
        else:
          itemized.delete_path = True
        itemized.Print(output=self.output)
        self.stats.total_mismatched_paths += 1
        if path_info.size:
          self.stats.total_mismatched_size += path_info.size
      del missing_paths[0]


def DoCompactImage(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--image-path', required=True)
  parser.add_argument('--no-defragment', dest='defragment', action='store_false')
  parser.add_argument('--defragment-iterations', default=str(DEFAULT_DEFRAGMENT_ITERATIONS), type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  image_compactor = ImageCompactor(
    cmd_args.image_path, defragment=cmd_args.defragment,
    defragment_iterations=cmd_args.defragment_iterations, output=output, dry_run=args.dry_run,
    verbose=args.verbose, encryption_manager=EncryptionManager(output=output))
  return image_compactor.Compact()


def DoDumpManifest(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('path', metavar='manifest_or_image_path')
  parser.add_argument('--no-shorten-sha256', dest='shorten_sha256', action='store_false')
  parser.add_argument('--no-shorten-xattr-hash', dest='shorten_xattr_hash', action='store_false')
  cmd_args = parser.parse_args(args.cmd_args)

  manifest = ReadManifestFromImageOrPath(
    cmd_args.path, encryption_manager=EncryptionManager(output=output), dry_run=args.dry_run)
  manifest.Dump(output, shorten_sha256=cmd_args.shorten_sha256,
                shorten_xattr_hash=cmd_args.shorten_xattr_hash)
  return True


def DoDiffManifests(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('first_path', metavar='first_manifest_or_image_path')
  parser.add_argument('second_path', metavar='second_manifest_or_image_path')
  parser.add_argument('--ignore-matching-renames', action='store_true')
  if IGNORE_UID_DIFFS:
    parser.add_argument('--no-ignore-uid-diffs', dest='ignore_uid_diffs', action='store_false')
  else:
    parser.add_argument('--ignore-uid-diffs', dest='ignore_uid_diffs', action='store_true')
  if IGNORE_GID_DIFFS:
    parser.add_argument('--no-ignore-gid-diffs', dest='ignore_gid_diffs', action='store_false')
  else:
    parser.add_argument('--ignore-gid-diffs', dest='ignore_gid_diffs', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  encryption_manager = EncryptionManager(output=output)

  first_manifest = ReadManifestFromImageOrPath(
    cmd_args.first_path, encryption_manager=encryption_manager, dry_run=args.dry_run)
  second_manifest = ReadManifestFromImageOrPath(
    cmd_args.second_path, encryption_manager=encryption_manager, dry_run=args.dry_run)

  manifest_diff_dumper = ManifestDiffDumper(
    first_manifest=first_manifest, second_manifest=second_manifest, output=output, verbose=args.verbose,
    ignore_matching_renames=cmd_args.ignore_matching_renames,
    ignore_uid_diffs=cmd_args.ignore_uid_diffs, ignore_gid_diffs=cmd_args.ignore_gid_diffs)
  return manifest_diff_dumper.DumpDiff()


def DoVerifyManifest(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--src-root', required=True)
  parser.add_argument('path', metavar='manifest_or_image_path')
  parser.add_argument('--checksum-all', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  manifest = ReadManifestFromImageOrPath(
    cmd_args.path, encryption_manager=EncryptionManager(output=output), dry_run=args.dry_run)

  manifest_verifier = ManifestVerifier(
    manifest, cmd_args.src_root, output,
    checksum_path_matcher=PathMatcherAllOrNone(cmd_args.checksum_all), verbose=args.verbose)
  return manifest_verifier.Verify()


def DoCommand(args, output):
  if args.command == COMMAND_COMPACT_IMAGE:
    return DoCompactImage(args, output=output)
  elif args.command == COMMAND_DUMP_MANIFEST:
    return DoDumpManifest(args, output=output)
  elif args.command == COMMAND_DIFF_MANIFESTS:
    return DoDiffManifests(args, output=output)
  elif args.command == COMMAND_VERIFY_MANIFEST:
    return DoVerifyManifest(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
