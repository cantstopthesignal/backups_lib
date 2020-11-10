import argparse
import binascii
import contextlib
import difflib
import fcntl
import getpass
import hashlib
import json
import os
import pipes
import plistlib
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import termios
import threading
import time
import traceback
import tty
import xattr

import staged_backup_pb2


COMMAND_CREATE = 'create'
COMMAND_APPLY = 'apply'
COMMAND_STRIP = 'strip'
COMMAND_COMPACT = 'compact'
COMMAND_DUMP_MANIFEST = 'dump-manifest'
COMMAND_DIFF_MANIFESTS = 'diff-manifests'
COMMAND_VERIFY_MANIFEST = 'verify-manifest'

COMMANDS = [
  COMMAND_CREATE,
  COMMAND_APPLY,
  COMMAND_STRIP,
  COMMAND_COMPACT,
  COMMAND_DUMP_MANIFEST,
  COMMAND_DIFF_MANIFESTS,
  COMMAND_VERIFY_MANIFEST,
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
  return s.encode('string-escape')


def EscapePath(path):
  return EscapeString(path)


def DeEscapeString(s):
  return s.decode('string-escape')


def DeEscapePath(path):
  return DeEscapeString(path)


class RsyncInclude(object):
  def __init__(self, path):
    self.path = path

  def GetArg(self):
    return '--include=%s' % self.path


class RsyncExclude(object):
  def __init__(self, path):
    self.path = path

  def GetArg(self):
    return '--exclude=%s' % self.path


class RsyncFilterDirMerge(object):
  def __init__(self, filename):
    self.filename = filename

  def GetArg(self):
    return '--filter=dir-merge /%s' % self.filename


class RsyncFilterMerge(object):
  def __init__(self, path):
    self.path = path

  def GetArg(self):
    return '--filter=merge %s' % self.path


RSYNC_DIR_MERGE_FILENAME = '.staged_backup_filter'

RSYNC_FILTERS = [RsyncFilterDirMerge(RSYNC_DIR_MERGE_FILENAME)]

IGNORED_XATTR_KEYS = ['com.apple.avkit.thumbnailCacheEncryptionKey',
                      'com.apple.avkit.thumbnailCacheIdentifier',
                      'com.apple.diskimages.recentcksum',
                      'com.apple.lastuseddate#PS',
                      'com.apple.quarantine']


@contextlib.contextmanager
def Chdir(new_cwd):
  old_cwd = os.getcwd()
  try:
    os.chdir(new_cwd)
    yield
  finally:
    os.chdir(old_cwd)


class MtimePreserver(object):
  def __init__(self):
    self.preserved_path_mtimes = {}

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc, exc_traceback):
    for path, mtime in self.preserved_path_mtimes.items():
      os.utime(path, (mtime, mtime))

  def PreserveMtime(self, path):
    if path not in self.preserved_path_mtimes:
      self.preserved_path_mtimes[path] = os.lstat(path).st_mtime

  def PreserveParentMtime(self, path):
    self.PreserveMtime(os.path.dirname(path))


@contextlib.contextmanager
def PreserveParentMtime(path):
  parent_dir = os.path.dirname(path)
  parent_stat = os.lstat(parent_dir)
  yield
  os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime))


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
      os.utime(parent_dir, (parent_stat.st_mtime, parent_stat.st_mtime))
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
  with open(path, 'rb') as f:
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
  BLOCKSIZE = 65536
  hasher = hashlib.sha256()
  read_bytes = 0
  read_bytes_str_max_len = 0
  print_progress = output.isatty() and path_info.size > MIN_SIZE_FOR_SHA256_PROGRESS
  last_progress_time = 0
  with open(full_path, 'rb') as f:
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
          message += '\xe2\x80\xa6' + path_info.path[len(path_info.path)-max_path_len+1:]
        else:
          message += path_info.path
        output.write('\033[K%s\r' % message)
  if print_progress:
    output.write("\033[K")
  return hasher.digest()


def GetXattrHash(path, ignored_keys=[]):
  xattr_data = xattr.xattr(path)
  xattr_list = []
  for key in sorted(xattr_data.keys()):
    if type(key) == unicode:
      key = key.encode('utf8')
    if key in ignored_keys:
      continue
    value = xattr_data[key]
    if type(value) == unicode:
      value = value.encode('utf8')
    xattr_list.append((key, value))
  if xattr_list:
    hasher = hashlib.sha256()
    hasher.update(repr(xattr_list))
    return hasher.digest()


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
  output = subprocess.check_output(['df', '-k', path])
  (header_row, data_row) = output.strip().split('\n')
  assert header_row.split()[:4] == [
    'Filesystem', '1024-blocks', 'Used', 'Available']
  data_row = data_row.split()
  available_kbs = int(data_row[3])
  return available_kbs * 1024


def CreateDiskImage(image_path, volume_name=None, size='1T', filesystem='APFS',
                    image_type=None, encrypt=False, encryption_manager=None, dry_run=False):
  password = None
  if encrypt:
    password = encryption_manager.CreatePassword(image_path)

  assert not os.path.exists(image_path)
  cmd = ['hdiutil', 'create', '-size', size, '-fs', filesystem, '-quiet',
         '-atomic']
  if image_type is not None:
    cmd.extend(['-type', image_type])
  if volume_name is not None:
    cmd.extend(['-volname', volume_name])
  if password is not None:
    cmd.extend(['-encryption', 'AES-128', '-stdinpass'])
  cmd.append(image_path)
  if not dry_run:
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    if password is not None:
      p.stdin.write(password)
    p.stdin.close()
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))

  if not dry_run and password is not None:
    _, image_uuid = GetImageEncryptionDetails(image_path)
    assert image_uuid
    encryption_manager.SavePassword(password, image_uuid)


def CompactImage(image_path, output, encryption_manager=None, encrypted=None, image_uuid=None,
                 dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetImageEncryptionDetails(image_path)

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
                         stderr=subprocess.STDOUT)
    if encrypted:
      p.stdin.write(password)
    p.stdin.close()
    output.write(p.stdout.read())
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))


def ResizeImage(image_path, block_count, output, encryption_manager=None, encrypted=None,
                image_uuid=None, dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetImageEncryptionDetails(image_path)

  cmd = ['hdiutil', 'resize', '-size', '%db' % block_count, image_path]
  if encrypted:
    cmd.append('-stdinpass')

  if not dry_run:
    if encrypted:
      password = encryption_manager.GetPassword(
        image_path, image_uuid, try_last_password=False)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    if encrypted:
      p.stdin.write(password)
    p.stdin.close()
    output.write(p.stdout.read())
    if p.wait():
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))


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
    (encrypted, image_uuid) = GetImageEncryptionDetails(image_path)

  if not os.path.normpath(image_path).endswith('.sparsebundle'):
    raise Exception('Expected %s to be a sparsebundle image' % image_path)

  plist_data = plistlib.readPlist(os.path.join(image_path, 'Info.plist'))
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
                       stderr=subprocess.STDOUT)
  if encrypted:
    p.stdin.write(password)
  p.stdin.close()
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
      start_band = (partition.start * block_size) / band_size
      end_band = ((partition.start + partition.length) * block_size) / band_size
      bands_to_delete = set()
      for band_id in range(start_band + 1, end_band):
        if band_id in bands_with_files:
          bands_to_delete.add(band_id)
      if bands_to_delete:
        print >>output, 'Deleting %d bands between (%d,%d) for empty partition %s...' % (
          len(bands_to_delete), start_band, end_band, partition)
        for band_id in bands_to_delete:
          band_path = os.path.join(image_path, 'bands', hex(band_id)[2:])
          if not dry_run:
            os.unlink(band_path)


def CompactImageWithResize(image_path, output, encryption_manager=None, encrypted=None,
                           image_uuid=None, dry_run=False):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetImageEncryptionDetails(image_path)

  (current_block_count, min_block_count) = GetDiskImageLimits(
    image_path, encryption_manager=encryption_manager, encrypted=encrypted, image_uuid=image_uuid)

  print >>output, 'Resizing image to minimum size: %d -> %d blocks...' % (
    current_block_count, min_block_count)
  ResizeImage(image_path, block_count=min_block_count, output=output,
              encryption_manager=encryption_manager, encrypted=encrypted,
              image_uuid=image_uuid, dry_run=dry_run)

  if os.path.normpath(image_path).endswith('.sparsebundle'):
    CleanFreeSparsebundleBands(
      image_path, output=output, encryption_manager=encryption_manager, encrypted=encrypted,
      image_uuid=image_uuid, dry_run=dry_run)

  print >>output, 'Restoring image size to %d blocks...' % current_block_count
  ResizeImage(image_path, block_count=current_block_count, output=output,
              encryption_manager=encryption_manager, encrypted=encrypted,
              image_uuid=image_uuid, dry_run=dry_run)

  CompactImage(image_path, output=output, encryption_manager=encryption_manager, encrypted=encrypted,
               image_uuid=image_uuid, dry_run=dry_run)


def GetApfsDeviceFromAttachedImageDevice(image_device, output):
  assert image_device.startswith('/dev/')
  diskutil_output = subprocess.check_output(['diskutil', 'list', image_device])
  apfs_identifier = None
  for line in diskutil_output.split('\n'):
    pieces = line.strip().split()
    if pieces[1:3] == ['Apple_APFS', 'Container']:
      if apfs_identifier is not None:
        raise Exception('Multiple apfs containers found in diskutil output: %s' % diskutil_output)
      apfs_identifier = pieces[-1]
  if apfs_identifier is None:
    print >>output, '*** Warning: no apfs container found to defragment:'
    for line in diskutil_output.split('\n'):
      print >>output, line
    return

  apfs_device = os.path.join('/dev', apfs_identifier)
  assert apfs_device.startswith(image_device)

  return apfs_device


def GetApfsDeviceLimits(apfs_device):
  current_bytes = None
  min_bytes = None
  diskutil_output = subprocess.check_output(['diskutil', 'apfs', 'resizeContainer', apfs_device , 'limits'])
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
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in p.stdout:
    print >>output, line.rstrip()
  if p.wait():
    raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))


def GetDiskImageLimits(image_path, encryption_manager, encrypted=None, image_uuid=None):
  if encrypted is None or image_uuid is None:
    (encrypted, image_uuid) = GetImageEncryptionDetails(image_path)

  cmd = ['hdiutil', 'resize', '-limits', image_path]
  if encrypted:
    cmd.append('-stdinpass')

  if encrypted:
    password = encryption_manager.GetPassword(
      image_path, image_uuid, try_last_password=False)
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
  if encrypted:
    p.stdin.write(password)
  p.stdin.close()
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


def CompactAndDefragmentImage(image_path, output, defragment=False, defragment_iterations=1,
                              encryption_manager=None, dry_run=False):
  (encrypted, image_uuid) = GetImageEncryptionDetails(image_path)

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

    print >>output, 'Defragmenting %s; apfs min size %s, current size %s...' % (
      image_path, FileSizeToString(min_bytes), FileSizeToString(old_apfs_container_size))
    if not dry_run:
      for i in range(defragment_iterations):
        if i:
          _, new_min_bytes = GetApfsDeviceLimits(apfs_device)
          if new_min_bytes >= min_bytes * 0.95:
            print >>output, 'Iteration %d, new apfs min size %s has low savings' % (
              i+1, FileSizeToString(new_min_bytes))
            break
          print >>output, 'Iteration %d, new apfs min size %s...' % (
            i+1, FileSizeToString(new_min_bytes))
          min_bytes = new_min_bytes
        ResizeApfsContainer(apfs_device, min_bytes, output=output)

  CompactImageWithResize(image_path, output=output, encryption_manager=encryption_manager,
                         encrypted=encrypted, image_uuid=image_uuid, dry_run=dry_run)

  if not dry_run:
    print >>output, 'Restoring apfs container size to %s...' % (
      FileSizeToString(old_apfs_container_size))
    with ImageAttacher(image_path, readonly=dry_run, mount=False,
                       encryption_manager=encryption_manager) as attacher:
      apfs_device = GetApfsDeviceFromAttachedImageDevice(attacher.GetDevice(), output)
      if apfs_device is None:
        raise Exception('No apfs device found for disk image, cannot restore to %d bytes'
                        % old_apfs_container_size)
      ResizeApfsContainer(apfs_device, old_apfs_container_size, output=output)

  CompactImage(image_path, output=output, encryption_manager=encryption_manager,
               encrypted=encrypted, image_uuid=image_uuid, dry_run=dry_run)


def GetImageEncryptionDetails(image_path):
  cmd = ['hdiutil', 'isencrypted', image_path]
  for i in range(5):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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

  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in p.stdout:
    print >>output, line.strip()
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
    print >>output, ' '.join([ pipes.quote(c) for c in cmd ])
    print >>output, '(%d paths)' % len(paths)
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for path in paths:
    p.stdin.write('%s\0' % path)
  p.stdin.close()
  for line in p.stdout:
    print >>output, line.strip()
  if p.wait():
    raise Exception('Rsync failed')

  if sync_roots:
    RsyncDirectoryOnly(src_root_path, dest_root_path, output, dry_run=dry_run, verbose=verbose)


def RsyncList(src_path, output, rsync_filters=None, verbose=False):
  cmd = [GetRsyncBin(),
         '-a',
         '--list-only',
         '--no-specials',
         '--no-devices']

  if rsync_filters is not None:
    for rsync_filter in rsync_filters:
      cmd.append(rsync_filter.GetArg())

  cmd.append(MakeRsyncDirname(src_path))

  if verbose:
    print >>output, ' '.join([ pipes.quote(c) for c in cmd ])
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    print >>output, err.rstrip()
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
    print >>output, ' '.join([ pipes.quote(c) for c in cmd ])
    print >>output, '(%d paths)' % len(paths)
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in p.stdout:
    print >>output, line.strip()
  if p.wait():
    raise Exception('Rsync failed')


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


class EncryptionManager(object):
  def __init__(self):
    self.image_uuid_password_map = {}
    self.last_password = None

  def CreatePassword(self, image_path):
    password = getpass.getpass(
      prompt='Enter a new password to secure "%s": ' % os.path.basename(image_path))
    password2 = getpass.getpass(prompt='Re-enter new password: ')
    if password != password2:
      raise Exception('Entered passwords did not match')
    return password

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
        password = getpass.getpass(
          prompt='Enter password to access "%s": ' % os.path.basename(image_path))
      self.image_uuid_password_map[image_uuid] = password
      self.last_password = password
    return password

  def _LoadPasswordFromKeychain(self, image_uuid):
    cmd = ['security', 'find-generic-password', '-ga', image_uuid]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = p.stdout.read().strip().split('\n')
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
           mount=True, encryption_manager=None):
    image_attacher = ImageAttacher(
      image_path, mount_point, readonly=readonly, browseable=browseable,
      mount=mount, encryption_manager=encryption_manager)
    image_attacher._Open()
    return image_attacher

  def __init__(self, image_path, mount_point=None, readonly=True, browseable=False,
               mount=True, encryption_manager=None):
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
    cmd = ['hdiutil', 'detach', self.device]
    for i in range(20):
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      output = p.stdout.read().strip()
      if not p.wait():
        break
      if output.endswith('- No such file or directory'):
        break
      elif not output.endswith('- Resource busy'):
        raise Exception('Unexpected output from %r: %r' % (cmd, output))
      time.sleep(10)
    else:
      raise Exception('Command %r failed after retries' % cmd)
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
    (self.encrypted, self.image_uuid) = GetImageEncryptionDetails(self.GetImagePath())
    cmd = ['hdiutil', 'attach', self.GetImagePath(), '-owners', 'on']
    if self.encrypted:
      cmd.append('-stdinpass')
    if self.mount:
      if self.random_mount_point:
        cmd.extend(['-mountrandom', tempfile.gettempdir()])
      else:
        cmd.extend(['-mountpoint', self.mount_point])
    else:
      cmd.append('-nomount')
    if self.readonly:
      cmd.append('-readonly')
    if self.mount and not self.browseable:
      cmd.append('-nobrowse')
    try:
      if not self._TryAttachCommand(cmd, try_last_password=True):
        if not self.encrypted or not self._TryAttachCommand(cmd, try_last_password=False):
          if not self.encrypted or not self._TryAttachCommand(cmd, try_last_password=False):
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

  def _TryAttachCommand(self, cmd, try_last_password):
    if self.encrypted:
      password = self.encryption_manager.GetPassword(
        self.GetImagePath(), self.image_uuid, try_last_password=try_last_password)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    if self.encrypted:
      p.stdin.write(password)
    p.stdin.close()
    output = p.stdout.read()
    lines = output.strip().split('\n')
    if p.wait():
      if len(lines) == 1 and lines[0].endswith('- Authentication error'):
        self.encryption_manager.ClearPassword(self.image_uuid)
        return False
      raise Exception('Command %s failed' % ' '.join([ pipes.quote(a) for a in cmd ]))
    self.device = None
    for line in lines:
      pieces = line.split(None, 2)
      if self.device is None:
        assert pieces[0].startswith('/dev/')
        self.device = pieces[0]
        if not self.mount:
          break
      if len(pieces) == 3 and os.path.isdir(pieces[2]):
        if self.random_mount_point:
          self.mount_point = pieces[2]
        break
    else:
      raise Exception('Unexpected output from hdiutil attach:\n%s' % output)
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

  def __str__(self):
    if self.delete_path:
      return '*deleting %s' % EscapePath(self.path)
    if self.error_path:
      return '*%s.error %s' % (self.GetItemizedShortCode(), EscapePath(self.path))
    itemized_str = ['.', self.GetItemizedShortCode(), '.', '.', '.', '.', '.', '.', '.']
    if self.new_path:
      itemized_str[0] = '>'
      for i in range(2, 9):
        itemized_str[i] = '+'
    else:
      if self.replace_path:
        itemized_str[0] = '>'
      if self.checksum_diff:
        itemized_str[2] = 'c'
      if self.size_diff:
        itemized_str[3] = 's'
      if self.time_diff:
        itemized_str[4] = 't'
      if self.permission_diff:
        itemized_str[5] = 'p'
      if self.uid_diff:
        itemized_str[6] = 'o'
      if self.gid_diff:
        itemized_str[7] = 'g'
      if self.xattr_diff:
        itemized_str[8] = 'x'
    link_dest_str = ''
    if self.link_dest is not None:
      link_dest_str = ' -> %s' % EscapePath(self.link_dest)
    return '%s %s%s' % (''.join(itemized_str), EscapePath(self.path), link_dest_str)


class PathInfo(object):
  TYPE_DIR = staged_backup_pb2.PathInfoProto.PathType.DIR
  TYPE_FILE = staged_backup_pb2.PathInfoProto.PathType.FILE
  TYPE_SYMLINK = staged_backup_pb2.PathInfoProto.PathType.SYMLINK

  TYPES = [TYPE_DIR, TYPE_FILE, TYPE_SYMLINK]

  @staticmethod
  def FromProto(pb):
    path = pb.path.encode('utf8')
    assert pb.path_type in PathInfo.TYPES
    size = None
    if pb.path_type == PathInfo.TYPE_FILE:
      size = int(pb.size)
    uid = int(pb.uid)
    gid = int(pb.gid)
    mtime = int(pb.mtime)
    link_dest = None
    if pb.link_dest:
      link_dest = pb.link_dest.encode('utf8')
    sha256 = None
    if pb.sha256:
      sha256 = pb.sha256
    xattr_hash = None
    if pb.xattr_hash:
      xattr_hash = pb.xattr_hash
    return PathInfo(path, path_type=pb.path_type, mode=pb.mode, uid=uid, gid=gid, mtime=mtime,
                    size=size, link_dest=link_dest, sha256=sha256, xattr_hash=xattr_hash)

  @staticmethod
  def FromPath(path, full_path, ignored_xattr_keys=None):
    if ignored_xattr_keys is None:
      ignored_xattr_keys = IGNORED_XATTR_KEYS
    stat_result = os.lstat(full_path)
    size = None
    sha256 = None
    link_dest = None
    xattr_hash = None
    if stat.S_ISDIR(stat_result.st_mode):
      path_type = PathInfo.TYPE_DIR
      xattr_hash = GetXattrHash(full_path, ignored_keys=ignored_xattr_keys)
    elif stat.S_ISREG(stat_result.st_mode):
      path_type = PathInfo.TYPE_FILE
      size = stat_result.st_size
      xattr_hash = GetXattrHash(full_path, ignored_keys=ignored_xattr_keys)
    elif stat.S_ISLNK(stat_result.st_mode):
      path_type = PathInfo.TYPE_SYMLINK
      link_dest = os.readlink(full_path)
    else:
      raise Exeption('Unexpected file mode for %r: %d' % (full_path, stat_result.st_mode))
    return PathInfo(path, path_type=path_type, mode=stat_result.st_mode, uid=stat_result.st_uid,
                    gid=stat_result.st_gid, mtime=int(stat_result.st_mtime), size=size,
                    link_dest=link_dest, sha256=sha256, xattr_hash=xattr_hash,
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
    if first.xattr_hash != second.xattr_hash:
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
               dev_inode=None):
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
    self.dev_inode = dev_inode

  def GetItemized(self):
    return ItemizedPathChange(self.path, self.path_type, link_dest=self.link_dest)

  def Clone(self):
    return PathInfo(self.path, self.path_type, self.mode, self.uid, self.gid, self.mtime, self.size,
                    self.link_dest, self.sha256, self.xattr_hash, dev_inode=self.dev_inode)

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
        out += ', sha256=%r' % binascii.b2a_hex(self.sha256)[:6]
      else:
        out += ', sha256=%r' % binascii.b2a_hex(self.sha256)
    if self.xattr_hash is not None:
      if shorten_xattr_hash:
        out += ', xattr-hash=%r' % binascii.b2a_hex(self.xattr_hash)[:6]
      else:
        out += ', xattr-hash=%r' % binascii.b2a_hex(self.xattr_hash)
    if self.dev_inode is not None:
      out += ', dev-inode=%r' % (self.dev_inode,)
    return out

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
    except ValueError:
      print '*** Error in ToProto for path %r' % self.path
      raise
    return pb


class FileEnumerator(object):
  def __init__(self, root_dir, output, filters=[], verbose=False):
    self.root_dir = os.path.normpath(root_dir)
    self.output = output
    self.filters = filters
    self.verbose = verbose

  def Scan(self):
    for path in sorted(RsyncList(self.root_dir, self.output, rsync_filters=self.filters,
                                 verbose=self.verbose)):
      yield path


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
      assert path_info.path not in self.path_map
    self.path_map[path_info.path] = path_info

  def RemovePathInfo(self, path):
    path_info = self.path_map[path]
    del self.path_map[path]
    return path_info

  def GetPathCount(self):
    return len(self.path_map)

  def Clone(self):
    clone = Manifest(self.path)
    for path, path_info in self.path_map.items():
      clone.path_map[path] = path_info.Clone()
    return clone

  def Dump(self, output):
    for path in sorted(self.path_map.keys()):
      print >>output, self.path_map[path]

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
    all_paths.update(other_manifest.path_map.keys())
    for path in sorted(all_paths):
      other_path_info = other_manifest.path_map.get(path)
      path_info = self.path_map.get(path)

      itemized = PathInfo.GetItemizedDiff(path_info, other_path_info)
      has_diffs = itemized.HasDiffs(ignore_uid_diffs=ignore_uid_diffs, ignore_gid_diffs=ignore_gid_diffs)
      if has_diffs or include_matching:
        itemized_results.append(itemized)
    return itemized_results

  def DumpDiff(self, other_manifest, output, verbose=False, ignore_uid_diffs=IGNORE_UID_DIFFS,
               ignore_gid_diffs=IGNORE_GID_DIFFS):
    for itemized in self.GetDiffItemized(
        other_manifest, include_matching=verbose, ignore_uid_diffs=ignore_uid_diffs,
        ignore_gid_diffs=ignore_gid_diffs):
      print >>output, itemized

  def CreateSha256ToPathInfosMap(self, min_file_size=1):
    sha256_to_pathinfos = {}
    for path in self.GetPaths():
      path_info = self.GetPathInfo(path)
      if (path_info.path_type == PathInfo.TYPE_FILE
          and path_info.size >= min_file_size):
        assert path_info.sha256 is not None
        if path_info.sha256 not in sha256_to_pathinfos:
          sha256_to_pathinfos[path_info.sha256] = []
        sha256_to_pathinfos[path_info.sha256].append(path_info)
    return sha256_to_pathinfos

  def CreateSizeToPathInfosMap(self, min_file_size=1):
    size_to_pathinfos = {}
    for path in self.GetPaths():
      path_info = self.GetPathInfo(path)
      if path_info.path_type == PathInfo.TYPE_FILE:
        assert path_info.size is not None
        if path_info.size >= min_file_size:
          if path_info.size not in size_to_pathinfos:
            size_to_pathinfos[path_info.size] = []
          size_to_pathinfos[path_info.size].append(path_info)
    return size_to_pathinfos


class Checkpoint(object):
  STATE_NEW = 'NEW'
  STATE_IN_PROGRESS = 'IN_PROGRESS'
  STATE_DONE = 'DONE'
  STATE_DELETED = 'DELETED'

  @staticmethod
  def New(base_path, name, encryption_manager=None, manifest_only=False, encrypt=False, dry_run=False):
    if name is None:
      name = time.strftime('%Y-%m-%d-%H%M%S')
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

  def GetImagePath(self):
    return os.path.join(self.base_path, self.name + '.sparseimage')

  def GetMountPoint(self):
    if self.attacher is not None:
      return self.attacher.GetMountPoint()

  def GetContentRootPath(self):
    return os.path.join(self.GetMountPoint(), CONTENT_DIR_NAME)

  def GetMetadataPath(self):
    return os.path.join(self.GetMountPoint(), METADATA_DIR_NAME)

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

  def _CreateImage(self):
    CreateDiskImage(self.GetImagePath(), volume_name=self.name, encrypt=self.encrypt,
                    encryption_manager=self.encryption_manager, dry_run=self.dry_run)

  def _MountImage(self):
    assert not self.mounted
    self.attacher = ImageAttacher.Open(self.GetImagePath(), encryption_manager=self.encryption_manager,
                                       readonly=(self.readonly or self.dry_run))
    self.mounted = True

  def _UnmountImage(self):
    assert self.mounted
    self.attacher.Close()
    self.attacher = None
    self.mounted = False


def ReadManifestFromCheckpointOrPath(path, encryption_manager=None, dry_run=False):
  if path.endswith('.sparseimage'):
    checkpoint = Checkpoint.Open(path, encryption_manager=encryption_manager, dry_run=dry_run)
    try:
      return Manifest.Load(os.path.join(checkpoint.GetMetadataPath(), MANIFEST_FILENAME))
    finally:
      checkpoint.Close()
  elif path.endswith('.pbdata') or path.endswith('.pbdata.bak') or path.endswith('.pbdata.new'):
    return Manifest.Load(path)
  else:
    raise Exception('Expected a .sparseimage or .pbdata file but got %r', path)


class CheckpointCreator(object):
  PRE_SYNC_CONTENTS_TEST_HOOK = None

  def __init__(self, src_root_dir, checkpoints_root_dir, name, output, basis_path=None, basis_manifest=None,
               dry_run=False, verbose=False, checksum_all=False, manifest_only=False, encrypt=True,
               encryption_manager=None, filters=RSYNC_FILTERS):
    if src_root_dir is None:
      raise Exception('src_root_dir cannot be None')
    self.src_root_dir = src_root_dir
    self.basis_path = basis_path
    self.basis_manifest = basis_manifest
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
    self.paths_to_sync = []
    self.file_enumerator = FileEnumerator(src_root_dir, output, filters=filters, verbose=verbose)
    self.total_paths = 0
    self.total_checkpoint_paths = 0
    self.total_size = 0
    self.total_checkpoint_size = 0

  def Create(self):
    try:
      self.checkpoint = Checkpoint.New(
        self.checkpoints_root_dir, self.name, encryption_manager=self.encryption_manager,
        manifest_only=self.manifest_only, encrypt=self.encrypt, dry_run=self.dry_run)

      self._CreateInternal()

      self.checkpoint.Close()

      self._PrintResults()
      return True
    except Exception, e:
      if self.checkpoint is not None:
        try:
          self.checkpoint.Delete()
        except Exception, e2:
          print 'Suppressed exception: %s' % e2
          traceback.print_exc()
        self.checkpoint = None
      raise

  def _CreateInternal(self):
    if not self.dry_run:
      self.manifest = Manifest(os.path.join(self.checkpoint.GetMetadataPath(), MANIFEST_FILENAME))
    else:
      self.manifest = Manifest()

    existing_paths = []
    if self.basis_manifest is not None:
      existing_paths = self.basis_manifest.GetPaths()

    for path in self.file_enumerator.Scan():
      self._HandleExistingPaths(existing_paths, next_new_path=path)
      self._AddPathIfChanged(path)

    self._HandleExistingPaths(existing_paths, next_new_path=None)

    if not self.manifest_only:
      self._SyncContents()

    self._WriteBasisInfo()
    if not self.dry_run:
      self.manifest.Write()

  def _PrintResults(self):
    if self.basis_manifest is None:
      if self.total_paths > 0:
        print >>self.output, 'Transferring %d paths (%s)' % (
          self.total_paths, FileSizeToString(self.total_size))
    elif self.total_checkpoint_paths > 0:
      print >>self.output, 'Transferring %d of %d paths (%s of %s)' % (
        self.total_checkpoint_paths, self.total_paths,
        FileSizeToString(self.total_checkpoint_size), FileSizeToString(self.total_size))
    if not self.dry_run:
      print >>self.output, 'Created checkpoint at %s' % self.checkpoint.GetImagePath()

  def _HandleExistingPaths(self, existing_paths, next_new_path=None):
    while existing_paths:
      next_existing_path = existing_paths[0]
      if next_new_path is not None and next_existing_path > next_new_path:
        break
      if next_new_path != next_existing_path:
        itemized = self.basis_manifest.GetPathInfo(next_existing_path).GetItemized()
        itemized.delete_path = True
        print >>self.output, itemized
      del existing_paths[0]

  def _AddPathIfChanged(self, path, allow_replace=False):
    full_path = os.path.join(self.src_root_dir, path)
    path_info = PathInfo.FromPath(path, full_path)
    self.total_paths += 1
    if path_info.size is not None:
      self.total_size += path_info.size

    basis_path_info = None
    if self.basis_manifest is not None:
      basis_path_info = self.basis_manifest.GetPathInfo(path)
    if basis_path_info is None:
      self._AddPath(path, full_path, path_info, allow_replace=allow_replace)
      return

    if path_info.path_type == PathInfo.TYPE_FILE:
      path_info.sha256 = basis_path_info.sha256
    self.manifest.AddPathInfo(path_info, allow_replace=allow_replace)

    itemized = PathInfo.GetItemizedDiff(path_info, basis_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        print >>self.output, itemized
      return
    if path_info.path_type == PathInfo.TYPE_FILE:
      path_info.sha256 = Sha256WithProgress(full_path, path_info, output=self.output)
    if path_info.sha256 != basis_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        print >>self.output, itemized
      return

    print >>self.output, itemized

    self._AddPathContents(path_info)

  def _AddPath(self, path, full_path, path_info, allow_replace=False):
    if path_info.path_type == PathInfo.TYPE_FILE:
      path_info.sha256 = Sha256WithProgress(full_path, path_info, output=self.output)

    itemized = path_info.GetItemized()
    itemized.new_path = True
    print >>self.output, itemized

    self.manifest.AddPathInfo(path_info, allow_replace=allow_replace)
    self._AddPathContents(path_info)

  def _AddPathContents(self, path_info):
    self.paths_to_sync.append(path_info.path)
    self.total_checkpoint_paths += 1
    if path_info.size is not None:
      self.total_checkpoint_size += path_info.size

  def _SyncContents(self):
    if self.dry_run:
      return

    max_retries = 5
    num_retries_left = max_retries
    while self.paths_to_sync:
      if not num_retries_left:
        raise Exception('Failed to create checkpoint after %d retries' % max_retries)
      num_retries_left -= 1

      if CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK:
        CheckpointCreator.PRE_SYNC_CONTENTS_TEST_HOOK(self)

      RsyncPaths(self.paths_to_sync, self.src_root_dir, self.checkpoint.GetContentRootPath(),
                 output=self.output, dry_run=self.dry_run, verbose=self.verbose)

      paths_just_synced = self.paths_to_sync
      self.paths_to_sync = []
      first_requeued = True
      for path in paths_just_synced:
        if self._ReQueuePathsModifiedSinceManifest(path, first_requeued):
          first_requeued = False

  def _ReQueuePathsModifiedSinceManifest(self, path, first_requeued):
    expected_path_info = self.manifest.GetPathInfo(path)
    if expected_path_info.path_type == PathInfo.TYPE_FILE:
      assert expected_path_info.sha256
    full_path = os.path.join(self.checkpoint.GetContentRootPath(), path)
    checkpoint_path_info = PathInfo.FromPath(path, full_path)
    if checkpoint_path_info.path_type == PathInfo.TYPE_FILE:
      checkpoint_path_info.sha256 = expected_path_info.sha256
    itemized = PathInfo.GetItemizedDiff(checkpoint_path_info, expected_path_info)
    if not itemized.HasDiffs():
      if checkpoint_path_info.path_type == PathInfo.TYPE_FILE:
        checkpoint_path_info.sha256 = Sha256WithProgress(full_path, checkpoint_path_info, output=self.output)
      if checkpoint_path_info.sha256 == expected_path_info.sha256:
        return False
    if first_requeued:
      print >>self.output, "*** Warning: Paths changed since syncing, checking..."
    self._AddPathIfChanged(path, allow_replace=True)
    return True

  def _WriteBasisInfo(self):
    if not self.dry_run and self.basis_path is not None:
      basis_info_path = os.path.join(self.checkpoint.GetMetadataPath(), BASIS_INFO_FILENAME)
      with open(basis_info_path, 'w') as out_file:
        out_file.write(json.dumps({
          'basis_filename': os.path.basename(self.basis_path)
        }, indent=2))
        out_file.write('\n')


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
    self.file_enumerator = FileEnumerator(dest_root, output, verbose=verbose)
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
    self.src_manifest = Manifest.Load(
      os.path.join(self.src_checkpoint.GetMetadataPath(), MANIFEST_FILENAME))

    new_paths = self.src_manifest.GetPaths()

    for path in self.file_enumerator.Scan():
      self._HandleNewPaths(new_paths, next_existing_path=path)

      full_path = os.path.join(self.dest_root, path)
      dest_path_info = PathInfo.FromPath(path, full_path)
      src_path_info = self.src_manifest.GetPathInfo(path)
      if src_path_info is None:
        self._AddDeleted(path, dest_path_info)
      else:
        self._AddIfChanged(path, src_path_info, dest_path_info)

    self._HandleNewPaths(new_paths, next_existing_path=None)

    if self.errors_encountered:
      print >>self.output, '*** Errors encountered before applying checkpoint'
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
          print >>self.output, itemized
      del new_paths[0]

  def _AddDeleted(self, path, dest_path_info):
    itemized = dest_path_info.GetItemized()
    itemized.delete_path = True
    print >>self.output, itemized
    self.paths_to_delete.append(path)

  def _AddIfChanged(self, path, src_path_info, dest_path_info):
    full_path = os.path.join(self.dest_root, dest_path_info.path)

    itemized = PathInfo.GetItemizedDiff(src_path_info, dest_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        print >>self.output, itemized
      return
    if dest_path_info.path_type == PathInfo.TYPE_FILE:
      dest_path_info.sha256 = Sha256WithProgress(full_path, dest_path_info, output=self.output)
    if dest_path_info.sha256 != src_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        print >>self.output, itemized
      return

    if self._AddPathContents(path, existing_path_info=dest_path_info):
      print >>self.output, itemized
    if self.verbose:
      if src_path_info is not None:
        print >>self.output, '<', src_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True)
      if dest_path_info is not None:
        print >>self.output, '>', dest_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True)

  def _AddPathContents(self, path, existing_path_info):
    if not os.path.lexists(os.path.join(self.src_checkpoint.GetContentRootPath(), path)):
      itemized = self.src_manifest.GetPathInfo(path).GetItemized()
      itemized.error_path = True
      print >>self.output, itemized
      self.errors_encountered = True
      return False

    self.paths_to_sync.append(path)
    if existing_path_info is not None and existing_path_info.path_type == PathInfo.TYPE_FILE:
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
      RsyncPaths(self.paths_to_sync, self.src_checkpoint.GetContentRootPath(), self.dest_root,
                 output=self.output, dry_run=self.dry_run, verbose=self.verbose)

    # TODO: Fixing mtimes for all parent directories of synced files may be required.
    if not self.dry_run and original_dest_mtime is not None:
      src_mtime = int(os.lstat(self.src_checkpoint.GetContentRootPath()).st_mtime)
      updated_dest_mtime = int(os.lstat(self.dest_root).st_mtime)
      if updated_dest_mtime not in [src_mtime, original_dest_mtime]:
        os.utime(self.dest_root, (original_dest_mtime, original_dest_mtime))

  def _ClearHardlinks(self, paths):
    for path in paths:
      full_path = os.path.join(self.dest_root, path)
      ClearPathHardlinks(full_path, dry_run=self.dry_run)


class CheckpointStripper(object):
  def __init__(self, checkpoint_path, output, defragment=False, defragment_iterations=1,
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
    self.checkpoint = Checkpoint.Open(
      self.checkpoint_path, encryption_manager=self.encryption_manager, readonly=False,
      dry_run=self.dry_run)
    try:
      self._StripInternal()
    finally:
      if self.checkpoint is not None:
        self.checkpoint.Close()
        self.checkpoint = None

    compactor = ImageCompactor(
      self.checkpoint_path, output=self.output, defragment=self.defragment,
      defragment_iterations=self.defragment_iterations, dry_run=self.dry_run,
      verbose=self.verbose, encryption_manager=self.encryption_manager)
    return compactor.Compact()

  def _StripInternal(self):
    if not os.path.exists(self.checkpoint.GetContentRootPath()):
      print >>self.output, "Checkpoint already stripped"
      return True

    if not self.dry_run:
      shutil.rmtree(self.checkpoint.GetContentRootPath())

    print >>self.output, "Checkpoint stripped"
    return True


class ImageCompactor(object):
  def __init__(self, image_path, output, defragment=False, defragment_iterations=1,
               dry_run=False, verbose=False, encryption_manager=None):
    self.image_path = image_path
    self.defragment = defragment
    self.defragment_iterations = defragment_iterations
    self.output = output
    self.dry_run = dry_run
    self.verbose = verbose
    self.encryption_manager = encryption_manager
    self.checkpoint = None

  def Compact(self):
    starting_size = GetPathTreeSize(self.image_path)
    CompactAndDefragmentImage(
      self.image_path, output=self.output, defragment=self.defragment,
      defragment_iterations=self.defragment_iterations, dry_run=self.dry_run,
      encryption_manager=self.encryption_manager)
    ending_size = GetPathTreeSize(self.image_path)
    print >>self.output, "Image size %s -> %s" % (
      FileSizeToString(starting_size), FileSizeToString(ending_size))
    return True


class ManifestVerifierStats(object):
  def __init__(self):
    self.total_paths = 0
    self.total_size = 0
    self.total_mismatched_paths = 0
    self.total_mismatched_size = 0
    self.total_checksummed_paths = 0
    self.total_checksummed_size = 0


class ManifestVerifier(object):
  def __init__(self, manifest, src_root, output, filters=[], manifest_on_top=True, checksum_all=False,
               escape_key_detector=None, verbose=False):
    self.manifest = manifest
    self.src_root = src_root
    self.output = output
    self.checksum_all = checksum_all
    self.escape_key_detector = escape_key_detector
    self.verbose = verbose
    self.manifest_on_top = manifest_on_top
    self.file_enumerator = FileEnumerator(src_root, output, filters=filters, verbose=verbose)
    self.has_diffs = False
    self.stats = ManifestVerifierStats()

  def Verify(self):
    missing_paths = self.manifest.GetPaths()

    for path in self.file_enumerator.Scan():
      if self.escape_key_detector is not None and self.escape_key_detector.WasEscapePressed():
        print >>self.output, '*** Cancelled at path %s' % EscapePath(path)
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
    print >>self.output, itemized
    self.stats.total_mismatched_paths += 1
    if src_path_info.size:
      self.stats.total_mismatched_size += src_path_info.size

  def _CheckCommonPath(self, path, src_path_info, manifest_path_info):
    full_path = os.path.join(self.src_root, src_path_info.path)

    itemized = PathInfo.GetItemizedDiff(src_path_info, manifest_path_info)
    matches = not itemized.HasDiffs()
    if matches and not self.checksum_all:
      if self.verbose:
        print >>self.output, itemized
      return
    if src_path_info.path_type == PathInfo.TYPE_FILE:
      src_path_info.sha256 = Sha256WithProgress(full_path, src_path_info, output=self.output)
      self.stats.total_checksummed_paths += 1
      self.stats.total_checksummed_size += src_path_info.size
    if src_path_info.sha256 != manifest_path_info.sha256:
      itemized.checksum_diff = True
      itemized.replace_path = True
      matches = False
    if matches:
      if self.verbose:
        print >>self.output, itemized
      return

    print >>self.output, itemized
    self.stats.total_mismatched_paths += 1
    if src_path_info.size:
      self.stats.total_mismatched_size += src_path_info.size
    if self.verbose:
      if src_path_info is not None:
        print >>self.output, '<', src_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True)
      if manifest_path_info is not None:
        print >>self.output, '>', manifest_path_info.ToString(
          shorten_sha256=True, shorten_xattr_hash=True)
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
        print >>self.output, itemized
        self.stats.total_mismatched_paths += 1
        if path_info.size:
          self.stats.total_mismatched_size += path_info.size
      del missing_paths[0]


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

  filters = list(RSYNC_FILTERS)
  if cmd_args.no_filters:
    filters = []
  if cmd_args.filter_merge_path is not None:
    if not os.path.exists(cmd_args.filter_merge_path):
      raise Exception('Expected filter merge path %r to exist' % cmd_args.filter_merge_path)
    filters.append(RsyncFilterMerge(cmd_args.filter_merge_path))

  encryption_manager = EncryptionManager()

  basis_path = cmd_args.last_manifest or cmd_args.last_checkpoint
  if basis_path:
    basis_manifest = ReadManifestFromCheckpointOrPath(
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
    encryption_manager=EncryptionManager())
  return checkpoint_applier.Apply()


def DoStripCheckpoint(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--checkpoint-path', required=True)
  parser.add_argument('--no-defragment', dest='defragment', action='store_false')
  parser.add_argument('--defragment-iterations', default='1', type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  checkpoint_stripper = CheckpointStripper(
    cmd_args.checkpoint_path, defragment=cmd_args.defragment,
    defragment_iterations=cmd_args.defragment_iterations, output=output, dry_run=args.dry_run,
    verbose=args.verbose, encryption_manager=EncryptionManager())
  return checkpoint_stripper.Strip()


def DoCompactImage(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--image-path', required=True)
  parser.add_argument('--no-defragment', dest='defragment', action='store_false')
  parser.add_argument('--defragment-iterations', default='1', type=int)
  cmd_args = parser.parse_args(args.cmd_args)

  image_compactor = ImageCompactor(
    cmd_args.image_path, defragment=cmd_args.defragment,
    defragment_iterations=cmd_args.defragment_iterations, output=output, dry_run=args.dry_run,
    verbose=args.verbose, encryption_manager=EncryptionManager())
  return image_compactor.Compact()


def DoDumpManifest(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('path', metavar='manifest_or_checkpoint_path')
  cmd_args = parser.parse_args(args.cmd_args)

  manifest = ReadManifestFromCheckpointOrPath(
    cmd_args.path, encryption_manager=EncryptionManager(), dry_run=args.dry_run)
  manifest.Dump(output)
  return True


def DoDiffManifests(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('first_path', metavar='first_manifest_or_checkpoint_path')
  parser.add_argument('second_path', metavar='second_manifest_or_checkpoint_path')
  if IGNORE_UID_DIFFS:
    parser.add_argument('--no-ignore-uid-diffs', dest='ignore_uid_diffs', action='store_false')
  else:
    parser.add_argument('--ignore-uid-diffs', dest='ignore_uid_diffs', action='store_true')
  if IGNORE_GID_DIFFS:
    parser.add_argument('--no-ignore-gid-diffs', dest='ignore_gid_diffs', action='store_false')
  else:
    parser.add_argument('--ignore-gid-diffs', dest='ignore_gid_diffs', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  encryption_manager = EncryptionManager()

  first_manifest = ReadManifestFromCheckpointOrPath(
    cmd_args.first_path, encryption_manager=encryption_manager, dry_run=args.dry_run)
  second_manifest = ReadManifestFromCheckpointOrPath(
    cmd_args.second_path, encryption_manager=encryption_manager, dry_run=args.dry_run)
  second_manifest.DumpDiff(first_manifest, output, verbose=args.verbose, ignore_uid_diffs=cmd_args.ignore_uid_diffs,
                           ignore_gid_diffs=cmd_args.ignore_gid_diffs)
  return True


def DoVerifyManifest(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('--src-root', required=True)
  parser.add_argument('path', metavar='manifest_or_checkpoint_path')
  parser.add_argument('--checksum-all', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  manifest = ReadManifestFromCheckpointOrPath(
    cmd_args.path, encryption_manager=EncryptionManager(), dry_run=args.dry_run)

  manifest_verifier = ManifestVerifier(
    manifest, cmd_args.src_root, output, checksum_all=cmd_args.checksum_all, verbose=args.verbose)
  return manifest_verifier.Verify()


def DoCommand(args, output):
  if args.command == COMMAND_CREATE:
    return DoCreateCheckpoint(args, output=output)
  elif args.command == COMMAND_APPLY:
    return DoApplyCheckpoint(args, output=output)
  elif args.command == COMMAND_STRIP:
    return DoStripCheckpoint(args, output=output)
  elif args.command == COMMAND_COMPACT:
    return DoCompactImage(args, output=output)
  elif args.command == COMMAND_DUMP_MANIFEST:
    return DoDumpManifest(args, output=output)
  elif args.command == COMMAND_DIFF_MANIFESTS:
    return DoDiffManifests(args, output=output)
  elif args.command == COMMAND_VERIFY_MANIFEST:
    return DoVerifyManifest(args, output=output)

  print >>output, '*** Error: Unknown command %s' % args.command
  return False
