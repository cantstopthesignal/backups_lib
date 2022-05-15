import contextlib
import errno
import json
import os
import shutil
import tempfile
import traceback
import uuid

from . import checkpoint_lib
from . import lib

from .test_util import AssertEquals
from .test_util import CreateFile
from .test_util import DoBackupsMain
from .test_util import Xattr


FAKE_DISK_IMAGE_LEVEL_OFF = 'off'
FAKE_DISK_IMAGE_LEVEL_MEDIUM = 'medium'
FAKE_DISK_IMAGE_LEVEL_HIGH = 'high'
FAKE_DISK_IMAGE_LEVEL_MAX = 'max'
FAKE_DISK_IMAGE_LEVEL_NONE = 'none'

FAKE_DISK_IMAGE_LEVEL_CHOICES = [
  FAKE_DISK_IMAGE_LEVEL_OFF,
  FAKE_DISK_IMAGE_LEVEL_MEDIUM,
  FAKE_DISK_IMAGE_LEVEL_HIGH,
  FAKE_DISK_IMAGE_LEVEL_MAX,
]

FAKE_DISK_IMAGE_LEVEL_TO_INDEX = {
  FAKE_DISK_IMAGE_LEVEL_OFF: 0,
  FAKE_DISK_IMAGE_LEVEL_MEDIUM: 1,
  FAKE_DISK_IMAGE_LEVEL_HIGH: 2,
  FAKE_DISK_IMAGE_LEVEL_MAX: 3,
  FAKE_DISK_IMAGE_LEVEL_NONE: 4,
}

FAKE_DISK_IMAGE_LEVEL = FAKE_DISK_IMAGE_LEVEL_MEDIUM

DEBUG_FAKE_DISK_IMAGE_LEVELS = False


def GetManifestItemized(manifest):
  itemized_outputs = []
  for path in manifest.GetPaths():
    itemized_outputs.append(str(manifest.GetPathInfo(path).GetItemized()))
  return itemized_outputs


def DoDumpManifest(manifest_path, ignore_matching_renames=False,
                   expected_success=True, expected_output=[]):
  cmd_args = ['dump-manifest',  manifest_path]
  with SetOmitUidAndGidInPathInfoToString():
    DoBackupsMain(cmd_args, expected_success=expected_success, expected_output=expected_output)


def DoVerifyManifest(src_root, manifest_or_image_path, dry_run=False,
                     expected_success=True, expected_output=[]):
  cmd_args = ['verify-manifest',
              '--src-root', src_root,
              manifest_or_image_path,
              '--checksum-all']
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def GetFileTreeManifest(parent_path):
  with open('/dev/null', 'w') as devnull:
    checkpoint_creator = checkpoint_lib.CheckpointCreator(
      src_root_dir=parent_path, checkpoints_root_dir='/dev/null', name='checkpoint',
      output=devnull, dry_run=True, encryption_manager=lib.EncryptionManager())
    checkpoint_creator.Create()
    return checkpoint_creator.manifest


@contextlib.contextmanager
def SetHdiutilCompactOnBatteryAllowed(new_value=False):
  old_value = lib.HDIUTIL_COMPACT_ON_BATTERY_ALLOWED
  lib.HDIUTIL_COMPACT_ON_BATTERY_ALLOWED = new_value
  try:
    yield
  finally:
    lib.HDIUTIL_COMPACT_ON_BATTERY_ALLOWED = old_value


@contextlib.contextmanager
def SetOmitUidAndGidInPathInfoToString(new_value=True):
  old_value = lib.OMIT_UID_AND_GID_IN_PATH_INFO_TO_STRING
  lib.OMIT_UID_AND_GID_IN_PATH_INFO_TO_STRING = new_value
  try:
    yield
  finally:
    lib.OMIT_UID_AND_GID_IN_PATH_INFO_TO_STRING = old_value


@contextlib.contextmanager
def SetMaxDupCounts(new_max_dup_find_count=10, new_max_dup_printout_count=5):
  old_find_value = lib.MAX_DUP_FIND_COUNT
  old_printout_value = lib.MAX_DUP_PRINTOUT_COUNT
  lib.MAX_DUP_FIND_COUNT = new_max_dup_find_count
  lib.MAX_DUP_PRINTOUT_COUNT = new_max_dup_printout_count
  try:
    yield
  finally:
    lib.MAX_DUP_FIND_COUNT = old_find_value
    lib.MAX_DUP_PRINTOUT_COUNT = old_printout_value


@contextlib.contextmanager
def SetEscapeKeyDetectorCancelAtInvocation(invocation_num):
  lib.EscapeKeyDetector.SetCancelAtInvocation(invocation_num)
  try:
    yield
  finally:
    lib.EscapeKeyDetector.ClearCancelAtInvocation()


@contextlib.contextmanager
def InteractiveCheckerReadyResults(interactive_checker):
  try:
    yield interactive_checker
  finally:
    interactive_checker.ClearReadyResults()


class FakeDiskImage(object):
  @staticmethod
  def PathFromDevice(device):
    prefix = '/dev/FAKE_'
    assert device.startswith(prefix)
    return device[len(prefix):]

  @staticmethod
  def UnMountedDataDir(image_path):
    return image_path + '_FAKE_IMAGE_DATA_UNMOUNTED'

  def __init__(self, path):
    assert os.path.splitext(path)[1] in ['.sparsebundle', '.dmg', '.sparseimage']
    self.path = path
    self.metadata = {}

  def Create(self):
    assert not os.path.lexists(self.path)
    self.metadata['attached'] = False
    self.metadata['mounted'] = False
    self.metadata['mount_point'] = None
    self.metadata['unmounted_data_dir'] = FakeDiskImage.UnMountedDataDir(self.path)
    self.metadata['image_uuid'] = str(uuid.uuid4())
    os.mkdir(self.metadata['unmounted_data_dir'])
    self._Save()

  def Attach(self, mount=False, random_mount_point=False, mount_point=None):
    self._Load()
    assert not self.metadata['attached']
    assert not self.metadata['mounted']
    self.metadata['attached'] = True
    self.metadata['mounted'] = mount
    if mount:
      self.metadata['mount_point'] = mount_point
      if random_mount_point or mount_point is None:
        self.metadata['mount_point'] = tempfile.NamedTemporaryFile(delete=False).name
        os.unlink(self.metadata['mount_point'])
      assert os.path.isdir(self.metadata['unmounted_data_dir'])
      os.rename(self.metadata['unmounted_data_dir'], self.metadata['mount_point'])
    self._Save()
    result = lib.DiskImageHelperAttachResult()
    result.device = '/dev/FAKE_' + self.path
    result.mount_point = self.metadata['mount_point']
    return result

  def Detach(self):
    self._Load()
    assert self.metadata['attached']
    self.metadata['attached'] = False
    if self.metadata['mounted']:
      assert self.metadata['mount_point'] is not None
      os.rename(self.metadata['mount_point'], self.metadata['unmounted_data_dir'])
      self.metadata['mount_point'] = None
      self.metadata['mounted'] = False
    self._Save()

  def MoveTo(self, to_path):
    self._Load()
    assert not self.metadata['attached']
    assert not self.metadata['mounted']
    old_unmounted_data_dir = self.metadata['unmounted_data_dir']
    self.metadata['unmounted_data_dir'] = FakeDiskImage.UnMountedDataDir(to_path)
    self._Save()
    shutil.move(self.path, to_path)
    self.path = to_path
    shutil.move(old_unmounted_data_dir, self.metadata['unmounted_data_dir'])

  def GetImageEncryptionDetails(self):
    self._Load()
    return (False, self.metadata['image_uuid'])

  def _Load(self):
    with open(self.path, 'r') as in_f:
      self.metadata = json.load(in_f)

  def _Save(self):
    with open(self.path, 'w') as out_f:
      json.dump(self.metadata, out_f, indent=2)


class FakeDiskImageHelper(object):
  def CreateImage(self, path, size=None, filesystem=None, image_type=None, volume_name=None,
                  encryption=False, password=None):
    assert not encryption
    assert not os.path.lexists(path)
    fake_image = FakeDiskImage(path)
    fake_image.Create()

  def AttachImage(self, path, encrypted=False, password=None, mount=False,
                  random_mount_point=False, mount_point=None,
                  readonly=True, browseable=False, verify=True):
    assert not encrypted
    fake_image = FakeDiskImage(path)
    return fake_image.Attach(mount=mount, random_mount_point=random_mount_point, mount_point=mount_point)

  def DetachImage(self, device):
    fake_image = FakeDiskImage(FakeDiskImage.PathFromDevice(device))
    fake_image.Detach()

  def MoveImage(self, from_path, to_path):
    fake_image = FakeDiskImage(from_path)
    fake_image.MoveTo(to_path)

  def GetImageEncryptionDetails(self, path):
    fake_image = FakeDiskImage(path)
    return fake_image.GetImageEncryptionDetails()


@contextlib.contextmanager
def ApplyFakeDiskImageHelperLevel(min_fake_disk_image_level=FAKE_DISK_IMAGE_LEVEL_MEDIUM, test_case=None):
  if (FAKE_DISK_IMAGE_LEVEL == FAKE_DISK_IMAGE_LEVEL_MAX
      and min_fake_disk_image_level == FAKE_DISK_IMAGE_LEVEL_NONE):
    print('*** Warning: %s skipped since it requires real disk images' % test_case)
    yield False
    return

  if (FAKE_DISK_IMAGE_LEVEL_TO_INDEX[min_fake_disk_image_level] >
      FAKE_DISK_IMAGE_LEVEL_TO_INDEX[FAKE_DISK_IMAGE_LEVEL]):
    if DEBUG_FAKE_DISK_IMAGE_LEVELS:
      print('Using REAL Disk Images')
      yield False
      return
    yield True
    return

  old_value = lib.DISK_IMAGE_HELPER_OVERRIDE
  lib.DISK_IMAGE_HELPER_OVERRIDE = FakeDiskImageHelper
  try:
    if DEBUG_FAKE_DISK_IMAGE_LEVELS:
      print('Using FAKE Disk Images')
      yield False
      return
    yield True
  finally:
    lib.DISK_IMAGE_HELPER_OVERRIDE = old_value


def CollapseApfsOperationsInOutput(output_lines):
  new_output_lines = []
  in_apfs_operation = False
  for line in output_lines:
    if line == 'Started APFS operation':
      assert not in_apfs_operation
      in_apfs_operation = True
      new_output_lines.append('<... snip APFS operation ...>')
      continue
    elif line == 'Finished APFS operation':
      assert in_apfs_operation
      in_apfs_operation = False
      continue
    elif in_apfs_operation:
      continue
    new_output_lines.append(line)
  assert not in_apfs_operation
  return new_output_lines


def CreateGoogleDriveRemoteFile(parent_dir, filename):
  path = CreateFile(parent_dir, filename, contents='IGNORE')
  xattr_data = Xattr(path)
  xattr_data[lib.GOOGLE_DRIVE_MIME_TYPE_XATTR_KEY] = (
    ('%sdocument' % lib.GOOGLE_DRIVE_REMOTE_FILE_MIME_TYPE_PREFIX).encode('ascii'))
  return path


@contextlib.contextmanager
def HandleGoogleDriveRemoteFiles(paths):
  class ErroringFile:
    def __enter__(self):
      return self
    def __exit__(self, exc_type, exc, exc_traceback):
      pass
    def read(self, size=-1):
      raise OSError(errno.ENOTSUP, 'Operation not supported')
    def close(self):
      pass

  def OpenContentOverride(path, mode='r'):
    if path in paths:
      return ErroringFile()
    return open(path, mode)

  old_value = lib.OPEN_CONTENT_FUNCTION
  lib.OPEN_CONTENT_FUNCTION = OpenContentOverride
  try:
    yield
  finally:
    lib.OPEN_CONTENT_FUNCTION = old_value


@contextlib.contextmanager
def HandleGetPass(expected_prompts=[], returned_passwords=[]):
  expected_prompts = expected_prompts[:]
  returned_passwords = returned_passwords[:]

  def GetPass(prompt=''):
    AssertEquals(expected_prompts[0], prompt)
    del expected_prompts[0]
    returned_password = returned_passwords[0]
    del returned_passwords[0]
    return returned_password

  old_value = lib.GETPASS_FUNCTION
  lib.GETPASS_FUNCTION = GetPass
  try:
    yield
    AssertEquals([], expected_prompts)
    AssertEquals([], returned_passwords)
  finally:
    lib.GETPASS_FUNCTION = old_value
