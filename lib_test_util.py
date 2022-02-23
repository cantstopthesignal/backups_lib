import contextlib
import errno

from . import checkpoint_lib
from . import lib

from .test_util import AssertEquals
from .test_util import CreateFile
from .test_util import DoBackupsMain
from .test_util import Xattr


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
