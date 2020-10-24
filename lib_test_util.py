import contextlib
import lib

from test_util import DoMain


def GetManifestItemized(manifest):
  itemized_outputs = []
  for path in manifest.GetPaths():
    itemized_outputs.append(str(manifest.GetPathInfo(path).GetItemized()))
  return itemized_outputs


def DoVerifyManifest(src_root, manifest_or_checkpoint_path, dry_run=False,
                    expected_success=True, expected_output=[]):
  cmd_args = ['verify-manifest',
              '--src-root', src_root,
              manifest_or_checkpoint_path,
              '--checksum-all']
  DoMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
         expected_output=expected_output)


def GetFileTreeManifest(parent_path):
  with open('/dev/null', 'w') as devnull:
    checkpoint_creator = lib.CheckpointCreator(
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
