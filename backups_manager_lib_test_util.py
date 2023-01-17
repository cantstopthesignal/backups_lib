import contextlib
import io
import os
import platform
import re
import subprocess

from . import backups_manager_lib
from . import backups_main
from . import lib

from .test_util import AssertEquals
from .test_util import AssertLinesEqual
from .test_util import CreateDir
from .test_util import CreateFile
from .test_util import DoBackupsMain


def CreateConfig(parent_dir, backups_filename_prefix='backups', filter_merge_path=None):
  config_path = os.path.join(parent_dir, '%s.config' % backups_filename_prefix)
  config = backups_manager_lib.BackupsConfig(config_path)
  if platform.system() == lib.PLATFORM_LINUX:
    config.image_path = os.path.join(parent_dir, '%s.img' % backups_filename_prefix)
  else:
    config.image_path = os.path.join(parent_dir, '%s.sparsebundle' % backups_filename_prefix)
  config.mount_path = os.path.join(parent_dir, '%s_mount' % backups_filename_prefix)
  config.src_path = CreateDir(parent_dir, '%s_src' % backups_filename_prefix)
  config.checkpoints_dir = CreateDir(parent_dir, '%s_checkpoints' % backups_filename_prefix)
  config.filter_merge_path = filter_merge_path
  config.Write()
  return config


def CreateBackupsBundle(config, create_example_content=True):
  lib.CreateDiskImage(config.image_path, size='1gb', volume_name='Backups')
  with lib.ImageAttacher(config.image_path, config.mount_path, readonly=False,
                         browseable=False) as attacher:
    backups_dir = CreateDir(attacher.GetMountPoint(), backups_manager_lib.BACKUPS_SUBDIR)
    backup1_dir = CreateDir(backups_dir, '2020-01-01-120000')
    CreateDir(backup1_dir, '.metadata')
    disk_dir = CreateDir(backup1_dir, 'Root')
    if create_example_content:
      CreateFile(disk_dir, 'f1')
      CreateFile(disk_dir, 'fX')
      CreateFile(disk_dir, 'fT')


def CreateLatestManifestCheckpoint(config):
  backups_manager = backups_manager_lib.BackupsManager.Open(
    config, readonly=False, browseable=False)
  try:
    last_backup = backups_manager.GetLastDone()
    src_root = last_backup.GetContentRootPath()
    output_lines = DoBackupsMain(['create-checkpoint',
                                  '--src-root', src_root,
                                  '--checksum-all',
                                  '--manifest-only',
                                  '--no-encrypt',
                                  '--checkpoint-name', last_backup.GetName(),
                                  '--checkpoints-dir', config.checkpoints_dir],
                                 expected_output=None)
    m = re.match('^Created checkpoint at (.+)$', output_lines[-1])
    assert m
    checkpoint_path = m.group(1)
    AssertLinesEqual(output_lines[:-1],
                     ['>d+++++++ .',
                      '>f+++++++ f1',
                      '>f+++++++ fT',
                      '>f+++++++ fX',
                      'Transferring 4 paths (0b)'])

    manifest = lib.ReadManifestFromImageOrPath(checkpoint_path)
    manifest.SetPath(last_backup.GetManifestPath())
    manifest.Write()

    return checkpoint_path
  finally:
    backups_manager.Close()


def VerifyBackupManifest(backup, path=None):
  if path is None:
    manifest = lib.Manifest.Load(backup.GetManifestPath())
  else:
    manifest = lib.ReadManifestFromImageOrPath(path)

  output = io.StringIO()
  verifier = lib.ManifestVerifier(manifest, backup.GetContentRootPath(), output,
                                  checksum_path_matcher=lib.PathMatcherAll())
  success = verifier.Verify()
  output_lines = [ line for line in output.getvalue().strip().split('\n') if line ]
  output.close()
  AssertLinesEqual(output_lines, [])
  if not success:
    raise Exception('Verification failed')


@contextlib.contextmanager
def SetLogThrottlerLogAlways(log_throttler):
  old_value = log_throttler.GetLogAlways()
  log_throttler.SetLogAlways(True)
  try:
    yield
  finally:
    log_throttler.SetLogAlways(old_value)


def DoCreateCheckpoint(src_root, checkpoints_dir, checkpoint_name, expected_output=[],
                       last_checkpoint_path=None, filter_merge_path=None):
  args = ['create-checkpoint',
          '--no-encrypt',
          '--checksum-all',
          '--src-root', src_root,
          '--checkpoints-dir', checkpoints_dir,
          '--checkpoint-name', checkpoint_name]
  if last_checkpoint_path is not None:
    args.extend(['--last-checkpoint', last_checkpoint_path])
  if filter_merge_path is not None:
    args.extend(['--filter-merge-path', filter_merge_path])
  output = io.StringIO()
  AssertEquals(backups_main.Main(args, output), True)
  output_lines = []
  checkpoint_path = None
  for line in output.getvalue().strip().split('\n'):
    m = re.match('^Created checkpoint at (.+)$', line)
    if m:
      checkpoint_path = m.group(1)
      continue
    output_lines.append(line)
  output.close()
  AssertLinesEqual(output_lines, expected_output)
  return checkpoint_path


def DoCreateBackup(config, backup_name=None, dry_run=False, expected_output=[]):
  cmd_args = ['create-backup',
              '--no-encrypt',
              '--backups-config', config.path]
  if backup_name is not None:
    cmd_args.extend(['--backup-name', backup_name])
  lines = DoBackupsMain(cmd_args, dry_run=dry_run, expected_output=None)
  checkpoint_path = None
  output_lines = []
  for line in lines:
    m = re.match('^Created checkpoint at (.+)$', line)
    if m:
      checkpoint_path = m.group(1)
      continue
    output_lines.append(line)
  AssertLinesEqual(output_lines, expected_output)
  return checkpoint_path


def DoApplyToBackups(config, dry_run=False, deduplicate_min_file_size=1024,
                     checksum_all=True, checksum_hardlinks=True, expected_success=True,
                     expected_output=[]):
  cmd_args = ['apply-to-backups',
              '--backups-config', config.path,
              '--deduplicate-min-file-size', str(deduplicate_min_file_size)]
  if not checksum_all:
    cmd_args.append('--no-checksum-all')
  if not checksum_hardlinks:
    cmd_args.append('--no-checksum-hardlinks')
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoListBackups(config, dry_run=False, expected_backups=[]):
  cmd_args = ['list-backups',
              '--backups-config', config.path]
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_output=expected_backups)


def DoVerifyBackups(config, dry_run=False, min_backup=None, max_backup=None,
                    full=True, continue_on_error=False, checksum_all=True,
                    expected_success=True, expected_output=[]):
  cmd_args = ['verify-backups',
              '--backups-config', config.path]
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  if not full:
    cmd_args.append('--no-full')
  if continue_on_error:
    cmd_args.append('--continue-on-error')
  if not checksum_all:
    cmd_args.append('--no-checksum-all')
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoAddMissingManifestsToBackups(config, expected_output=[]):
  cmd_args = ['add-missing-manifests-to-backups',
              '--backups-config', config.path]
  DoBackupsMain(cmd_args, expected_output=expected_output)


def DoDeduplicateBackups(
    config, min_backup=None, max_backup=None, match_older_mtimes=False, dry_run=False, verbose=False,
    expected_output=[]):
  cmd_args = ['deduplicate-backups',
              '--min-file-size', '1024',
              '--backups-config', config.path]
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  if match_older_mtimes:
    cmd_args.append('--match-older-mtimes')
  DoBackupsMain(cmd_args, dry_run=dry_run, verbose=verbose, expected_output=expected_output)


def DoCloneBackup(config, backup_name, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['clone-backup',
              '--backups-config', config.path,
              '--backup-name', backup_name]
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoDeleteBackups(config, backup_names, dry_run=False, expected_success=True, expected_output=[]):
  cmd_args = ['delete-backups',
              '--backups-config', config.path]
  for backup_name in backup_names:
    cmd_args.extend(['--backup-name', backup_name])
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoDeleteBackupsInteractive(config, backup_names=[], min_backup=None, max_backup=None,
                               ignore_matching_renames=False, include_latest_backup=False,
                               dry_run=False, verbose=False,
                               expected_success=True, expected_output=[]):
  cmd_args = ['delete-backups-interactive',
              '--backups-config', config.path]
  for backup_name in backup_names:
    cmd_args.extend(['--backup-name', backup_name])
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  if ignore_matching_renames:
    cmd_args.append('--ignore-matching-renames')
  if include_latest_backup:
    cmd_args.append('--include-latest-backup')
  DoBackupsMain(cmd_args, dry_run=dry_run, verbose=verbose, expected_success=expected_success,
                expected_output=expected_output)


def DoDumpUniqueFilesInBackups(config, backup_names=[], min_backup=None, max_backup=None,
                               ignore_matching_renames=False, match_previous_only=False,
                               match_next_only=False, dry_run=False, verbose=False,
                               expected_success=True, expected_output=[]):
  cmd_args = ['dump-unique-files-in-backups',
              '--backups-config', config.path]
  for backup_name in backup_names:
    cmd_args.extend(['--backup-name', backup_name])
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  if ignore_matching_renames:
    cmd_args.append('--ignore-matching-renames')
  if match_previous_only:
    cmd_args.append('--match-previous-only')
  if match_next_only:
    cmd_args.append('--match-next-only')
  DoBackupsMain(cmd_args, dry_run=dry_run, verbose=verbose, expected_success=expected_success,
                expected_output=expected_output)


def DoExtractFromBackups(config, dry_run=False, min_backup=None, max_backup=None,
                         output_image_path=None, paths=[], expected_success=True,
                         expected_output=[]):
  cmd_args = ['extract-from-backups',
              '--backups-config', config.path,
              '--no-encrypt',
              '--deduplicate-min-file-size', '1024']
  if output_image_path is not None:
    cmd_args.extend(['--output-image-path', output_image_path])
  for path in paths:
    cmd_args.extend(['--path', path])
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoMergeIntoBackups(config, dry_run=False, min_backup=None, max_backup=None,
                       from_image_path=None, expected_success=True,
                       expected_output=[]):
  cmd_args = ['merge-into-backups',
              '--backups-config', config.path,
              '--deduplicate-min-file-size', '1024']
  if from_image_path is not None:
    cmd_args.extend(['--from-image-path', from_image_path])
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)


def DoDeleteInBackups(config, dry_run=False, min_backup=None, max_backup=None,
                      paths=[], expected_success=True, expected_output=[]):
  cmd_args = ['delete-in-backups',
              '--backups-config', config.path]
  if min_backup is not None:
    cmd_args.extend(['--min-backup', min_backup])
  if max_backup is not None:
    cmd_args.extend(['--max-backup', max_backup])
  for path in paths:
    cmd_args.extend(['--path', path])
  DoBackupsMain(cmd_args, dry_run=dry_run, expected_success=expected_success,
                expected_output=expected_output)
