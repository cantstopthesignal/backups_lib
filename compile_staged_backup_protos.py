#!/usr/bin/env -S python3 -u -B

import argparse
import os
import re
import subprocess
import sys


STAGED_BACKUP_PROTO_FILENAME = 'staged_backup.proto'


def GetProtocVersion(protoc_bin):
  output = subprocess.check_output([protoc_bin, '--version'], text=True).strip()
  m = re.search(r'libprotoc\s+(\d+)\.(\d+)(?:\.(\d+))?', output)
  if not m:
    raise ValueError('Could not parse protoc version from %r' % output)
  major = int(m.group(1))
  minor = int(m.group(2))
  patch = int(m.group(3)) if m.group(3) is not None else 0
  return (major, minor, patch), output


def CheckProtocVersion(protoc_bin, force=False):
  version_tuple, version_str = GetProtocVersion(protoc_bin)
  major = version_tuple[0]
  if major != 3:
    msg = (
      'protoc version %r is too new (%s). Expected protoc 3.x (e.g. 3.19.4 or 3.20.x) '
      'to ensure generated code remains compatible with older protobuf runtimes. '
      'Specify a compatible protoc binary with --protoc=<path> or pass --force to bypass.'
      % (version_str, protoc_bin)
    )
    if force:
      sys.stderr.write('WARNING: %s\n' % msg)
    else:
      raise ValueError(msg)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='Compile staged_backup.proto using a compatible protoc compiler.')
  parser.add_argument(
      '--protoc', default=os.environ.get('PROTOC', 'protoc'),
      help='Path to protoc binary (default: $PROTOC or protoc).')
  parser.add_argument(
      '--force', action='store_true',
      help='Allow compiling with an untested/newer protoc version.')
  args = parser.parse_args()

  try:
    CheckProtocVersion(args.protoc, force=args.force)
  except Exception as e:
    sys.exit('Error: %s' % e)

  lib_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
  proto_file_path = os.path.join(lib_dir, STAGED_BACKUP_PROTO_FILENAME)

  subprocess.check_call([
    args.protoc,
    '-I=%s' % lib_dir,
    '--python_out=%s' % lib_dir,
    proto_file_path])
