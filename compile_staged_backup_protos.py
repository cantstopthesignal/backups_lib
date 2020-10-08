#!/usr/bin/python -B

import argparse, subprocess, sys, os


STAGED_BACKUP_PROTO_FILENAME = 'staged_backup.proto'


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  args = parser.parse_args()

  lib_dir = os.path.dirname(sys.argv[0])
  proto_file_path = os.path.join(lib_dir, STAGED_BACKUP_PROTO_FILENAME)

  subprocess.check_call([
    'protoc',
    '-I=%s' % lib_dir,
    '--python_out=%s' % lib_dir,
    proto_file_path])
