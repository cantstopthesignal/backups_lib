import argparse
import sys

from . import checksums_lib


COMMANDS = checksums_lib.COMMANDS


def Main(main_args=sys.argv[1:], output=sys.stdout):
  parser = argparse.ArgumentParser()
  parser.add_argument('--dry-run', action='store_true')
  parser.add_argument('--verbose', action='store_true')
  parser.add_argument('command', choices=COMMANDS)
  parser.add_argument('cmd_args', nargs=argparse.REMAINDER)
  args = parser.parse_args(main_args)

  if args.command in checksums_lib.COMMANDS:
    return checksums_lib.DoCommand(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
