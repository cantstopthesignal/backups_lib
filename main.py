import argparse
import sys

import backups_lib
import backups_oneoff_lib
import lib


COMMANDS = (lib.COMMANDS +
            backups_lib.COMMANDS +
            backups_oneoff_lib.COMMANDS)


def Main(main_args=sys.argv[1:], output=sys.stdout):
  parser = argparse.ArgumentParser()
  parser.add_argument('--dry-run', action='store_true')
  parser.add_argument('--verbose', action='store_true')
  parser.add_argument('command', choices=COMMANDS)
  parser.add_argument('cmd_args', nargs=argparse.REMAINDER)
  args = parser.parse_args(main_args)

  if args.command in lib.COMMANDS:
    return lib.DoCommand(args, output=output)
  elif args.command in backups_lib.COMMANDS:
    return backups_lib.DoCommand(args, output=output)
  elif args.command in backups_oneoff_lib.COMMANDS:
    return backups_oneoff_lib.DoCommand(args, output=output)

  print >>output, '*** Error: Unknown command %s' % args.command
  return False
