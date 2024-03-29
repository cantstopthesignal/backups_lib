import argparse
import sys

from . import backups_manager_lib
from . import backups_oneoff_lib
from . import checkpoint_lib
from . import legacy_backups_lib
from . import lib


COMMANDS = (lib.COMMANDS +
            checkpoint_lib.COMMANDS +
            backups_manager_lib.COMMANDS +
            backups_oneoff_lib.COMMANDS +
            legacy_backups_lib.COMMANDS)


def Main(main_args=sys.argv[1:], output=sys.stdout):
  parser = argparse.ArgumentParser()
  parser.add_argument('--dry-run', action='store_true')
  parser.add_argument('--verbose', action='store_true')
  parser.add_argument('command', choices=COMMANDS)
  parser.add_argument('cmd_args', nargs=argparse.REMAINDER)
  args = parser.parse_args(main_args)

  if args.command in lib.COMMANDS:
    return lib.DoCommand(args, output=output)
  elif args.command in backups_manager_lib.COMMANDS:
    return backups_manager_lib.DoCommand(args, output=output)
  elif args.command in backups_oneoff_lib.COMMANDS:
    return backups_oneoff_lib.DoCommand(args, output=output)
  elif args.command in checkpoint_lib.COMMANDS:
    return checkpoint_lib.DoCommand(args, output=output)
  elif args.command in legacy_backups_lib.COMMANDS:
    return legacy_backups_lib.DoCommand(args, output=output)

  print('*** Error: Unknown command %s' % args.command, file=output)
  return False
