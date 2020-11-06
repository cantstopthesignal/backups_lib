import argparse


COMMAND_VERIFY = 'verify'
COMMAND_SYNC = 'sync'

COMMANDS = [
  COMMAND_VERIFY,
  COMMAND_SYNC
]


def DoVerify(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  parser.add_argument('--checksum-all', action='store_true')
  cmd_args = parser.parse_args(args.cmd_args)

  print >>output, 'Not implemented'
  return False


def DoSync(args, output):
  parser = argparse.ArgumentParser()
  parser.add_argument('root_path')
  cmd_args = parser.parse_args(args.cmd_args)


  print >>output, 'Not implemented'
  return False


def DoCommand(args, output):
  if args.command == COMMAND_VERIFY:
    return DoVerify(args, output=output)
  elif args.command == COMMAND_SYNC:
    return DoSync(args, output=output)

  print >>output, '*** Error: Unknown command %s' % args.command
  return False
