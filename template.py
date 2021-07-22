#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path, PurePath
from wheezy.template.engine import Engine
from wheezy.template.ext.core import CoreExtension
from wheezy.template.ext.code import CodeExtension
from wheezy.template.loader import FileLoader
from pwn import *

parser = ArgumentParser(description='Generate an exploit template, according to libfuzzer\'s crash')

parser.add_argument('crash', nargs='?', help='Target crash report')
parser.add_argument('--exe', help='Target crash report')
parser.add_argument('--host', help='Remote host / SSH server')
parser.add_argument('--port', help='Remote port / SSH port', type=int)
parser.add_argument('--user', help='SSH Username')
parser.add_argument('--pass', '--password', help='SSH Password', dest='password')
parser.add_argument('--path', help='Remote path of file on SSH server')
parser.add_argument('--quiet', help='Less verbose template comments', action='store_true')
parser.add_argument('--color', help='Print the output in color', choices=['never', 'always', 'auto'], default='auto')

args = parser.parse_args()
def main ():
    # For the SSH scenario, check that the binary is at the
    # same path on the remote host.
    if args.user:
        if not (args.path or args.crash):
            log.error("Must specify --path or a crash")

        s = ssh(args.user, args.host, args.port or 22, args.password or None)

        try:
            remote_file = args.path or args.crash
            s.download(remote_file)
        except Exception:
            log.warning("Could not download file %r, opening a shell", remote_file)
            s.interactive()
            return
        if not args.crash:
            args.crash = PurePath(args.path).name

    searchpath = [str(Path().absolute()) + '/templates']
    engine = Engine(loader=FileLoader(searchpath), extensions=[CoreExtension(), CodeExtension()])
    template = engine.get_template('pwncrash.wheezy')
    output = template.render(vars(args))
    
    # Colorize the output if it's a TTY
    if args.color == 'always' or (args.color == 'auto' and sys.stdout.isatty()):
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pygments.lexers.python import PythonLexer
        output = highlight(output, PythonLexer(), TerminalFormatter())

    print(output)

    # If redirected to a file, make the resulting script executable
    if not sys.stdout.isatty():
        try: os.fchmod(sys.stdout.fileno(), 0o700)
        except OSError: pass

if __name__ == '__main__':
    main()