#!/usr/bin/env python -u

#   Mosh: the mobile shell
#   Copyright 2012 Keith Winstein
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

MOSH_VERSION = '1.1.3'

import sys, os, re, errno
import getopt
import socket
import signal
import subprocess, pipes, pty
import fcntl, termios, posix

def shell_quote(*x):
    return ' '.join("'%s'" % a.replace("'", "'\\''") for a in x)

def die(x):
    print x
    exit(255)

client = 'mosh-client'
server = 'mosh-server'
predict = None
port_request = None
help = None
version = None
fake_proxy = None

usage = """Usage: %s [options] [--] [user@]host [command...]
        --client=PATH        mosh client on local machine
                                (default: "mosh-client")
        --server=PATH        mosh server on remote machine
                                (default: "mosh-server")

        --predict=adaptive   local echo for slower links [default]
-a      --predict=always     use local echo even on fast links
-n      --predict=never      never use local echo

-p NUM  --port=NUM           server-side UDP port

        --help               this message
        --version            version and copyright information

Please report bugs to mosh-devel@mit.edu.
Mosh home page: http://mosh.mit.edu""" % sys.argv[0]

version_message = """mosh %s
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.""" % MOSH_VERSION

def predict_check(predict, env_set):
    if not predict in ['adaptive', 'always', 'never']:
        explanation = " (MOSH_PREDICTION_DISPLAY in environment)" if env_set else ""
        print >>sys.stderr, '%s: Unknown mode "%s"%s.\n' % (sys.argv[0], predict, explanation)
        die(usage)

args = sys.argv[1:]
try:
    optlist, args = getopt.gnu_getopt(sys.argv[1:], 'anp:', ['client=', 'server=', 'predict=', 'port=', 'help', 'version', 'fake-proxy!'])
except getopt.GetoptError, err:
    die('%s\n%s' % (err, usage))

for opt, arg in optlist:
    if opt=='--client':                 client = arg
    elif opt=='--server':               server = arg
    elif opt=='--predict':              predict = arg
    elif opt=='--port' or opt=='-p':    port_request = arg
    elif opt=='-a':                     predict = 'always'
    elif opt=='-n':                     predict = 'never'
    elif opt=='--help':                 help = True
    elif opt=='--version':              version = True
    elif opt=='--fake-proxy!':          fake_proxy = True

if help: die(usage)
if version: die(version_message)

ENV = os.environ

if predict:
    predict_check(predict, 0)
elif 'MOSH_PREDICTION_DISPLAY' in ENV:
    predict = ENV['MOSH_PREDICTION_DISPLAY']
    predict_check(predict, 1)
else:
    predict = 'adaptive'
    predict_check(predict, 0)

if port_request:
    if re.match(r'^[0-9]+$', port_request) \
        and int(port_request) >= 0 \
        and int(port_request) <= 65535:
        pass # good port
    else:
        die("%s: Server-side port (%s) must be within valid range [0..65535]." % (sys.argv[0], port_request))

if 'MOSH_PREDICTION_DISPLAY' in ENV: del ENV['MOSH_PREDICTION_DISPLAY']

if fake_proxy:
    host, port = args

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        die("%s: Could not resolve hostname %s" % (sys.argv[0], host))

    print >>sys.stderr, "MOSH IP %s" % ip

    # Act like netcat
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.connect((ip, int(port)))
    except socket.error, err:
        die("%s: connect to host %s port %s: %s" % (sys.argv[0], ip, port, str(err)))

    def cat(I, O):
        while 1:
            try:
                buf = posix.read(I.fileno(), 4096)
                if buf is None or len(buf) == 0: break
            except IOError, err:
                if err.errno == errno.EINTR: continue
            try:
                posix.write(O.fileno(), buf)
            except:
                break

    try:
        pid = os.fork()
    except OSError, err:
        die("%s: fork: %s" % (sys.argv[0], str(err)))
    if pid == 0:
        cat(sock, sys.stdout); sock.shutdown(0)
        exit(0)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    cat(sys.stdin, sock); sock.shutdown(1)
    os.waitpid(pid, 0)
    exit(0)

if len(args) < 1:
    die(usage)

userhost, args = args[0], args[1:]
command = args

# Run SSH and read password
pty, pty_slave = map(os.fdopen, os.openpty())

fcntl.ioctl(pty_slave.fileno(), termios.TIOCSWINSZ, fcntl.ioctl(0, termios.TIOCGWINSZ, ' '*4))

# Count colors
colors = ""
try:
    colors = subprocess.Popen([client, '-c'], stdout=subprocess.PIPE).communicate()[0].split('\n')[0].strip()
except OSError, err:
    die("Can't count colors: %s" % str(err))

if not re.match(r'^[0-9]+$', colors) or int(colors) < 0:
    colors = '0'

try:
    pid = os.fork()
except OSError, err:
    die("%s: fork: %s" % (sys.argv[0], str(err)))

if pid == 0:
    pty.close()
    try:
        os.dup2(pty_slave.fileno(), 1)
        os.dup2(pty_slave.fileno(), 2)
    except OSError, err:
        die(err)
    pty_slave.close()

    server_args = ['new', '-s', '-c', colors] + (['-p', port_request] if port_request else []) + ((['--'] + command) if len(command) else [])

    quoted_self = shell_quote(sys.argv[0])
    try:
        os.execvpe('ssh', ['ssh', '-S', 'none', '-o', "ProxyCommand=%s --fake-proxy -- %%h %%p" % quoted_self,
                           '-t', userhost, '--', server + ' ' + shell_quote(*server_args)], ENV)
    except OSError, err:
        die("Cannot exec ssh: %s" % err)

ip, port, key = None, None, None
pty_slave.close()
for line in pty:
    line = line.strip()
    if re.match(r'^MOSH IP ', line):
        match = re.match(r'^MOSH IP (\S+)\s*$', line) or die("Bad MOSH IP string: %s" % line)
        ip = match.group(1)
    elif re.match(r'^MOSH CONNECT ', line):
        match = re.match(r'^MOSH CONNECT (\d+?) ([A-Za-z0-9/+]{22})\s*$', line) or die("Bad MOSH CONNECT string: %s" % line)
        port, key = match.group(1), match.group(2)
        break
    else:
        print line
os.waitpid(pid, 0)

if ip is None:
    die("%s: Did not find remote IP address (is SSH ProxyCommand disabled?)." % sys.argv[0])

if key is None or port is None:
    die("%s: Did not find mosh server startup message." % sys.argv[0])

# Now start real mosh client
ENV['MOSH_KEY'] = key
ENV['MOSH_PREDICTION_DISPLAY'] = predict
os.execvpe(client, [client, ip, port], ENV)
