//   Mosh: the mobile shell
//   Copyright 2012 Keith Winstein
//
//   This program is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "config.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#if HAVE_PTY_H
#include <pty.h>
#elif HAVE_UTIL_H
#include <util.h>
#endif

#if OPENPTY_IN_LIBUTIL
#include <libutil.h>
#endif

#if !HAVE_GETLINE
ssize_t getline( char ** restrict linep,
    size_t * restrict linecapp,
    FILE * restrict stream ) {
  size_t num_read = 0;
  if ( !linep || !linecapp ) {
    errno = EINVAL;
    return -1;
  }
  if ( !*linep ) {
    *linecapp = 0;
  }
  while ( 1 ) {
    int ch = getc( stream );
    if ( ch == EOF ) {
      return num_read ? (ssize_t)num_read : -1;
    }
    if ( num_read + 1 >= *linecapp ) {
      char *new_line = *linep;
      size_t new_linecap = *linecapp;
      if ( *linecapp > SSIZE_MAX - 4096 ) {
        errno = EOVERFLOW;
        return -1;
      }
      new_linecap += 4096;
      new_line = (char *)realloc( new_line, new_linecap );
      if ( !new_line ) {
        return -1;
      }
      *linecapp = new_linecap;
      *linep = new_line;
    }
    (*linep)[num_read++] = ch;
    // so that we can safely return at any time,
    (*linep)[num_read] = '\0';
    if (ch == '\n') {
      return num_read;
    }
  }
  return -1;
}
#endif

using namespace std;

inline string shell_quote_string( const string &x )
{
  string result = "'";
  string rest = x;
  while ( rest.size() ) {
    size_t good_part = rest.find( "'" );
    result += rest.substr( 0, good_part );
    if ( good_part != string::npos ) {
      result += "'\\''";
      rest = rest.substr( good_part + 1 );
    } else {
      break;
    }
  }
  return result + "'";
}

template <typename SequenceT>
inline string shell_quote( const SequenceT &sequence )
{
  string result;
  for ( typename SequenceT::const_iterator i = sequence.begin();
        i != sequence.end();
        i++ ) {
    result += shell_quote_string( *i ) + " ";
  }
  return result.substr( 0, result.size() - 1 );
}

void die( const char *format, ... ) {
  va_list args;
  va_start( args, format );
  vfprintf( stderr, format, args );
  va_end( args );
  fprintf( stderr, "\n" );
  exit( 255 );
}

static const char *usage_format =
"Usage: %s [options] [--] [user@]host [command...]\n"
"        --client=PATH        mosh client on local machine\n"
"                                (default: mosh-client)\n"
"        --server=PATH        mosh server on remote machine\n"
"                                (default: mosh-server)\n"
"\n"
"        --predict=adaptive   local echo for slower links [default]\n"
"-a      --predict=always     use local echo even on fast links\n"
"-n      --predict=never      never use local echo\n"
"\n"
"-p NUM  --port=NUM           server-side UDP port\n"
"\n"
"        --ssh=COMMAND        ssh command to run when setting up session\n"
"                                (example: \"ssh -p 2222\")\n"
"                                (default: \"ssh\")\n"
"\n"
"        --help               this message\n"
"        --version            version and copyright information\n"
"\n"
"Please report bugs to mosh-devel@mit.edu.\n"
"Mosh home page: http://mosh.mit.edu";

static const char *version_format =
"mosh %s\n"
"Copyright 2012 Keith Winstein <mosh-devel@mit.edu>\n"
"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
"This is free software: you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.";

static const char *key_valid_char_set =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

static char *argv0;

void predict_check( const string &predict, bool env_set )
{
  if ( predict != "adaptive" &&
       predict != "always" &&
       predict != "never" ) {
    fprintf( stderr, "%s: Unknown mode \"%s\"%s.\n", argv0, predict.c_str(),
        env_set ? " (MOSH_PREDICTION_DISPLAY in environment)" : "" );
    die( usage_format, argv0 );
  }
}

void cat( int ifd, int ofd )
{
  char buf[4096];
  ssize_t n;
  while ( 1 ) {
    n = read( ifd, buf, sizeof( buf ) );
    if ( n==-1 ) {
      if (errno == EINTR ) {
        continue;
      }
      break;
    }
    if ( n==0 ) {
      break;
    }
    n = write( ofd, buf, n );
    if ( n==-1 ) {
      break;
    }
  }
}

int main( int argc, char *argv[] )
{
  argv0 = argv[0];
  string client = "mosh-client";
  string server = "mosh-server";
  string ssh = "ssh";
  string predict, port_request;
  int help=0, version=0, fake_proxy=0;

  static struct option long_options[] =
  {
    { "client",      required_argument,  0,              'c' },
    { "server",      required_argument,  0,              's' },
    { "predict",     required_argument,  0,              'r' },
    { "port",        required_argument,  0,              'p' },
    { "ssh",         required_argument,  0,              'S' },
    { "help",        no_argument,        &help,           1  },
    { "version",     no_argument,        &version,        1  },
    { "fake-proxy!", no_argument,        &fake_proxy,     1  },
    { 0, 0, 0, 0 }
  };
  while ( 1 ) {
    int option_index = 0;
    int c = getopt_long( argc, argv, "anp:",
        long_options, &option_index );
    if ( c == -1 ) {
      break;
    }

    switch ( c ) {
      case 0:
        // flag has been set
        break;
      case 'c':
        client = optarg;
        break;
      case 's':
        server = optarg;
        break;
      case 'r':
        predict = optarg;
        break;
      case 'p':
        port_request = optarg;
        break;
      case 'S':
        ssh = optarg;
        break;
      case 'a':
        predict = "always";
        break;
      case 'n':
        predict = "never";
        break;
      default:
        die( usage_format, argv[0] );
    }
  }

  if ( help ) {
    die( usage_format, argv[0] );
  }
  if ( version ) {
    die( version_format, PACKAGE_VERSION );
  }

  if ( predict.size() ) {
    predict_check( predict, 0 );
  } else if ( getenv( "MOSH_PREDICTION_DELAY" ) ) {
    predict = getenv( "MOSH_PREDICTION_DELAY" );
    predict_check( predict, 1 );
  } else {
    predict = "adaptive";
    predict_check( predict, 0 );
  }

  if ( port_request.size() ) {
    if ( port_request.find_first_not_of( "0123456789" ) != string::npos ||
         atoi( port_request.c_str() ) < 0 ||
         atoi( port_request.c_str() ) > 65535 ) {
      die( "%s: Server-side port (%s) must be within valid range [0..65535].",
           argv[0],
           port_request.c_str() );
    }
  }

  unsetenv( "MOSH_PREDICTION_DISPLAY" );

  if ( fake_proxy ) {
    string host = argv[optind++];
    string port = argv[optind++];

    int sockfd = -1;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ( ( rv = getaddrinfo( host.c_str(),
                             port_request.size() ? port_request.c_str() : "ssh",
                             &hints,
                             &servinfo ) ) != 0 ) {
      die( "%s: Could not resolve hostname %s: getaddrinfo: %s",
           argv[0],
           host.c_str(),
           gai_strerror( rv ) );
    }

    // loop through all the results and connect to the first we can
    for ( p = servinfo; p != NULL; p = p->ai_next ) {
      if ( ( sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) == -1 ) {
        continue;
      }

      if ( connect( sockfd, p->ai_addr, p->ai_addrlen ) == -1 ) {
        close( sockfd );
        continue;
      }

      char host[NI_MAXHOST], service[NI_MAXSERV];
      if ( getnameinfo( p->ai_addr, p->ai_addrlen,
            host, NI_MAXHOST,
            service, NI_MAXSERV,
            NI_NUMERICSERV | NI_NUMERICHOST ) == -1 ) {
        die( "Couldn't get host name info" );
      }

      fprintf( stderr, "MOSH IP %s\n", host );
      break; // if we get here, we must have connected successfully
    }

    if ( p == NULL ) {
      // looped off the end of the list with no connection
      die( "%s: failed to connect to host %s port %s",
            argv[0], host.c_str(), port.c_str() );
    }

    freeaddrinfo( servinfo ); // all done with this structure

    int pid = fork();
    if ( pid == -1 ) {
      die( "%s: fork: %d", argv[0], errno );
    }
    if ( pid == 0 ) {
      cat( sockfd, 1 );
      shutdown( sockfd, 0 );
      exit( 0 );
    }
    signal( SIGHUP, SIG_IGN );
    cat( 0, sockfd );
    shutdown( sockfd, 1 );
    waitpid( pid, NULL, 0 );
    exit( 0 );
  }

  if ( argc - optind < 1 ) {
    die( usage_format, argv[0] );
  }

  string userhost = argv[optind++];
  char **command = &argv[optind];
  int commands = argc - optind;

  int pipe_fd[2];
  if ( pipe( pipe_fd ) < 0 ) {
    die( "%s: pipe: %d", argv[0], errno );
  }

  string color_invocation = client + " -c";
  FILE *color_file = popen( color_invocation.c_str(), "r" );
  if ( !color_file ) {
    die( "%s: popen: %d", argv[0], errno );
  }
  char *buf = NULL;
  size_t buf_sz = 0;
  ssize_t n;
  if ( ( n = getline( &buf, &buf_sz, color_file ) ) < 0 ) {
    die( "%s: Can't count colors: %d", argv[0], errno );
  }
  string colors = string( buf, n );
  pclose( color_file );

  if ( !colors.size() ||
       colors.find_first_not_of( "0123456789" ) != string::npos ||
       atoi( colors.c_str() ) < 0 ) {
    colors = "0";
  }

  int pty, pty_slave;
  struct winsize ws;
  if ( ioctl( 0, TIOCGWINSZ, &ws ) == -1 ) {
    die( "%s: ioctl: %d", argv[0], errno );
  }

  if ( openpty( &pty, &pty_slave, NULL, NULL, &ws ) == -1 ) {
    die( "%s: openpty: %d", argv[0], errno );
  }

  int pid = fork();
  if ( pid == -1 ) {
    die( "%s: fork: %d", argv[0], errno );
  }
  if ( pid == 0 ) {
    close( pty );
    if ( -1 == dup2( pty_slave, 1 ) ||
         -1 == dup2( pty_slave, 2 ) ) {
      die( "%s: dup2: %d", argv[0], errno );
    }
    close( pty_slave );

    vector<string> server_args;
    server_args.push_back( "new" );
    server_args.push_back( "-s" );
    server_args.push_back( "-c" );
    server_args.push_back( colors );
    if ( port_request.size() ) {
      server_args.push_back( "-p" );
      server_args.push_back( port_request );
    }
    if ( commands ) {
      server_args.insert( server_args.end(), command, command + commands );
    }
    string quoted_self = shell_quote_string( string( argv[0] ) );
    string quoted_server_args = shell_quote( server_args );
    fflush( stdout );

    string proxy_arg = "ProxyCommand=" + quoted_self + " --fake-proxy -- %h %p";
    string ssh_remote_command = server + " " + quoted_server_args;

    vector<string> ssh_args;
    ssh_args.push_back( "-S" );
    ssh_args.push_back( "none" );
    ssh_args.push_back( "-o" );
    ssh_args.push_back( proxy_arg );
    ssh_args.push_back( "-t" );
    ssh_args.push_back( userhost );
    ssh_args.push_back( "--" );
    ssh_args.push_back( ssh_remote_command );

    string ssh_exec_string = ssh + " " + shell_quote( ssh_args );

    int ret = execlp( "sh", "sh", "-c", ssh_exec_string.c_str(), (char *)NULL );
    if ( ret == -1 ) {
      die( "Cannot exec ssh: %d", errno );
    }
  }

  close( pty_slave );
  string ip, port, key;

  FILE *pty_file = fdopen( pty, "r" );
  string line;
  while ( ( n = getline( &buf, &buf_sz, pty_file ) ) >= 0 ) {
    line = string( buf, n );
    line = line.erase( line.find_last_not_of( "\n" ) );
    if ( line.compare( 0, 8, "MOSH IP " ) == 0 ) {
      size_t ip_end = line.find_last_not_of( " \t\n\r" );
      if ( ip_end != string::npos && ip_end >= 8 ) {
        ip = line.substr( 8, ip_end + 1 - 8 );
      }
    } else if ( line.compare( 0, 13, "MOSH CONNECT " ) == 0 ) {
      size_t port_end = line.find_first_not_of( "0123456789", 13 );
      if ( port_end != string::npos && port_end >= 13 ) {
        port = line.substr( 13, port_end - 13 );
      }
      string rest = line.substr( port_end + 1 );
      size_t key_end = rest.find_last_not_of( " \t\n\r" );
      size_t key_valid_end = rest.find_last_of( key_valid_char_set );
      if ( key_valid_end == key_end && key_end + 1 == 22 ) {
        key = rest.substr( 0, key_end + 1 );
      }
      break;
    } else {
      printf( "%s\n", line.c_str() );
    }
  }
  waitpid( pid, NULL, 0 );

  if ( !ip.size() ) {
    die( "%s: Did not find remote IP address (is SSH ProxyCommand disabled?).",
         argv[0] );
  }

  if ( !key.size() || !port.size() ) {
    die( "%s: Did not find mosh server startup message.", argv[0] );
  }

  setenv( "MOSH_KEY", key.c_str(), 1 );
  setenv( "MOSH_PREDICTION_DISPLAY", predict.c_str(), 1 );
  execlp( client.c_str(), client.c_str(), ip.c_str(), port.c_str(), (char *)NULL );
}
