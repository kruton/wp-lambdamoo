/******************************************************************************
  Copyright (c) 1994, 1995, 1996 Xerox Corporation.  All rights reserved.
  Portions of this code were written by Stephen White, aka ghond.
  Use and copying of this software and preparation of derivative works based
  upon this software are permitted.  Any distribution of this software or
  derivative works must comply with all applicable United States export
  control laws.  This software is made available AS IS, and Xerox Corporation
  makes no warranty about the software, its performance or its conformity to
  any specification.  Any person obtaining a copy of this software is requested
  to send their name and post office or electronic mail address to:
    Pavel Curtis
    Xerox PARC
    3333 Coyote Hill Rd.
    Palo Alto, CA 94304
    Pavel@Xerox.Com
 *****************************************************************************/

/* This module provides IP host name lookup with timeouts.  Because
 * longjmps out of name lookups corrupt some UNIX name lookup modules, this
 * module uses a subprocess to do the name lookup.  On any failure, the
 * subprocess is restarted.
 */

#include "options.h"

#if NETWORK_PROTOCOL == NP_TCP	/* Skip almost entire file otherwise... */

#include "my-signal.h"
#include "my-stdlib.h"
#include "my-unistd.h"
#include "my-inet.h"		/* inet_addr() */
#include "my-in.h"		/* struct sockaddr_in, INADDR_ANY, htons(),
				   * htonl(), ntohl(), struct in_addr */
#include <netdb.h>		/* struct hostent, gethostbyaddr() */
#include "my-socket.h"		/* AF_INET */
#include "my-wait.h"
#include "my-string.h"
#include <errno.h>

#include "config.h"
#include "log.h"
#include "name_lookup.h"
#include "server.h"
#include "storage.h"
#include "timers.h"

/******************************************************************************
 * Utilities
 *****************************************************************************/

static pid_t
spawn_pipe(void (*child_proc) (int to_parent, int from_parent),
	   int *to_child, int *from_child)
{
    int pipe_to_child[2], pipe_from_child[2];
    pid_t pid;

    if (pipe(pipe_to_child) < 0) {
	log_perror("SPAWNING: Couldn't create first pipe");
    } else if (pipe(pipe_from_child) < 0) {
	log_perror("SPAWNING: Couldn't create second pipe");
	close(pipe_to_child[0]);
	close(pipe_to_child[1]);
    } else if ((pid = fork()) < 0) {
	log_perror("SPAWNING: Couldn't fork middleman");
	close(pipe_to_child[0]);
	close(pipe_to_child[1]);
	close(pipe_from_child[0]);
	close(pipe_from_child[1]);
    } else if (pid != 0) {	/* parent */
	int status;

	close(pipe_to_child[0]);
	close(pipe_from_child[1]);
	*to_child = pipe_to_child[1];
	*from_child = pipe_from_child[0];

	/* Cast to (void *) to avoid warnings on systems that misdeclare the
	 * argument.
	 */
	wait((void *) &status);	/* wait for middleman to die */
	if (status != 0) {
	    errlog("SPAWNING: Middleman died with status %d!\n", status);
	    close(pipe_to_child[1]);
	    close(pipe_from_child[0]);
	} else if (read(*from_child, &pid, sizeof(pid)) != sizeof(pid)) {
	    errlog("SPAWNING: Bad read() for pid\n");
	    close(pipe_to_child[1]);
	    close(pipe_from_child[0]);
	} else {
	    return pid;
	}
    } else {			/* middleman */
	close(pipe_to_child[1]);
	close(pipe_from_child[0]);
	if ((pid = fork()) < 0) {
	    log_perror("SPAWNING: Couldn't fork child");
	    exit(1);
	} else if (pid != 0) {	/* still the middleman */
	    write(pipe_from_child[1], &pid, sizeof(pid));
	    exit(0);
	} else {		/* finally, the child */
	    (*child_proc) (pipe_from_child[1], pipe_to_child[0]);
	    exit(0);
	}
    }

    return 0;
}

static void
ensure_buffer(char **buffer, int *buflen, int len)
{
    if (len > *buflen) {
	if (*buffer)
	    myfree(*buffer, M_STRING);
	*buflen = len;
	*buffer = mymalloc(len, M_STRING);
    }
}

static int
robust_read(int fd, void *buffer, int len)
{
    int count;

    do {
	count = read(fd, buffer, len);
    } while (count == -1 && errno == EINTR);

    return count;
}

static int
get_sockaddr_len(struct sockaddr* addr)
{
    if (addr->sa_family == AF_INET6) {
	return sizeof(struct sockaddr_in6);
    } else {
	return sizeof(struct sockaddr_in);
    }
}

static struct sockaddr*
get_in_addr(struct sockaddr* addr)
{
    if (addr->sa_family == AF_INET6) {
	return &(((struct sockaddr_in6*) addr)->sin6_addr);
    } else {
	return &(((struct sockaddr_in*) addr)->sin_addr);
    }
}

/******************************************************************************
 * Data structures and types used by more than one process.
 *****************************************************************************/

struct request {
    enum {
	REQ_NAME_FROM_ADDR, REQ_ADDR_FROM_NAME
    } kind;
    unsigned timeout;
    unsigned length;
};

struct reply {
    unsigned length;
};

/******************************************************************************
 * Code that runs in the lookup process.
 *****************************************************************************/

static void
timeout_proc(Timer_ID id, Timer_Data data)
{
    _exit(1);
}

static void
lookup(int to_intermediary, int from_intermediary)
{
    struct request req;
    struct reply reply;
    static char *buffer = 0;
    static int buflen = 0;
    Timer_ID id;
    struct addrinfo hints, *res;
    struct sockaddr_storage addr;
    struct sockaddr* sa;
    char host_name[NI_MAXHOST];
    int rc;
    int replysize;

    set_server_cmdline("(MOO name-lookup slave)");
    /* Read requests and do them.  Before each, we set a timer.  If it
       expires, we exit (in timeout_proc, above).  The intermediary will
       restart us in that event. */
    for (;;) {
	if (robust_read(from_intermediary, &req, sizeof(req)) != sizeof(req))
	    _exit(1);
	ensure_buffer(&buffer, &buflen, req.length + 1);
	memset(buffer, '\0', buflen);
	if (robust_read(from_intermediary, buffer, req.length)
	    != req.length)
	    _exit(1);
	buffer[req.length] = 0;
	if (req.kind == REQ_ADDR_FROM_NAME) {
	    memset(&hints, 0, sizeof(hints));
	    hints.ai_family = PF_UNSPEC;
	    hints.ai_socktype = SOCK_STREAM;
	    id = set_timer(req.timeout, timeout_proc, 0);
	    rc = getaddrinfo(buffer, NULL, &hints, &res);
	    cancel_timer(id);
	    if (rc != 0) {
		reply.length = 0;
		write(to_intermediary, &reply, sizeof(reply));
	    } else {
		reply.length = res->ai_addrlen;
		write(to_intermediary, &reply, sizeof(reply));
		write(to_intermediary, res->ai_addr, reply.length);
		freeaddrinfo(res);
	    }
	} else {
	    sa = (struct sockaddr*) buffer;
	    id = set_timer(req.timeout, timeout_proc, 0);
	    rc = getnameinfo(sa, req.length, host_name, sizeof(host_name),
		    NULL, 0, NI_NAMEREQD);
	    cancel_timer(id);
	    if (rc != 0) {
		reply.length = 0;
		write(to_intermediary, &reply, sizeof(reply));
	    } else {
		reply.length = strlen(host_name);
		write(to_intermediary, &reply, sizeof(reply));
		write(to_intermediary, host_name, reply.length);
	    }
	}
    }
}

/******************************************************************************
 * Code that runs in the intermediary process.
 *****************************************************************************/

static int to_lookup, from_lookup;
static pid_t lookup_pid;

static void
restart_lookup(void)
{
    if (lookup_pid) {
	kill(lookup_pid, SIGKILL);
	close(to_lookup);
	close(from_lookup);
	oklog("NAME_LOOKUP: Killing old lookup process ...\n");
    }
    lookup_pid = spawn_pipe(lookup, &to_lookup, &from_lookup);
    if (lookup_pid)
	oklog("NAME_LOOKUP: Started new lookup process\n");
    else
	errlog("NAME_LOOKUP: Can't spawn lookup process; "
	       "will try again later...\n");
}

static void
intermediary(int to_server, int from_server)
{
    struct request req;
    struct reply reply;
    static char *buffer = 0;
    static int buflen = 0;

    set_server_cmdline("(MOO name-lookup master)");
    signal(SIGPIPE, SIG_IGN);
    restart_lookup();
    for (;;) {
	if (robust_read(from_server, &req, sizeof(req)) != sizeof(req))
	    _exit(1);
	ensure_buffer(&buffer, &buflen, req.length);
	if (robust_read(from_server, buffer, req.length) != req.length)
	    _exit(1);
	if (!lookup_pid)	/* Restart lookup if it's died */
	    restart_lookup();
	if (lookup_pid) {	/* Only try to deal with lookup if alive */
	    write(to_lookup, &req, sizeof(req));
	    write(to_lookup, buffer, req.length);
	    if (robust_read(from_lookup, &reply, sizeof(reply))
		!= sizeof(reply)) {
		restart_lookup();
		reply.length = 0;
	    } else {
		ensure_buffer(&buffer, &buflen, reply.length);
		if (reply.length > 0
		    && robust_read(from_lookup, buffer, reply.length) != reply.length) {
		    restart_lookup();
		    reply.length = 0;
		}
	    }
	    write(to_server, &reply, sizeof(reply));
	    if (reply.length > 0)
		write(to_server, buffer, reply.length);
	} else {		/* Lookup dead and wouldn't restart ... */
	    reply.length = 0;

	    write(to_server, &reply, sizeof(reply));
	}
    }
}


/******************************************************************************
 * Code that runs in the server process.
 *****************************************************************************/

static int to_intermediary, from_intermediary;
static int dead_intermediary = 0;


int
initialize_name_lookup(void)
{
    return spawn_pipe(intermediary, &to_intermediary, &from_intermediary);
}

static void
abandon_intermediary(const char *prefix)
{
    errlog("LOOKUP_NAME: %s; presumed dead...\n", prefix);
    dead_intermediary = 1;
    close(to_intermediary);
    close(from_intermediary);
}

const char *
lookup_name_from_addr(struct sockaddr* addr, unsigned timeout)
{
    struct request req;
    struct reply reply;
    static char *buffer = 0;
    static int buflen = 0;

    if (!dead_intermediary) {
	req.kind = REQ_NAME_FROM_ADDR;
	req.timeout = timeout;
	req.length = get_sockaddr_len(addr);
	if (write(to_intermediary, &req, sizeof(req)) != sizeof(req) ||
		write(to_intermediary, addr, req.length) != req.length)
	    abandon_intermediary("LOOKUP_NAME: Write to intermediary failed");
	else if (robust_read(from_intermediary, &reply, sizeof(reply))
		 != sizeof(reply))
	    abandon_intermediary("LOOKUP_NAME: Read from intermediary failed");
	else if (reply.length != 0) {
	    ensure_buffer(&buffer, &buflen, reply.length + 1);
	    if (robust_read(from_intermediary, buffer, reply.length)
		!= reply.length)
		abandon_intermediary("LOOKUP_NAME: "
				   "Data-read from intermediary failed");
	    else {
		buffer[reply.length] = '\0';
		return buffer;
	    }
	}
    }
    /* Either the intermediary is presumed dead, or else it failed to produce
     * a name; in either case, we must fall back on a the default, dotted-
     * decimal notation.
     */

    {
	static char str6[INET6_ADDRSTRLEN];
	inet_ntop(addr->sa_family, get_in_addr(addr), str6, INET6_ADDRSTRLEN);
	return str6;
    }
}

int
lookup_addr_from_name(const char *name, struct sockaddr* addr, unsigned timeout)
{
    struct request req;
    struct reply reply;

    if (dead_intermediary) {
	/* Numeric addresses should always work... */
	addr->sa_family = AF_INET6;
	return inet_pton(addr->sa_family, name, get_in_addr(addr));
    } else {
	req.kind = REQ_ADDR_FROM_NAME;
	req.timeout = timeout;
	req.length = strlen(name);
	if (write(to_intermediary, &req, sizeof(req)) != sizeof(req)
	    || write(to_intermediary, name, req.length) != req.length) {
	    abandon_intermediary("LOOKUP_ADDR: Write to intermediary failed");
	    return -1;
	} else if (robust_read(from_intermediary, &reply, sizeof(reply))
		 != sizeof(reply)) {
	    abandon_intermediary("LOOKUP_ADDR: Read from intermediary failed");
	    return -1;
	} else if (reply.length > 0
		 && robust_read(from_intermediary, addr, reply.length)
			!= reply.length) {
	    abandon_intermediary("LOOKUP_ADDR: Data-read from intermediary failed");
	    return -1;
	} else {
	    return 0;
	}
    }
}

#endif				/* NETWORK_PROTOCOL == NP_TCP */

char rcsid_name_lookup[] = "$Id$";

/* 
 * $Log$
 * Revision 1.3  1998/12/14 13:18:25  nop
 * Merge UNSAFE_OPTS (ref fixups); fix Log tag placement to fit CVS whims
 *
 * Revision 1.2  1997/03/03 04:19:00  nop
 * GNU Indent normalization
 *
 * Revision 1.1.1.1  1997/03/03 03:45:00  nop
 * LambdaMOO 1.8.0p5
 *
 * Revision 2.2  1996/02/08  06:59:04  pavel
 * Renamed err/logf() to errlog/oklog().  Updated copyright notice for 1996.
 * Release 1.8.0beta1.
 *
 * Revision 2.1  1995/12/11  08:11:45  pavel
 * Added missing #include of "my-stdlib.h".  Release 1.8.0alpha2.
 *
 * Revision 2.0  1995/11/30  04:28:09  pavel
 * New baseline version, corresponding to release 1.8.0alpha1.
 *
 * Revision 1.1  1995/11/30  04:27:56  pavel
 * Initial revision
 */
