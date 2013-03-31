/************
 * net_tcp.c
 *
 * common code for
 * multi-user networking protocol implementations for TCP/IP 
 * (net_bsd_tcp.c and net_sysv_tcp.c)
 *
 */

#include <netdb.h>

#ifdef OUTBOUND_NETWORK
static char outbound_network_enabled = OUTBOUND_NETWORK;
#endif

static struct addrinfo *bind_addr;

const char *
proto_usage_string(void)
{
    return "[+O|-O] [-a ip_address] [[-p] port]";
}


static int
tcp_arguments(int argc, char **argv, int *pport)
{
    struct addrinfo hints;
    char *host = NULL;
    char *p = 0;
    char *portstr;
    int rc;

    for ( ; argc > 0; argc--, argv++) {
	if (argc > 0
	    && (argv[0][0] == '-' || argv[0][0] == '+')
	    && argv[0][1] == 'O'
	    && argv[0][2] == 0
	    ) {
#ifdef OUTBOUND_NETWORK
	    outbound_network_enabled = (argv[0][0] == '+');
#else
	    if (argv[0][0] == '+') {
		fprintf(stderr, "Outbound network not supported.\n");
		oklog("CMDLINE: *** Ignoring %s (outbound network not supported)\n", argv[0]);
	    }
#endif
	}
	else if (0 == strcmp(argv[0],"-a")) {
            if (argc <= 1)
                return 0;
            argc--;
            argv++;
            host = argv[0];
	    oklog("CMDLINE: Source address restricted to %s\n", argv[0]);
        }
        else {
            if (p != 0) /* strtoul always sets p */
                return 0;
            if (0 == strcmp(argv[0],"-p")) {
                if (argc <= 1)
                    return 0;
                argc--;
                argv++;
            }
            *pport = strtoul(argv[0], &p, 10);
            if (*p != '\0')
                return 0;
	    oklog("CMDLINE: Initial port = %d\n", *pport);
        }
    }

    memset(&hints, '\0', sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;
    asprintf(&portstr, "%u", *pport);
    rc = getaddrinfo(host, portstr, &hints, &bind_addr);
    free(portstr);
    if (rc != 0) {
	errlog("Could not find listening address %s: %s\n", host,
	       gai_strerror(rc));
        return 0;
    }

#ifdef OUTBOUND_NETWORK
    oklog("CMDLINE: Outbound network connections %s.\n", 
          outbound_network_enabled ? "enabled" : "disabled");
#endif
    return 1;
}

char rcsid_net_tcp[] = "$Id$";

/* 
 * $Log$
 * Revision 1.2.4.2  2005/09/29 06:56:18  bjj
 * Merge HEAD onto WAIF, bringing it approximately to 1.8.2
 *
 * Revision 1.2  2004/05/22 01:25:44  wrog
 * merging in WROGUE changes (W_SRCIP, W_STARTUP, W_OOB)
 *
 * Revision 1.1.2.2  2003/06/10 00:14:52  wrog
 * fixed printf warning
 *
 * Revision 1.1.2.1  2003/06/01 12:42:30  wrog
 * added cmdline options -a (source address) +O/-O (enable/disable outbound network)
 *
 *
 */
