/* 
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 * Standalone version of the event-based httpget. 
 */

#include "libbb.h"
#include <syslog.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>

#include "eperd.h"

static void done(void *state UNUSED_PARAM)
{
	fprintf(stderr, "And we are done\n");
	exit(0);
}

int evhttpget_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evhttpget_main(int argc UNUSED_PARAM, char **argv)
{
	int r;
	void *state;

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		fprintf(stderr, "evhttpget_base_new failed\n");
		exit(1);
	}
	DnsBase= evdns_base_new(EventBase, 1 /*initialize*/);
	if (!DnsBase)
	{
		fprintf(stderr, "evdns_base_new failed\n");
		exit(1);
	}

	state= httpget_ops.init(argc, argv, done);
	if (!state)
	{
		fprintf(stderr, "evhttpget: traceroute_ops.init failed\n");
		exit(1);
	}
	httpget_ops.start(state);

	r= event_base_loop(EventBase, 0);
	if (r != 0)
	{
		fprintf(stderr, "evhttpget: event_base_loop failed\n");
		exit(1);
	}
	return 0; /* not reached */
}

