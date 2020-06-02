/*
rxtxrpt.c

Report RX and TX statistics. Also report IPv6 address and the IPv6 routing
table if it has changed.
*/
//config:config RXTXRPT
//config:       bool "rxtxrpt"
//config:       default n
//config:       help
//config:         rxtxrpt report RX and TX statistics as well as IPv6 addresses and
//config:         routes

//applet:IF_RXTXRPT(APPLET(rxtxrpt, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_RXTXRPT) += rxtxrpt.o

//usage:#define rxtxrpt_trivial_usage
//usage:       "[-A STRING] [ipv6-info-cache]"
//usage:#define rxtxrpt_full_usage "\n\n"
//usage:       "Display RX and TX statistics as well as IPv6 info\n"
//usage:       "\n     -A STRING       Use Atlas format with STRING"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "libbb.h"

#define NEW_FORMAT

#define DEV_FILE	"/proc/net/dev"
#define IF_INET6_FILE	"/proc/net/if_inet6"
#define IPV6_ROUTE_FILE	"/proc/net/ipv6_route"
#define SUFFIX		".new"

#define DBQ(str) "\"" #str "\""

int do_atlas= 0;

static int rpt_rxtx(void);
static int setup_ipv6_rpt(char *cache_name, int *need_report);
static int rpt_ipv6(char *cache_name);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);

int rxtxrpt_main(int argc, char *argv[])
{
	int r, need_report;
	char *opt_atlas, *cache_name;

	opt_atlas= NULL;
	opt_complementary= NULL;
	getopt32(argv, "A:", &opt_atlas);

	do_atlas= (opt_atlas != NULL);

	if (argc > optind+1)
		bb_show_usage();

	cache_name= NULL;
	if (argc == optind+1)
		cache_name= argv[optind];

	if (do_atlas)
	{
#ifdef NEW_FORMAT
		printf("RESULT { " DBQ(id) ": " DBQ(%s) ", ", opt_atlas);
		printf("%s, ", atlas_get_version_json_str());
		printf(DBQ(time) ": %lld, ", (long long)time(NULL));
		printf(DBQ(lts) ": %d, ", get_timesync());
		printf(DBQ(interfaces) ": [");
#else /* !NEW_FORMWAT */
		printf("%s %lu ", opt_atlas, time(NULL));
#endif /* NEW_FORMWAT */
	}

	r= rpt_rxtx();
	if (r != 0)
		return r;

	if (do_atlas)
	{
#ifdef NEW_FORMAT
		printf(" ] }\n");
#else /* !NEW_FORMAT */
		printf("\n");

#endif /* NEW_FORMAT */
	}

	if (cache_name)
	{
		r= setup_ipv6_rpt(cache_name, &need_report);
		if (r != 0)
			return r;
		if (need_report)
		{
			r= rpt_ipv6(cache_name);
			if (r != 0)
				return r;
		}
	}

	return 0;
}

#ifdef NEW_FORMAT
static int rpt_rxtx(void)
{
	int i;
	unsigned long long bytes_recv, pkt_recv, errors_recv, dropped_recv,
		fifo_recv, framing_recv, compressed_recv, multicast_recv,
		bytes_sent, pkt_sent, errors_sent, dropped_sent,
		fifo_sent, collisions_sent, carr_lost_sent, compressed_sent;
	char *cp, *infname;
	FILE *file;
	char buf[256];

	file= fopen(DEV_FILE, "r");
	if (!file)
	{
		report_err("unable to open '%s'", DEV_FILE);
		return 1;
	}

	/* Skip two lines */
	if (fgets(buf, sizeof(buf), file) == NULL ||
		fgets(buf, sizeof(buf), file) == NULL)
	{
		report_err("unable to read from '%s'", DEV_FILE);
		fclose(file);
		return 1;
	}

	for (i= 0; i<100; i++)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
			if (feof(file))
				break;
			report_err("unable to read from '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		cp= buf;

		/* Skip leading white space */
		while (*cp == ' ')
			cp++;
		infname= cp;
		cp= strchr(cp, ':');
		if (cp == NULL)
		{
			report_err("format error in '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		/* Get all the values */
		if (sscanf(cp+1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			&bytes_recv, &pkt_recv, &errors_recv, &dropped_recv,
			&fifo_recv, &framing_recv, &compressed_recv,
			&multicast_recv,
			&bytes_sent, &pkt_sent, &errors_sent, &dropped_sent,
			&fifo_sent, &collisions_sent, &carr_lost_sent,
			&compressed_sent) != 16)
		{
			report_err("format error in '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		*cp= '\0';

		printf("%s { " DBQ(name) ": " DBQ(%s) ", ",
			i == 0 ? "" : ",", infname);
	
		printf(DBQ(bytes_recv) ": %llu, ", bytes_recv);
		printf(DBQ(pkt_recv) ": %llu, ", pkt_recv);
		printf(DBQ(errors_recv) ": %llu, ", errors_recv);
		printf(DBQ(dropped_recv) ": %llu, ", dropped_recv);
		printf(DBQ(fifo_recv) ": %llu, ", fifo_recv);
		printf(DBQ(framing_recv) ": %llu, ", framing_recv);
		printf(DBQ(compressed_recv) ": %llu, ", compressed_recv);
		printf(DBQ(multicast_recv) ": %llu, ", multicast_recv);
		printf(DBQ(bytes_sent) ": %llu, ", bytes_sent);
		printf(DBQ(pkt_sent) ": %llu, ", pkt_sent);
		printf(DBQ(errors_sent) ": %llu, ", errors_sent);
		printf(DBQ(dropped_sent) ": %llu, ", dropped_sent);
		printf(DBQ(fifo_sent) ": %llu, ", fifo_sent);
		printf(DBQ(collisions_sent) ": %llu, ", collisions_sent);
		printf(DBQ(carr_lost_sent) ": %llu, ", carr_lost_sent);
		printf(DBQ(compressed_sent) ": %llu", compressed_sent);
		printf(" }");
	}
	fclose(file);

	return 0;
}
#else /* !NEW_FORMAT */
static int rpt_rxtx(void)
{
	int i;
	char *cp;
	FILE *file;
	char buf[256];

	file= fopen(DEV_FILE, "r");
	if (!file)
	{
		report_err("unable to open '%s'", DEV_FILE);
		return 1;
	}

	/* Skip two lines */
	if (fgets(buf, sizeof(buf), file) == NULL ||
		fgets(buf, sizeof(buf), file) == NULL)
	{
		report_err("unable to read from '%s'", DEV_FILE);
		fclose(file);
		return 1;
	}

	/* Copy two line */
	for (i= 0; i<2; i++)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
			report_err("unable to read from '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		if (do_atlas)
		{
			/* Get rid of newline */
			cp= strchr(buf, '\n');
			if (cp) *cp= '\0';

			if (i != 0)
				printf(" NEWLINE ");
		}
		fputs(buf, stdout);
	}
	fclose(file);

	return 0;
}
#endif /* NEW_FORMAT */

static int setup_ipv6_rpt(char *cache_name, int *need_report)
{
	int i, r;
	char *cp, *cp1;
	char filename[80];
	char buf1[1024];
	char buf2[1024];
	FILE *in_file, *out_file, *cache_file;

	*need_report= 0;

	if (strlen(cache_name) + strlen(SUFFIX) + 1 > sizeof(filename))
	{
		report("cache name '%s' too long", cache_name);
		return 1;
	}

	strlcpy(filename, cache_name, sizeof(filename));
	strlcat(filename, SUFFIX, sizeof(filename));

	out_file= fopen(filename, "w");
	if (out_file == NULL)
	{
		report_err("unable to create '%s'", filename);
		return 1;
	}

	/* Copy IF_INET6_FILE */
	in_file= fopen(IF_INET6_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IF_INET6_FILE);
		fclose(out_file);
		return 1;
	}

	while (r= fread(buf1, 1, sizeof(buf1), in_file), r > 0)
	{
		if (fwrite(buf1, 1, r, out_file) != r)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
	}
	if (ferror(in_file))
	{
		report_err("error reading from '%s'", IF_INET6_FILE);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}
	fclose(in_file);

	/* Copy IPV6_ROUTE_FILE */
	in_file= fopen(IPV6_ROUTE_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IPV6_ROUTE_FILE);
		fclose(out_file);
		return 1;
	}

	while (fgets(buf1, sizeof(buf1), in_file) != NULL)
	{
		/* Cut out Ref and Use fields */
		cp= buf1;
		for (i= 0; i<6; i++)
		{
			if (cp && cp[0] != '\0')
				cp= strchr(cp+1, ' ');
		}
		if (!cp && cp[0] == '\0')
		{
			report("bad data in '%s'", IPV6_ROUTE_FILE);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
		cp++;
		/* Find the end of the two fields */
		cp1= cp;
		for (i= 0; i<2; i++)
		{
			if (cp1 && cp1[0] != '\0')
				cp1= strchr(cp1+1, ' ');
		}
		if (!cp1 && cp1[0] == '\0')
		{
			report("bad data in '%s'", IPV6_ROUTE_FILE);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
		cp1++;
		/* And delete the two fields */
		memmove(cp, cp1, strlen(cp1)+1);

		if (fputs(buf1, out_file) == -1)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
	}
	if (ferror(in_file))
	{
		report_err("error reading from '%s'", IPV6_ROUTE_FILE);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}
	fclose(in_file);

	/* Now check if the new file is different from the cache one */
	fclose(out_file);
	cache_file= fopen(cache_name, "r");
	if (cache_file == NULL)
	{
		/* Assume that any kind of error here calls for reporting */
		*need_report= 1;
	}

	if (cache_file)
	{
		in_file= fopen(filename, "r");
		if (in_file == NULL)
		{
			report_err("unable to open '%s'", filename);
			fclose(cache_file);
			return 1;
		}

		/* Compare them */
		while (r= fread(buf1, 1, sizeof(buf1), cache_file), r > 0)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != r)
			{
				/* Ignore errors, just report */
				*need_report= 1;
				break;
			}

			if (memcmp(buf1, buf2, r) != 0)
			{
				/* Something changed, report */
				*need_report= 1;
				break;
			}
		}

		/* Maybe something got added */
		if (!*need_report)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != 0)
			{
				*need_report= 1;
			}
		}
		fclose(cache_file);
		fclose(in_file);
	}

	if (*need_report)
	{
		if (rename(filename, cache_name) == -1)
		{
			report_err("renaming '%s' to '%s' failed",
				filename, cache_name);
			return 1;
		}
	}
	else
	{
		if (unlink(filename) == -1)
		{
			report_err("unlinking '%s' failed",
				filename);
		}
	}

	return 0;
}

static int rpt_ipv6(char *cache_name)
{
	FILE *file;
	char *cp;
	char buf[256];

	file= fopen(cache_name, "r");
	if (!file)
	{
		report_err("unable to open '%s'", cache_name);
		return 1;
	}

	/* Copy all lines */
	while (fgets(buf, sizeof(buf), file) != NULL)
	{
		if (do_atlas)
		{
			/* Get rid of newline */
			cp= strchr(buf, '\n');
			if (cp) *cp= '\0';

			printf(" NEWLINE ");
		}
		fputs(buf, stdout);
	}
	fclose(file);

	return 0;
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "rxtxrpt: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

static void report_err(const char *fmt, ...)
{
	int t_errno;
	va_list ap;

	t_errno= errno;

	va_start(ap, fmt);

	fprintf(stderr, "rxtxrpt: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(t_errno));

	va_end(ap);
}
