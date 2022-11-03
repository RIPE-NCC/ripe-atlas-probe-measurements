/*
 * Copyright (c) 2011-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * httppost.c -- Simple program that uses the HTTP POST command
*/
//config:config HTTPPOST
//config:       bool "httppost"
//config:       default n
//config:       help
//config:         httppost post files using http

//applet:IF_HTTPPOST(APPLET(httppost, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_HTTPPOST) += httppost.o

//usage:#define httppost_trivial_usage
//usage:       ""
//usage:#define httppost_full_usage "\n\n"
//usage:       ""

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "libbb.h"

#include "../eperd/eperd.h"

//#define SAFE_PREFIX_DATA_OUT ATLAS_DATA_OUT
#define SAFE_PREFIX_DATA_OUT_REL ATLAS_DATA_OUT_REL
#define SAFE_PREFIX_DATA_OOQ_OUT ATLAS_DATA_OOQ_OUT
#define SAFE_PREFIX_DATA_OOQ_OUT_REL ATLAS_DATA_OOQ_OUT_REL
#define SAFE_PREFIX_DATA_NEW_REL ATLAS_DATA_NEW_REL
#define SAFE_PREFIX_DATA_STORAGE ATLAS_DATA_STORAGE
#define SAFE_PREFIX_DATA_STORAGE_REL ATLAS_DATA_STORAGE_REL
#define SAFE_PREFIX_STATUS_REL ATLAS_STATUS_REL

/* Maximum number of files to post in one go with post-dir */
#define MAX_FILES	1000

struct option longopts[]=
{
	{ "delete-file", no_argument, NULL, 'd' },
	{ "maxpostsize", required_argument, NULL, 'm' },
	{ "post-file", required_argument, NULL, 'p' },
	{ "post-dir", required_argument, NULL, 'D' },
	{ "post-header", required_argument, NULL, 'h' },
	{ "post-footer", required_argument, NULL, 'f' },
	{ "set-time", required_argument, NULL, 's' },
	{ "timeout", required_argument, NULL, 't' },
	{ "loglevel", required_argument, NULL, 'l' },
	{ NULL, }
};

#define INIT_G() do { \
	LogLevel = 8; \
} while (0)

static int tcp_fd;
static struct timeval start_time;
static time_t timeout = 300;

/* Result sent by controller when input is acceptable. */
#define OK_STR	"OK\n"

static int parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp);
static int check_result(FILE *tcp_file);
static int eat_headers(FILE *tcp_file, int *chunked, int *content_length, time_t *timep);
static int connect_to_name(char *host, char *port);
char *do_dir(char *dir_name, off_t curr_size, off_t max_size, off_t *lenp);
static int copy_chunked(FILE *in_file, FILE *out_file, int *found_okp);
static int copy_bytes(FILE *in_file, FILE *out_file, size_t len,
	int *found_okp);
static int copy_all(FILE *in_file, FILE *out_file, int *found_okp);
static int write_to_tcp_fd (int fd, FILE *tcp_file);
static void skip_spaces(const char *cp, char **ncp);
static void got_alarm(int sig);
static void kick_watchdog(void);

int httppost_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int httppost_main(int argc, char *argv[])
{
	int c,  r, fd, fdF, fdH, fdS, chunked, content_length, result;
	int opt_delete_file, found_ok;
	char *url, *host, *port, *hostport, *path, *filelist, *p, *check;
	char *post_dir, *post_file, *atlas_id, *output_file,
		*post_footer, *post_header, *maxpostsizestr, *timeoutstr,
		*loglevelstr;
	char *time_tolerance, *rebased_fn= NULL;
	char *fn_new, *fn;
	FILE *tcp_file, *out_file, *fh;
	time_t server_time, tolerance;
	struct stat sbF, sbH, sbS;
	off_t cLength, dir_length, maxpostsize;
	struct sigaction sa;
	struct timespec ts;

	post_dir= NULL; 
	post_file= NULL; 
	post_footer=NULL;
	post_header=NULL;
	atlas_id= NULL;
	output_file= NULL;
	opt_delete_file = 0;
	time_tolerance = NULL;
	maxpostsizestr= NULL;
	timeoutstr= NULL;
	loglevelstr= NULL;

	fd= -1;
	fdH= -1;
	fdF= -1;
	fdS= -1;
	tcp_fd= -1;
	tcp_file= NULL;
	out_file= NULL;
	host= NULL;
	port= NULL;
	hostport= NULL;
	path= NULL;
	filelist= NULL;
	maxpostsize= 1000000;

	INIT_G();

	/* Allow us to be called directly by another program in busybox */
	optind= 0;
	while (c= getopt_long(argc, argv, "A:O:?", longopts, NULL), c != -1)
	{
		switch(c)
		{
		case 'A':
			atlas_id= optarg;
			break;
		case 'O':
			output_file= optarg;
			break;
		case 'd':
			opt_delete_file = 1;
			break;
		case 'D':
			post_dir = optarg;		/* --post-dir */
			break;
		case 'h':				/* --post-header */
			post_header= optarg;
			break;
		case 'f':				/* --post-footer */
			post_footer= optarg;
			break;
		case 'm':				/* --maxpostsize */
			maxpostsizestr= optarg;
			break;
		case 'p':				/* --post-file */
			post_file= optarg;
			break;
		case 's':				/* --set-time */
			time_tolerance= optarg;
			break;
		case 't':				/* --timeout */
			timeoutstr= optarg;
			break;
		case 'l':				/* --loglevel */
			loglevelstr= optarg;
			break;
		case '?':
			crondlog(LVL9 "bad option");
			return 1;
		default:
			crondlog(DIE9 "bad option '%c'", c);
		}
	}

	if (optind != argc-1)
	{
		crondlog(LVL9 "exactly one url expected");
		return 1;
	}
	url= argv[optind];

	if (atlas_id)
	{
		if (!validate_atlas_id(atlas_id))
		{
			crondlog(LVL9 "bad atlas ID '%s'", atlas_id);
			return 1;
		}
	}

	if (maxpostsizestr)
	{
		maxpostsize= strtoul(maxpostsizestr, &check, 0);
		if (check[0] != 0)
		{
			crondlog(LVL9 "unable to parse maxpostsize '%s'",
				maxpostsizestr);
			goto err;
		}
	}

	if (timeoutstr)
	{
		timeout= strtoul(timeoutstr, &check, 0);
		if (check[0] != 0)
		{
			crondlog(LVL9 "unable to parse timeout '%s'",
				timeoutstr);
			goto err;
		}
	}

	if (loglevelstr)
	{
		LogLevel= (unsigned)strtoul(loglevelstr, &check, 0);
		if (check[0] != '\0')
		{
			crondlog(LVL9 "unable to parse loglevel '%s'\n",
				loglevelstr);
			goto err;
		}
	}

	tolerance= 0;
	if (time_tolerance)
	{
		tolerance= strtoul(time_tolerance, &p, 10);
		if (p[0] != '\0')
		{
			crondlog(LVL9 "unable to parse tolerance '%s'\n",
				time_tolerance);
			return 1;
		}
	}

	if (parse_url(url, &host, &port, &hostport, &path) == -1)
		return 1;

	//printf("host: %s\n", host);
	//printf("port: %s\n", port);
	//printf("hostport: %s\n", hostport);
	//printf("path: %s\n", path);

	cLength= 0;

	if(post_header != NULL )
	{	
		rebased_fn= rebased_validated_filename(post_header,
			SAFE_PREFIX_DATA_OUT_REL);
		if (rebased_fn == NULL)
		{
			rebased_fn= rebased_validated_filename(post_header,
				SAFE_PREFIX_STATUS_REL);
		}
		if (rebased_fn == NULL)
		{
			crondlog(LVL9 "protected file (for header) '%s'",
				post_header);
			goto err;
		}
		fdH = open(rebased_fn, O_RDONLY);
		if(fdH == -1 )
		{
			crondlog(LVL9 "unable to open header '%s'", rebased_fn);
			goto err;
		}
		if (fstat(fdH, &sbH) == -1)
		{
			crondlog(LVL9 "fstat failed on header file '%s'",
				rebased_fn);
			goto err;
		}
		if (!S_ISREG(sbH.st_mode))
		{
			crondlog(LVL9 "'%s' header is not a regular file",
				rebased_fn);
			goto err;
		}
		free(rebased_fn); rebased_fn= NULL;
		cLength  +=  sbH.st_size;
	}

	if (post_footer != NULL )
	{	
		rebased_fn= rebased_validated_filename(post_footer,
			SAFE_PREFIX_DATA_OUT_REL);
		if (rebased_fn == NULL)
		{
			rebased_fn= rebased_validated_filename(post_footer,
				SAFE_PREFIX_STATUS_REL);
		}
		if (rebased_fn == NULL)
		{
			crondlog(LVL9 "protected file (for footer) '%s'",
				post_footer);
			goto err;
		}
		fdF = open(rebased_fn, O_RDONLY);
		if(fdF == -1 )
		{
			crondlog(LVL9 "unable to open footer '%s'",
				rebased_fn);
			goto err;
		}
		if (fstat(fdF, &sbF) == -1)
		{
			crondlog(LVL9 "fstat failed on footer file '%s'",
				rebased_fn);
			goto err;
		}
		if (!S_ISREG(sbF.st_mode))
		{
			crondlog(LVL9 "'%s' footer is not a regular file",
				rebased_fn);
			goto err;
		}
		free(rebased_fn); rebased_fn= NULL;
		cLength  +=  sbF.st_size;
	}

	/* Try to open the file before trying to connect */
	if (post_file != NULL)
	{
		rebased_fn= rebased_validated_filename(post_file,
			SAFE_PREFIX_DATA_OUT_REL);
		if (rebased_fn == NULL)
		{
			rebased_fn= rebased_validated_filename(post_file,
				SAFE_PREFIX_STATUS_REL);
		}
		if (rebased_fn == NULL)
		{
			crondlog(LVL9 "protected file (post) '%s'", post_file);
			goto err;
		}
		fdS= open(post_file, O_RDONLY);
		if (fdS == -1)
		{
			crondlog(LVL9 "unable to open '%s'", rebased_fn);
			goto err;
		}
		if (fstat(fdS, &sbS) == -1)
		{
			crondlog(LVL9 "fstat failed");
			goto err;
		}
		if (!S_ISREG(sbS.st_mode))
		{
			crondlog(LVL9 "'%s' is not a regular file", rebased_fn);
			goto err;
		}
		free(rebased_fn); rebased_fn= NULL;
		cLength  += sbS.st_size;
	}

	if (post_dir)
	{
		rebased_fn= rebased_validated_dir(post_dir,
			SAFE_PREFIX_DATA_OUT_REL);
		if (rebased_fn == NULL)
		{
			rebased_fn= rebased_validated_dir(post_dir,
				SAFE_PREFIX_DATA_STORAGE_REL);
		}
		if (rebased_fn == NULL)
		{
			crondlog(LVL9 "protected dir (post) '%s'", post_dir);
			goto err;
		}
		filelist= do_dir(rebased_fn, cLength, maxpostsize, &dir_length);
		free(rebased_fn); rebased_fn= NULL;
		if (!filelist)
		{
			/* Something went wrong. */
			goto err;
		}
		crondlog(LVL7 "total size in dir: %ld", (long)dir_length);
		cLength += dir_length;
	}

	gettimeofday(&start_time, NULL);

	sa.sa_flags= 0;
	sa.sa_handler= got_alarm;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
	alarm(10);
	signal(SIGPIPE, SIG_IGN);

	tcp_fd= connect_to_name(host, port);
	if (tcp_fd == -1)
	{
		crondlog(LVL9 "unable to connect to '%s'", host);
		goto err;
	}

	/* Stdio makes life easy */
	tcp_file= fdopen(tcp_fd, "r+");
	if (tcp_file == NULL)
	{
		crondlog(LVL9 "fdopen failed");
		goto err;
	}

	crondlog(LVL7 "httppost: sending request");
	fprintf(tcp_file, "POST %s HTTP/1.1\r\n", path);
	//fprintf(tcp_file, "GET %s HTTP/1.1\r\n", path);
	fprintf(tcp_file, "Host: %s\r\n", host);
	fprintf(tcp_file, "Connection: close\r\n");
	fprintf(tcp_file, "User-Agent: httppost for atlas.ripe.net\r\n");
	fprintf(tcp_file,
			"Content-Type: application/x-www-form-urlencoded\r\n");

	cLength= 0;
	if( post_header != NULL )
		cLength  +=  sbH.st_size;

	if (post_file)
		cLength  += sbS.st_size;

	if (post_dir)
		cLength += dir_length;

	if( post_footer != NULL )
		cLength  +=  sbF.st_size;

	fprintf(tcp_file, "Content-Length: %lu\r\n", (unsigned long)cLength);
	fprintf(tcp_file, "\r\n");

	if( post_header != NULL )
	{
		if (!write_to_tcp_fd(fdH, tcp_file))
			goto err;
	}

	if (post_file != NULL)
	{
		if (!write_to_tcp_fd(fdS, tcp_file))
			goto err;
	}

	if (post_dir)
	{
		for (p= filelist; p[0] != 0; p += strlen(p)+1)
		{
			crondlog(LVL7 "posting file '%s'", p);
			rebased_fn= rebased_validated_filename(p,
				SAFE_PREFIX_DATA_OUT_REL);
			if (rebased_fn == NULL)
			{
				rebased_fn= rebased_validated_filename(p,
					SAFE_PREFIX_DATA_OOQ_OUT_REL);
			}
			if (rebased_fn == NULL)
			{
				rebased_fn= rebased_validated_filename(p,
					SAFE_PREFIX_DATA_STORAGE_REL);
			}
			if (rebased_fn == NULL)
			{
				crondlog(LVL9 "protected file (post dir) '%s'", p);
				goto err;
			}
			fd= open(p, O_RDONLY);
			if (fd == -1)
			{
				crondlog(LVL9 "unable to open '%s'",
					rebased_fn);
				goto err;
			}
			free(rebased_fn); rebased_fn= NULL;
			r= write_to_tcp_fd(fd, tcp_file);
			close(fd);
			fd= -1;
			if (!r)
				goto err;
		}
	}

	if( post_footer != NULL)
	{
		if (!write_to_tcp_fd(fdF, tcp_file))
			goto err;
	}

	crondlog(LVL7 "httppost: getting result");
	if (!check_result(tcp_file))
		goto err;
	crondlog(LVL7 "httppost: getting reply headers");
	server_time= 0;
	content_length= -1;
	if (!eat_headers(tcp_file, &chunked, &content_length, &server_time))
		goto err;

	if (tolerance && server_time > 0)
	{
		/* Try to set time from server */
		int need_set_time;
		struct timeval now;
		double rtt;

		gettimeofday(&now, NULL);
		rtt= now.tv_sec-start_time.tv_sec;
		rtt += (now.tv_usec-start_time.tv_usec)/1e6;
		if (rtt < 0) rtt= 0;
		need_set_time= (now.tv_sec < server_time-tolerance-rtt ||
			now.tv_sec > server_time+tolerance+rtt);
		if (need_set_time && getenv("HTTPPOST_ALLOW_STIME"))
		{
			crondlog(LVL8
				"setting time, time difference is %llu",
				(unsigned long long)server_time-now.tv_sec);
			ts.tv_sec= server_time;
			ts.tv_nsec= 0;
			clock_settime(CLOCK_REALTIME, &ts);
			if (atlas_id)
			{
				printf(
	"RESULT %s ongoing %llu httppost setting time, local %llu, remote %llu\n",
					atlas_id, (unsigned long long)time(NULL),
					(unsigned long long)now.tv_sec,
					(unsigned long long)server_time);
			}
		}
		else if (need_set_time)
		{
			crondlog(LVL8
				"not setting time, time difference is %llu",
				(unsigned long long)server_time-now.tv_sec);
			if (atlas_id)
			{
				printf(
	"RESULT %s ongoing %llu httppost not in sync, local %llu, remote %llu\n",
					atlas_id, (unsigned long long)time(NULL),
					(unsigned long long)now.tv_sec,
					(unsigned long long)server_time);
			}
		}
		else if (rtt <= 1)
		{
			/* Time and network are fine. Record this fact */
			fn_new= atlas_path(ATLAS_TIMESYNC_FILE_REL ".new");
			fn= atlas_path(ATLAS_TIMESYNC_FILE_REL);
			fh= fopen(fn_new, "wt");
			if (fh)
			{
				fprintf(fh, "%llu\n", (unsigned long long)now.tv_sec);
				fclose(fh);
				rename(fn_new, fn);
			}
			free(fn_new); fn_new= NULL;
			free(fn); fn= NULL;
		}
		else if (atlas_id)
		{
			printf("RESULT %s ongoing %llu httppost rtt %g ms\n",
				atlas_id, (unsigned long long)time(NULL), rtt*1000);
		}
	}

	crondlog(LVL7 "httppost: writing output");
	if (output_file)
	{
		rebased_fn= rebased_validated_filename(output_file,
			SAFE_PREFIX_DATA_NEW_REL);
		if (!rebased_fn)
		{
			crondlog(LVL9 "protected file (output) '%s'", output_file);
			goto err;
		}
		out_file= fopen(rebased_fn, "w");
		if (!out_file)
		{
			crondlog(LVL9 "unable to create '%s'", rebased_fn);
			goto err;
		}
		free(rebased_fn); rebased_fn= NULL;
	}
	else
		out_file= stdout;

	crondlog(LVL7 "httppost: chunked %d, content_length %d",
		chunked, content_length);
	found_ok= 0;
	if (chunked)
	{
		if (!copy_chunked(tcp_file, out_file, &found_ok))
			goto err;
	}
	else if (content_length >= 0)
	{
		if (!copy_bytes(tcp_file, out_file, content_length, &found_ok))
			goto err;
	}
	else
	{
		if (!copy_all(tcp_file, out_file, &found_ok))
			goto err;
	}
	if (!found_ok)
		crondlog(LVL8 "httppost: reply text was not equal to OK");
	if (opt_delete_file == 1  && found_ok)
	{
		crondlog(LVL7 "httppost: deleting files");
		if (post_file)
		{
			rebased_fn= rebased_validated_filename(post_file,
					SAFE_PREFIX_DATA_OUT_REL);
			if (!rebased_fn)
			{
				crondlog(LVL9 "trying to delete protected file '%s'",
					post_file);
				goto err;
			}
			unlink (rebased_fn);
			free(rebased_fn); rebased_fn= NULL;
		}
		if (post_dir)
		{
			for (p= filelist; p[0] != 0; p += strlen(p)+1)
			{
				crondlog(LVL7 "unlinking file '%s'", p);
				if (unlink(p) != 0)
					crondlog(LVL9 "unable to unlink '%s'", p);
			}
		}
	}
	crondlog(LVL7 "httppost: done");

	result= 0;

leave:
	if (fdH != -1) close(fdH);
	if (fdF != -1) close(fdF);
	if (fdS != -1) close(fdS);
	if (fd != -1) close(fd);
	if (tcp_file)
	{
		fclose(tcp_file);
		tcp_fd= -1;
	}
	if (tcp_fd != -1) close(tcp_fd);
	if (out_file) fclose(out_file);
	if (host) free(host);
	if (port) free(port);
	if (hostport) free(hostport);
	if (path) free(path);
	if (filelist) free(filelist);
	if (rebased_fn) free(rebased_fn);

	alarm(0);
	signal(SIGPIPE, SIG_DFL);

	return result; 

err:
	crondlog(LVL9 "httppost: leaving with error");
	result= 1;
	goto leave;
}

static int write_to_tcp_fd (int fd, FILE *tcp_file)
{
	int r;
	char buffer[1024];

	/* Copy file */
	while(r= read(fd, buffer, sizeof(buffer)), r > 0)
	{
		if (fwrite(buffer, r, 1, tcp_file) != 1)
		{
			crondlog(LVL9 "error writing to tcp connection");
			return 0;
		}
		alarm(10);
	}
	if (r == -1)
	{
		crondlog(LVL9 "error reading from file");
		return 0;
	}
	return 1;
}


static int parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp)
{
	char *item;
	const char *cp, *np, *prefix;
	size_t len;

	*hostportp= NULL;
	*pathp= NULL;
	*hostp= NULL;
	*portp= NULL;

	/* the url must start with 'http://' */
	prefix= "http://";
	len= strlen(prefix);
	if (strncasecmp(prefix, url, len) != 0)
	{
		crondlog(LVL9 "bad prefix in url '%s'", url);
		return -1;
	}

	cp= url+len;

	/* Get hostport part */
	np= strchr(cp, '/');
	if (np != NULL)
		len= np-cp;
	else
	{
		len= strlen(cp);
		np= cp+len;
	}
	if (len == 0)
	{
		crondlog(LVL9 "missing host part in url '%s'", url);
		return -1;
	}

	item= malloc(len+1);
	if (!item) crondlog(DIE9 "out of memory");
	memcpy(item, cp, len);
	item[len]= '\0';
	*hostportp= item;

	/* The remainder is the path */
	cp= np;
	if (cp[0] == '\0')
		cp= "/";
	len= strlen(cp);
	item= malloc(len+1);
	if (!item) crondlog(DIE9 "out of memory");
	memcpy(item, cp, len);
	item[len]= '\0';
	*pathp= item;

	/* Extract the host name from hostport */
	cp= *hostportp;
	np= cp;
	if (cp[0] == '[')
	{
		/* IPv6 address literal */
		np= strchr(cp, ']');
		if (np == NULL || np == cp+1)
		{
			crondlog(LVL9
				"malformed IPv6 address literal in url '%s'",
				url);
			goto error;
		}
	}
	np= strchr(np, ':');
	if (np != NULL)
		len= np-cp;
	else
	{
		len= strlen(cp);
		np= cp+len;
	}
	if (len == 0)
	{
		crondlog(LVL9 "missing host part in url '%s'", url);
		goto error;
	}
	item= malloc(len+1);
	if (!item) crondlog(DIE9 "out of memory");
	if (cp[0] == '[')
	{
		/* Leave out the square brackets */
		memcpy(item, cp+1, len-2);
		item[len-2]= '\0';
	}
	else
	{
		memcpy(item, cp, len);
		item[len]= '\0';
	}
	*hostp= item;

	/* Port */
	cp= np;
	if (cp[0] == '\0')
		cp= "80";
	else
		cp++;
	len= strlen(cp);
	item= malloc(len+1);
	if (!item) crondlog(DIE9 "out of memory");
	memcpy(item, cp, len);
	item[len]= '\0';
	*portp= item;

	return 0;
error:
	free(*hostportp); *hostportp= NULL;
	free(*pathp); *pathp= NULL;
	free(*hostp); *hostp= NULL;
	free(*portp); *portp= NULL;

	return -1;
}

static int check_result(FILE *tcp_file)
{
	int major, minor;
	size_t len;
	char *cp, *check, *line;
	const char *prefix;
	char buffer[1024];
	
	while (fgets(buffer, sizeof(buffer), tcp_file) == NULL)
	{
		if (feof(tcp_file))
		{
			crondlog(LVL9 "got unexpected EOF from server");
			return 0;
		}
		if (errno == EINTR)
		{
			crondlog(LVL9 "timeout");
			sleep(10);
		}
		else
		{
			crondlog(LVL9 "error reading from server");
			return 0;
		}
	}

	line= buffer;
	cp= strchr(line, '\n');
	if (cp == NULL)
	{
		crondlog(LVL9 "line too long");
		return 0;
	}
	cp[0]= '\0';
	if (cp > line && cp[-1] == '\r')
		cp[-1]= '\0';

	/* Check http version */
	prefix= "http/";
	len= strlen(prefix);
	if (strncasecmp(prefix, line, len) != 0)
	{
		crondlog(LVL9 "bad prefix in response '%s'", line);
		return 0;
	}
	cp= line+len;
	major= strtoul(cp, &check, 10);
	if (check == cp || check[0] != '.')
	{
		crondlog(LVL9 "bad major version in response '%s'", line);
		return 0;
	}
	cp= check+1;
	minor= strtoul(cp, &check, 10);
	if (check == cp || check[0] == '\0' ||
		!isspace(*(unsigned char *)check))
	{
		crondlog(LVL9 "bad major version in response '%s'", line);
		return 0;
	}

	skip_spaces(check, &cp);

	if (!isdigit(*(unsigned char *)cp))
	{
		crondlog(LVL9 "bad status code in response '%s'", line);
		return 0;
	}

	if (cp[0] != '2')
	{
		crondlog(LVL9 "POST command failed: '%s'", cp);
		return 0;
	}

	return 1;
}

static int eat_headers(FILE *tcp_file, int *chunked, int *content_length, time_t *timep)
{
	char *line, *cp, *ncp, *check;
	size_t len;
	const char *kw;
	char buffer[1024];

	*chunked= 0;
	while (fgets(buffer, sizeof(buffer), tcp_file) != NULL)
	{
		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			crondlog(LVL9 "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		if (line[0] == '\0')
			return 1;		/* End of headers */

		crondlog(LVL7 "httppost: got line '%s'", line);

		if (strncmp(line, "Date: ", 6) == 0)
		{
			/* Parse date header */
			struct tm tm;

			cp= strptime(line+6, "%a, %d %b %Y %H:%M:%S ", &tm);
			if (!cp || strcmp(cp, "GMT") != 0)
			{
				crondlog(LVL9 "unable to parse time '%s'",
					line+6);
			}
			*timep= timegm(&tm);
		}

		cp= line;
		skip_spaces(cp, &ncp);
		if (ncp != line)
			continue;	/* Continuation line */

		cp= ncp;
		while (ncp[0] != '\0' && ncp[0] != ':' &&
			!isspace((unsigned char)ncp[0]))
		{
			ncp++;
		}

		kw= "Transfer-Encoding";
		len= strlen(kw);
		if (strncasecmp(cp, kw, len) == 0)
		{
			/* Skip optional white space */
			cp= ncp;
			skip_spaces(cp, &cp);

			if (cp[0] != ':')
			{
				crondlog(LVL9
					"malformed transfer-encoding header");
				return 0;
			}
			cp++;

			/* Skip more white space */
			skip_spaces(cp, &cp);

			/* Should have the value by now */
			kw= "chunked";
			len= strlen(kw);
			if (strncasecmp(cp, kw, len) != 0)
				continue;
			/* make sure we have end of line or white space */
			if (cp[len] != '\0' && isspace((unsigned char)cp[len]))
				continue;
			*chunked= 1;
			continue;
		}

		kw= "Content-length";
		len= strlen(kw);
		if (strncasecmp(cp, kw, len) != 0)
			continue;

		/* Skip optional white space */
		cp= ncp;
		skip_spaces(cp, &cp);

		if (cp[0] != ':')
		{
			crondlog(LVL9 "malformed content-length header");
			return 0;
		}
		cp++;

		/* Skip more white space */
		skip_spaces(cp, &cp);

		/* Should have the value by now */
		*content_length= strtoul(cp, &check, 10);
		if (check == cp)
		{
			crondlog(LVL9 "malformed content-length header");
			return 0;
		}

		/* And after that we should have just white space */
		cp= check;
		skip_spaces(cp, &cp);

		if (cp[0] != '\0')
		{
			crondlog(LVL9 "malformed content-length header");
			return 0;
		}
	}
	if (feof(tcp_file))
		crondlog(LVL9 "got unexpected EOF from server");
	else
		crondlog(LVL9 "error reading from server");
	return 0;
}

static int connect_to_name(char *host, char *port)
{
	int r, s, s_errno;
	struct addrinfo *res, *aip;
	struct addrinfo hints;

	crondlog(LVL5 "httppost: before getaddrinfo");
	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	r= getaddrinfo(host, port, &hints, &res);
	if (r != 0)
	{
		crondlog(LVL9 "unable to resolve '%s': %s",
			host, gai_strerror(r));
		errno= ENOENT;	/* Need something */
		return -1;
	}

	s_errno= 0;
	s= -1;
	for (aip= res; aip != NULL; aip= aip->ai_next)
	{
		s= socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
		{	
			s_errno= errno;
			continue;
		}

		crondlog(LVL5 "httppost: before connect");
		if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
			break;

		s_errno= errno;
		close(s);
		s= -1;
	}

	freeaddrinfo(res);
	if (s == -1)
		errno= s_errno;
	return s;
}

char *do_dir(char *dir_name, off_t curr_tot_size, off_t max_size, off_t *lenp)
{
	int file_count;
	size_t currsize, allocsize, dirlen, len;
	char *list, *tmplist, *path;
	DIR *dir;
	struct dirent *de;
	struct stat sb;

	/* Scan a directory for files. Return the filenames asa list of 
	 * strings. An empty string terminates the list. Also compute the
	 * total size of the files
	 */
	*lenp= 0;
	currsize= 0;
	allocsize= 0;
	file_count= 0;
	list= NULL;
	dir= opendir(dir_name);
	if (dir == NULL)
	{
		crondlog(LVL9 "opendir failed for '%s'", dir_name);
		return NULL;
	}

	dirlen= strlen(dir_name);
	while (de= readdir(dir), de != NULL)
	{
		/* Concat dir and entry */
		len= dirlen + 1 + strlen(de->d_name) + 1;
		if (currsize+len > allocsize)
		{
			allocsize += 4096;
			tmplist= realloc(list, allocsize);
			if (!tmplist)
			{
				free(list);
				crondlog(LVL9 "realloc failed for %d bytes",
					allocsize);
				closedir(dir);
				return NULL;
			}
			list= tmplist;
		}
		path= list+currsize;

		strlcpy(path, dir_name, allocsize-currsize);
		strlcat(path, "/", allocsize-currsize);
		strlcat(path, de->d_name, allocsize-currsize);

		if (stat(path, &sb) != 0)
		{
			crondlog(LVL9 "stat '%s' failed", path);
			free(list);
			closedir(dir);
			return NULL;
		}

		if (!S_ISREG(sb.st_mode))
			continue;	/* Just skip entry */

		if (curr_tot_size + sb.st_size > max_size)
		{
			/* File is too big to fit this time. */
			if (sb.st_size > max_size/2)
			{
				/* File just too big in general */
				crondlog(LVL9 "deleting file '%s', size %d",
					path, sb.st_size);
				unlink(path);
			}
			continue;
		}

		currsize += len;
		curr_tot_size += sb.st_size;
		*lenp += sb.st_size;

		file_count++;

		if (file_count >= MAX_FILES)
			break;
	}
	closedir(dir);

	/* Add empty string to terminate the list */
	len= 1;
	if (currsize+len > allocsize)
	{
		allocsize += 4096;
		tmplist= realloc(list, allocsize);
		if (!tmplist)
		{
			free(list);
			crondlog(LVL9 "realloc failed for %d bytes", allocsize);
			return NULL;
		}
		list= tmplist;
	}
	path= list+currsize;

	*path= '\0';

	return list;
}

static int copy_chunked(FILE *in_file, FILE *out_file, int *found_okp)
{
	int i;
	size_t len, offset, size;
	char *cp, *line, *check;
	const char *okp;
	char buffer[1024];

	okp= OK_STR;

	for (;;)
	{
		/* Get a chunk size */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
		{
			crondlog(LVL9 "error reading input");
			return 0;
		}

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			crondlog(LVL9 "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		crondlog(LVL7 "httppost: got chunk line '%s'", line);
		len= strtoul(line, &check, 16);
		if (check[0] != '\0' && !isspace(*(unsigned char *)check))
		{
			crondlog(LVL9 "bad chunk line '%s'", line);
			return 0;
		}
		if (!len)
			break;

		offset= 0;

		while (offset < len)
		{
			size= len-offset;
			if (size > sizeof(buffer))
				size= sizeof(buffer);
			if (fread(buffer, size, 1, in_file) != 1)
			{
				crondlog(LVL9 "error reading input");
				return 0;
			}
			if (fwrite(buffer, size, 1, out_file) != 1)
			{
				crondlog(LVL9 "error writing output");
				return 0;
			}
			offset += size;

			crondlog(LVL7 "httppost: chunk data '%.*s'", 
				(int)size, buffer);
			for (i= 0; i<size; i++)
			{
				if (!okp)
					break;
				if (*okp != buffer[i] || *okp == '\0')
				{
					okp= NULL;
					break;
				}
				okp++;
			}
		}

		/* Expect empty line after data */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
		{
			crondlog(LVL9 "error reading input");
			return 0;
		}

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			crondlog(LVL9 "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] != '\0')
		{
			crondlog(LVL9 "Garbage after chunk data");
			return 0;
		}
	}

	for (;;)
	{
		/* Get an end-of-chunk line */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
		{
			crondlog(LVL9 "error reading input");
			return 0;
		}

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			crondlog(LVL9 "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] == '\0')
			break;

		crondlog(LVL5 "httppost: got end-of-chunk line '%s'", line);
	}
	*found_okp= (okp != NULL && *okp == '\0');
	return 1;
}

static int copy_bytes(FILE *in_file, FILE *out_file, size_t len, int *found_okp)
{
	int i;
	size_t offset, size;
	const char *okp;
	char buffer[1024];

	okp= OK_STR;

	offset= 0;

	while (offset < len)
	{
		size= len-offset;
		if (size > sizeof(buffer))
			size= sizeof(buffer);
		if (fread(buffer, size, 1, in_file) != 1)
		{
			crondlog(LVL9 "error reading input");
			return 0;
		}
		if (fwrite(buffer, size, 1, out_file) != 1)
		{
			crondlog(LVL9 "error writing output");
			return 0;
		}
		offset += size;

		crondlog(LVL7 "httppost: normal data '%.*s'", 
				(int)size, buffer);

		for (i= 0; i<size; i++)
		{
			if (!okp)
				break;
			if (*okp != buffer[i] || *okp == '\0')
			{
				okp= NULL;
				break;
			}
			okp++;
		}
	}
	*found_okp= (okp != NULL && *okp == '\0');
	return 1;
}

static int copy_all(FILE *in_file, FILE *out_file, int *found_okp)
{
	int i, size;
	const char *okp;
	char buffer[1024];

	okp= OK_STR;

	while (!feof(in_file) && !ferror(in_file))
	{
		size= fread(buffer, 1, sizeof(buffer), in_file);
		if (size <= 0)
			break;
		if (fwrite(buffer, size, 1, out_file) != 1)
		{
			crondlog(LVL9 "error writing output");
			return 0;
		}

		crondlog(LVL7 "httppost: all data '%.*s'", 
				(int)size, buffer);

		for (i= 0; i<size; i++)
		{
			if (!okp)
				break;
			if (*okp != buffer[i] || *okp == '\0')
			{
				okp= NULL;
				break;
			}
			okp++;
		}
	}
	if  (ferror(in_file))
	{
		crondlog(LVL9 "error reading input");
		return 0;
	}
	*found_okp= (okp != NULL && *okp == '\0');
	return 1;
}

static void skip_spaces(const char *cp, char **ncp)
{
	const unsigned char *ucp;

	ucp= (const unsigned char *)cp;
	while (ucp[0] != '\0' && isspace(ucp[0]))
		ucp++;
	*ncp= (char *)ucp;
}

static void got_alarm(int sig __attribute__((unused)) )
{
	if (tcp_fd != -1 && time(NULL) > start_time.tv_sec+timeout)
	{
		crondlog(LVL7 "setting tcp_fd to nonblock");
		fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK);
	}
	kick_watchdog();
	crondlog(LVL7 "got alarm, setting alarm again");
	alarm(1);
}

static void kick_watchdog(void)
{
	int fdwatchdog = open("/dev/watchdog", O_RDWR);
	if (fdwatchdog != -1)
	{
		write(fdwatchdog, "1", 1);
		close(fdwatchdog);
	}
}
