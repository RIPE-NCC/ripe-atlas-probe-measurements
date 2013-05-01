/*
cmdtable.h

Commands for perd and ooqd 
*/

int condmv_main(int argc, char *argv[]);
int httpget_main(int argc, char *argv[]);
int httppost_main(int argc, char *argv[]);
int sslgetcert_main(int argc, char *argv[]);

static struct builtin 
{
	const char *cmd;
	int (*func)(int argc, char *argv[]);
} builtin_cmds[]=
{
	{ "condmv", condmv_main },
	{ "httppost", httppost_main },
	{ "sslgetcert", sslgetcert_main },
	{ NULL, 0 }
};

