#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <limits.h>

int opt_set = 0;
int opt_dironly = 0;
int retval = 0;

#define USERNAME_MAX  32
#define GROUPNAME_MAX 32

struct uhustat {
	char file[PATH_MAX + 1];
	char linkto[PATH_MAX + 1];
	long uid;
	long gid;
	char username[USERNAME_MAX + 1];
	char groupname[GROUPNAME_MAX + 1];
	char type;
	unsigned int mode;
	int minor;
	int major;
	long size;
	long modtime;
} uhustat;

void print_escape (const char *s)
{
	while (*s) {
		if (*s <= 32) {
			putchar('\\');
			if (*s == ' ') putchar('s');
			else if (*s == '\n') putchar('n');
			else if (*s == '\t') putchar('t');
			else printf("%03o", *s);
		} else {
			if (*s == '\\') putchar('\\');
			putchar(*s);
		}
		s++;
	}
}

int unescape (const char *s, char *d)
{
	while (*s) {
		if (*s != '\\') {
			*(d++) = *(s++);
			continue;
		}
		s++;
		if (*s == 's') *(d++) = ' ';
		else if (*s == 'n') *(d++) = '\n';
		else if (*s == 't') *(d++) = '\t';
		else if (*s == '\\') *(d++) = '\\';
		else {
			if (*s < '0' || *s > '3' ||
			  *(s+1) < '0' || *(s+1) > '7' ||
			  *(s+2) < '0' || *(s+2) > '7') return -1;
			*(d++) = 64 * (*s - '0') + 8 * (*(s+1) - '0') + *(s+2) - '0';
			s += 2;
		}
		s++;
	}
	*d = '\0';
	return 0;
}

int get_uhustat (const char *file, struct uhustat *uhustat)
{
	int i;
	struct stat st;
	struct passwd *passwd;
	struct group *group;

	if (lstat(file, &st) < 0) {
		fprintf(stderr, "uhu-stat: lstat() sikertelen: %s\n",
		  strerror(errno));
		return -1;
	}

	strcpy(uhustat->file, file);

	uhustat->uid = st.st_uid;
	uhustat->gid = st.st_gid;
	if ((passwd = getpwuid(st.st_uid)) == NULL) {
		strcpy(uhustat->username, "-");
	} else {
		strcpy(uhustat->username, passwd->pw_name);
	}
	if ((group = getgrgid(st.st_gid)) == NULL) {
		strcpy(uhustat->groupname, "-");
	} else {
		strcpy(uhustat->groupname, group->gr_name);
	}

	if (S_ISREG(st.st_mode)) {
		uhustat->type='f';
	} else if (S_ISDIR(st.st_mode)) {
		uhustat->type='d';
	} else if (S_ISLNK(st.st_mode)) {
		uhustat->type='l';
	} else if (S_ISCHR(st.st_mode)) {
		uhustat->type='c';
	} else if (S_ISBLK(st.st_mode)) {
		uhustat->type='b';
	} else if (S_ISFIFO(st.st_mode)) {
		uhustat->type='p';
	} else if (S_ISSOCK(st.st_mode)) {
		uhustat->type='s';
	} else {
		fprintf(stderr, "uhu-stat: ismeretlen fájltípus\n");
		return -1;
	}

	if (uhustat->type == 'b' || uhustat->type == 'c') {
		uhustat->major = (((st.st_rdev) >> 8) & 0xff);
		uhustat->minor = ((st.st_rdev) & 0xff);
	} else {
		uhustat->major = -1;
		uhustat->minor = -1;
	}

	if (uhustat->type == 'l') {
		i = readlink(file, uhustat->linkto, PATH_MAX);
		if (i >= 0) {
			uhustat->linkto[i] = '\0';
		} else {
			fprintf(stderr, "uhu-stat: readlink() sikertelen: %s\n",
			  strerror(errno));
			return -1;
		}
	} else {
		uhustat->linkto[0] = '\0';
	}

	if (uhustat->type == 'f') {
		uhustat->size = st.st_size;
	} else {
		uhustat->size = -1;
	}

	uhustat->mode = st.st_mode & 07777;
	uhustat->modtime = st.st_mtime;

	return 0;
}

int print_uhustat (const struct uhustat *uhustat)
{
	char filemode_print[5];
	char major_print[16];
	char minor_print[16];
	char size_print[16];

	sprintf(filemode_print, "%04o", uhustat->mode);
	if (filemode_print[0] == '0') filemode_print[0] = ' ';
	if (uhustat->type == 'b' || uhustat->type == 'c') {
		sprintf(major_print, "%d", uhustat->major);
		sprintf(minor_print, "%d", uhustat->minor);
	} else {
		strcpy(major_print, "-");
		strcpy(minor_print, "-");
	}
	if (uhustat->type == 'f') {
		sprintf(size_print, "%ld", uhustat->size);
	} else {
		strcpy(size_print, "-");
	}

	printf("%5ld %-8s %5ld %-8s %c %s %3s %3s %8s %10ld ",
	  uhustat->uid, uhustat->username, uhustat->gid, uhustat->groupname,
	  uhustat->type, filemode_print, major_print, minor_print,
	  size_print, uhustat->modtime);

	print_escape(uhustat->file);

	if (uhustat->type == 'l') {
		printf(" -> ");
		print_escape(uhustat->linkto);
	}

	printf("\n");
	return 0;
}

int parse_uhustat (char *line, struct uhustat *uhustat)
{
	char *uid, *username, *gid, *groupname, *type, *mode;
	char *major, *minor, *size, *modtime;
	char *file, *arrow, *linkto, *garbage;
	char dummy;

	uid = strtok(line, " ");
	username = strtok(NULL, " ");
	gid = strtok(NULL, " ");
	groupname = strtok(NULL, " ");
	type = strtok(NULL, " ");
	mode = strtok(NULL, " ");
	major = strtok(NULL, " ");
	minor = strtok(NULL, " ");
	size = strtok(NULL, " ");
	modtime = strtok(NULL, " ");
	file = strtok(NULL, " ");
	arrow = strtok(NULL, " ");
	linkto = strtok(NULL, " ");
	garbage = strtok(NULL, " ");

	if (file == NULL) {
		fprintf(stderr, "uhu-stat: túl kevés oszlop\n");
		return -1;
	}

	if (sscanf(uid, "%ld%c", &uhustat->uid, &dummy) != 1) {
		fprintf(stderr, "uhu-stat: hibás uid érték\n");
		return -1;
	}

	if (strlen(username) > USERNAME_MAX) {
		fprintf(stderr, "uhu-stat: túl hosszú username érték\n");
		return -1;
	}
	strcpy(uhustat->username, username);

	if (sscanf(gid, "%ld%c", &uhustat->gid, &dummy) != 1) {
		fprintf(stderr, "uhu-stat: hibás gid érték\n");
		return -1;
	}

	if (strlen(groupname) > GROUPNAME_MAX) {
		fprintf(stderr, "uhu-stat: túl hosszú groupname érték\n");
		return -1;
	}
	strcpy(uhustat->groupname, groupname);

	if (strlen(type) != 1 || strchr("fdlbcps", type[0]) == NULL) {
		fprintf(stderr, "uhu-stat: hibás fájltípus\n");
		return -1;
	}
	uhustat->type = type[0];

	if (sscanf(mode, "%o%c", &uhustat->mode, &dummy) != 1 ||
	  uhustat->mode > 07777) {
		fprintf(stderr, "uhu-stat: hibás mode érték\n");
		return -1;
	}

	if (uhustat->type != 'b' && uhustat->type != 'c') {
		if (!strcmp(major, "-")) {
			uhustat->major = -1;
		} else {
			fprintf(stderr, "uhu-stat: hibás major érték\n");
			return -1;
		}
		if (!strcmp(minor, "-")) {
			uhustat->minor = -1;
		} else {
			fprintf(stderr, "uhu-stat: hibás minor érték\n");
			return -1;
		}
	} else {
		if (sscanf(major, "%d%c", &uhustat->major, &dummy) != 1) {
			fprintf(stderr, "uhu-stat: hibás major érték\n");
			return -1;
		}
		if (sscanf(minor, "%d%c", &uhustat->minor, &dummy) != 1) {
			fprintf(stderr, "uhu-stat: hibás minor érték\n");
			return -1;
		}
	}

	if (uhustat->type != 'f') {
		if (!strcmp(size, "-")) {
			uhustat->size = -1;
		} else {
			fprintf(stderr, "uhu-stat: hibás size érték\n");
			return -1;
		}
	} else {
		if (sscanf(size, "%ld%c", &uhustat->size, &dummy) != 1) {
			fprintf(stderr, "uhu-stat: hibás size érték\n");
			return -1;
		}
	}

	if (sscanf(modtime, "%ld%c", &uhustat->modtime, &dummy) != 1) {
		fprintf(stderr, "uhu-stat: hibás size érték\n");
		return -1;
	}

	if (unescape(file, uhustat->file) < 0) {
		fprintf(stderr, "uhu-stat: hibás fájlnév\n");
		return -1;
	}

	if (uhustat->type != 'l') {
		if (arrow != NULL) {
			fprintf(stderr, "uhu-stat: túl sok oszlop\n");
			return -1;
		}
	} else {
		if (linkto == NULL) {
			fprintf(stderr, "uhu-stat: túl kevés oszlop\n");
			return -1;
		}
		if (strcmp(arrow, "->")) {
			fprintf(stderr, "uhu-stat: hibás nyíl\n");
			return -1;
		}
		if (garbage != NULL) {
			fprintf(stderr, "uhu-stat: túl sok oszlop\n");
			return -1;
		}
		if (unescape(linkto, uhustat->linkto) < 0) {
			fprintf(stderr, "uhu-stat: hibás szimlink érték\n");
			return -1;
		}
	}

	return 0;
}

int main (int argc, char *argv[])
{
	int c;

	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "sd")) != -1) {
		switch (c) {
		  case 's':
			opt_set = 1;
			break;
		  case 'd':
			opt_dironly = 1;
			break;
		  case '?':
		  case ':':
			exit(1);
		}
	}

	if (!opt_set) {
		struct uhustat uhustat;

		while (optind < argc) {
			if (get_uhustat(argv[optind++], &uhustat) < 0) {
				retval = 1;
				continue;
			}
			print_uhustat(&uhustat);
		}
	} else {
		ssize_t i;
		struct uhustat uhustat;
		char *inputline = NULL;
		size_t inputlinesize = 0;

		while ((i = getline(&inputline, &inputlinesize, stdin)) >= 0) {
			if (i >= 0 && inputline[i-1] == '\n')
			  inputline[i-1] = 0;
			if (parse_uhustat(inputline, &uhustat) < 0)
			  continue;
			if (opt_dironly && uhustat.type != 'd') continue;
			if (lchown(uhustat.file, uhustat.uid, uhustat.gid) < 0) {
				fprintf(stderr, "uhu-stat: lchown() sikertelen: %s: %s\n",
				  uhustat.file, strerror(errno));
				retval = 1;
				continue;
			}
			if (uhustat.type == 'l') continue;
			if (chmod(uhustat.file, uhustat.mode) < 0) {
				fprintf(stderr, "uhu-stat: chmod() sikertelen: %s: %s\n",
				  uhustat.file, strerror(errno));
				retval = 1;
				continue;
			}
		}
	}
	return retval;
}

