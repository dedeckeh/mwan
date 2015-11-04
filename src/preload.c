/*
 * The source code form of this Open Source Project components is
 * subject to the terms of the Clear BSD license.
 * You can redistribute it and/or modify it under the terms of the
 * Clear BSD License (http://directory.fsf.org/wiki/License:ClearBSD)
 * See COPYING file/LICENSE file for more details.
 * This software project does also include third party Open Source
 * Software: See COPYING file/LICENSE file for more details.
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>

#define PRELOAD_CONFIG "/var/etc/mwan.config"

static void init() __attribute__ ((constructor));
static int (*realsocket)(int domain, int type, int protocol) = NULL;

static int hook=0;
static int fwmark= 0;
static const int *val = &fwmark;

/**
 * Turn the source path into an absolute path.
 *
 * @param srcpath unqualified path that needs expanding
 * @param maxsize maximum size of the qualified path buffer
 * @param qualified_path resulting fully qualified path
 *
 * @return 0 on success
 */
static int expand_path(const char *srcpath, int maxsize, char *qualified_path)
{
    char path[PATH_MAX];
    char *sptr;
    int ret= -1;
    char *dptr;
    char *maxdptr = &qualified_path[maxsize];

    // check for relative path
    if (srcpath[0] != '/') {
        if (!getcwd(path, sizeof(path)-1))
            goto err;

        sptr = &path[strlen(path)];
        if (sptr[-1] != '/')
            *sptr++ = '/';

    } else {
        sptr= path;
    }

    // check for possible overrun
    if (strlen(srcpath) + (sptr-path) >= sizeof(path))
        goto err;

    // append user specified path
    strcpy(sptr, srcpath);

    sptr = path;
    dptr = qualified_path;

    *dptr++ = '/';
    while(*sptr != '\0') {
        if (*sptr == '/') {
            sptr++;
            continue;
        }

        if (*sptr == '.') {

            // skip single dot
            if (sptr[1] == '\0' || sptr[1] == '/') {
                sptr++;
                continue;
            }

            // ..
            if (sptr[1] == '.') {

                // dot dot or dot dot slash
                if (sptr[2] == '\0' || sptr[2] == '/') {
                    sptr += 2;

                    // don't move up when at root
                    if (dptr == &qualified_path[1])
                        continue;

                    // move up a directory, ie. strip last added component
                    while((--dptr)[-1] != '/');
                    continue;
                }
            }
        }

        // copy current path component to destination
        while(*sptr != '\0' && *sptr != '/') {

            // prevent buffer overrun
            if (dptr == maxdptr)
                goto err;

            *dptr++ = *sptr++;
        }

        *dptr++ = '/';
    }

    // strip last slash, unless we're at the root
    if (dptr != &qualified_path[1] && *(dptr-1) == '/')
        dptr--;

    // null terminate the path
    *dptr = '\0';

    ret= 0;

err:
    return ret;
}

/**
 * @brief Verify if socket() should be redirected.
 *
 * Find the executable that is currently running and expand it's path, then
 * check the configuration file for an extry specifying this executable.
 * If a match is found, the command line arguments are string matched with
 * the config file, if an argument match is specified for the executable.
 *
 * If all the tests are positive, indicate that redirection is required.
 *
 * @return true if redirection is required.
 */
static int should_redirect_socket()
{
    char cmdline[256];
    int cmdlen;
    int fd= -1;
    int ret= -1;
    char qualified_path[PATH_MAX];
    int len;
    char current[PATH_MAX];
    struct stat st;
    FILE *config= NULL;
    char cmd[256];
    char *args;

    // check if an environment variable SO_MARK is defined and that
    // we can convert the first field to a hex number
    args= getenv("SO_MARK");
    if (args) {
        if (sscanf(args, "%x", &fwmark) == 1)
            return 1;
    }

    // quick check for config file
    if (access(PRELOAD_CONFIG, R_OK) != 0)
        goto err;

    // get ARGV[0] from proc
    fd= open("/proc/self/cmdline", O_RDONLY);
    if (fd == -1) {
        perror("open");
        goto err;
    }

    cmdlen= read(fd, cmdline, sizeof(cmdline)-1);
    close(fd); fd= -1;
    if (cmdlen <= 0) {
        perror("read");
        goto err;
    }
    cmdline[cmdlen] = 0; // NULL terminate
    len = strlen(cmdline);
    if (len+1 > cmdlen)
        args= NULL;
    else
        args= &cmdline[len+1];

    /* Is there a path component specified?
     * /xxxx
     * ../xxx
     * ./xx
     */
    if (cmdline[0] == '/' ||
            (cmdline[0] == '.' && (
                (len >= 2 && cmdline[1] == '.' && cmdline[2] == '/') ||
                (len >= 1 && cmdline[1] == '/'))
             )
            )
        ret= expand_path(cmdline, sizeof(qualified_path), qualified_path);
    else {
        // need to resolve via PATH
        char *path= getenv("PATH");
        char *pe;

        if (!path)
            goto err;

        while(path && path != '\0') {
            pe= strchr(path, ':');
            if (pe) {
                memcpy(current, path, pe-path);
                current[pe-path]= '\0';
                path= pe+1;

                // skip empty PATH part, ie. ::
                if (!strlen(current))
                    continue;
            } else {
                strcpy(current, path);
                path= NULL;
            }

            // append command to path component
            if (strlcat(current, "/", sizeof(current)) >= sizeof(current))
                goto err;
            if (strlcat(current, cmdline, sizeof(current)) >= sizeof(current))
                goto err;

            ret= expand_path(current, sizeof(qualified_path), qualified_path);
            if (ret == 0 && !access(qualified_path, X_OK) &&
                !stat(qualified_path, &st) && S_ISREG(st.st_mode)) {

                // executable file found in the path
                ret= 0;
                break;
            }
        }

    }
    // nothing found or expansion failed
    if (ret)
        goto err;

    ret= -1;

    // rebuild commandline of executable by replacing the NUL bytes
    // by spaces
    if (args) {
        char *ptr = strchr(args, 0);
        while(ptr < &cmdline[cmdlen]) {
            *ptr= ' ';
            ptr = strchr(ptr, 0);
        }
    }

    // qualified_path contains the executable we need to check
    // now check versus local db.
    config= fopen(PRELOAD_CONFIG, "r");
    if (!config)
        goto err;

    while(!feof(config)) {
        int matchlen;
        char *p_match;
        char match[256];

        // read exe name and mark number
        if (fscanf(config, "%255s %x", cmd, &fwmark) != 2)
            goto err;

        // read rest of the line
        if (fgets(match, sizeof(match), config) == NULL)
            goto err;

        // strip trailing CR and whitespaces
        matchlen = strlen(match);
        while (matchlen && (match[matchlen-1] == '\n' || match[matchlen-1] == '\r' || match[matchlen-1] == ' '))
            match[--matchlen] = '\0';

        // skip leading spaces;
        p_match= match;
        while(p_match && *p_match == ' ') {
            p_match++;
            matchlen--;
        }

        // does command match what is specified in the config?
        if (!strcmp(qualified_path, cmd)) {

            // are the arguments also a match?
            if ( matchlen == 0 || (matchlen && strstr(args, p_match))) {
                 ret= 0;
                 break;
            }
        }
    }

err:
    if (config)
        fclose(config);

    if (fd != -1)
        close(fd);

    return ret == 0;
}

/**
 * @brief socket - create an endpoint for communication
 *
 * This function intercepts the real libc() socket() function and
 * checks if for the current executable a firewall mark needs to be
 * set on the socket.
 *
 */
int socket(int domain, int type, int protocol)
{
    int s;
    if (!realsocket) {
        errno = ENFILE;
        return -1;
    }

    s= realsocket(domain, type, protocol);
    if (s != -1 && (domain == AF_INET || domain == AF_INET6) && hook)
        if (setsockopt(s, SOL_SOCKET, SO_MARK, val, sizeof(*val)) < 0)
            perror("setsockopt");

    return s;
}

/**
 * @brief init - get real socket() address and check if redirect is needed.
 *
 * This needs to happen in the constructor, because we can't do it in the
 * actual socket() call as that might cause issues in multi threaded apps
 * where socket() calls are run in parallel. To prevent threading issues,
 * we'd have to use pthread_mutex, but then every app we preload to will
 * include pthreads, which we don't want either.
 */
static void init()
{
    if (!realsocket) {
        realsocket = dlsym(RTLD_NEXT, "socket");
        hook= should_redirect_socket();
    }
}
