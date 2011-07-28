/*
    Sylverant Patch Server

    Copyright (C) 2009, 2010, 2011 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*  To give credit where credit is due... This program is based in large part
    upon information obtained by reading the source of Tethealla Patch Server
    (Sylverant started as a port of Tethealla to *nix). Tethealla Patch Server
    is Copyright (C) 2008 Terry Chatman Jr. and is also released under the
    GPLv3. This code however isn't directly started from that code, I wrote
    Sylverant Patch Server based on what I learned from reading the code, not
    from the code itself (I documented it (and studied PSOBB's responses to
    develop the documents fully), and based this on my documents). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <sylverant/config.h>
#include <sylverant/debug.h>
#include <sylverant/mtwist.h>
#include <sylverant/encryption.h>
#include <sylverant/checksum.h>

#include "patch_packets.h"
#include "patch_server.h"

#ifdef ENABLE_IPV6
#define NUM_PORTS 10
#else
#define NUM_PORTS 5
#endif

/* The ports to listen on. */
#define PC_PATCH_PORT   10000
#define PC_DATA_PORT    10001
#define WEB_PORT        10002
#define BB_PATCH_PORT   11000
#define BB_DATA_PORT    11001

static const int ports[NUM_PORTS][3] = {
    { AF_INET , PC_PATCH_PORT, CLIENT_TYPE_PC_PATCH },
    { AF_INET , PC_DATA_PORT , CLIENT_TYPE_PC_DATA  },
    { AF_INET , WEB_PORT     , CLIENT_TYPE_WEB      },
    { AF_INET , BB_PATCH_PORT, CLIENT_TYPE_BB_PATCH },
    { AF_INET , BB_DATA_PORT , CLIENT_TYPE_BB_DATA  },
#ifdef ENABLE_IPV6
    { AF_INET6, PC_PATCH_PORT, CLIENT_TYPE_PC_PATCH },
    { AF_INET6, PC_DATA_PORT , CLIENT_TYPE_PC_DATA  },
    { AF_INET6, WEB_PORT     , CLIENT_TYPE_WEB      },
    { AF_INET6, BB_PATCH_PORT, CLIENT_TYPE_BB_PATCH },
    { AF_INET6, BB_DATA_PORT , CLIENT_TYPE_BB_DATA  }
#endif
};

static patch_config_t *cfg;

static unsigned char recvbuf[65536];

static struct client_queue clients = TAILQ_HEAD_INITIALIZER(clients);
static int client_count = 0;

static sigjmp_buf jmpbuf;
static volatile sig_atomic_t rehash = 0;
static volatile sig_atomic_t canjump = 0;
static int dont_daemonize = 0;

/* Forward declaration... */
static void rehash_files();

/* Create a new connection, storing it in the list of clients. */
static patch_client_t *create_connection(int sock, int type,
                                         struct sockaddr *ip, socklen_t size) {
    patch_client_t *rv;
    uint32_t svect, cvect;

    /* Allocate the space for the new client. */
    rv = (patch_client_t *)malloc(sizeof(patch_client_t));

    if(!rv) {
        return NULL;
    }

    memset(rv, 0, sizeof(patch_client_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->type = type;
    memcpy(&rv->ip_addr, ip, size);

    /* Is the user on IPv6? */
    if(ip->sa_family == AF_INET6) {
        rv->is_ipv6 = 1;
    }

    /* Generate the encryption keys for the client and server. */
    cvect = (uint32_t)genrand_int32();
    svect = (uint32_t)genrand_int32();

    CRYPT_CreateKeys(&rv->client_cipher, &cvect, CRYPT_PC);
    CRYPT_CreateKeys(&rv->server_cipher, &svect, CRYPT_PC);

    /* Send the client the welcome packet, or die trying. */
    if(send_welcome(rv, svect, cvect)) {
        close(sock);
        free(rv);
        return NULL;
    }

    /* Initialize the file list */
    TAILQ_INIT(&rv->files);

    /* Insert it at the end of our list, and we're done. */
    TAILQ_INSERT_TAIL(&clients, rv, qentry);

    ++client_count;

    return rv;
}

/* Destroy a connection, closing the socket and removing it from the list. */
static void destroy_connection(patch_client_t *c) {
    patch_cfile_t *i, *tmp;

    TAILQ_REMOVE(&clients, c, qentry);

    i = TAILQ_FIRST(&c->files);

    while(i) {
        tmp = TAILQ_NEXT(i, qentry);
        free(i);
        i = tmp;
    }

    if(c->sock >= 0) {
        close(c->sock);
    }

    if(c->recvbuf) {
        free(c->recvbuf);
    }

    if(c->sendbuf) {
        free(c->sendbuf);
    }

    free(c);

    --client_count;
}

/* Send the patch packets needed to change the client's current directory to the
   given destination. */
static int change_directory(patch_client_t *c, const char cur[],
                            const char dst[]) {
    char *s1, *s2, *d1, *d2, *t1, *t2;
    int rv = 0;

    /* If the current and destination are the same directory, return. */
    if(!strcmp(cur, dst)) {
        return 0;
    }

    /* Otherwise, split up the two directories, and figure out where they
       differ. */
    s1 = strdup(cur);
    s2 = strdup(dst);

    t1 = strtok_r(s1, "/", &d1);
    t2 = strtok_r(s2, "/", &d2);

    while(t1 && t2 && !strcmp(t1, t2)) {
        t1 = strtok_r(NULL, "/", &d1);
        t2 = strtok_r(NULL, "/", &d2);
    }

    /* If t1 is non-NULL, we need to go up the tree as many times as we have
       path components left to be parsed. */
    while(t1) {
        if(send_simple(c, PATCH_ONE_DIR_UP)) {
            rv = -1;
            goto out;
        }

        t1 = strtok_r(NULL, "/", &d1);
    }

    /* Now, if t2 is non-NULL, we need to go down the tree as many times as we
       have path components left to be parsed. */
    while(t2) {
        if(send_chdir(c, t2)) {
            rv = -1;
            goto out;
        }

        t2 = strtok_r(NULL, "/", &d2);
    }

out:
    /* We should be where we belong, clean up. */
    free(s1);
    free(s2);

    return rv;
}

/* Send the list of files to check for patching to the client. */
static int send_file_list(patch_client_t *c, struct file_queue *q) {
    uint32_t filenum = 0;
    patch_file_t *i;
    char dir[PATH_MAX], dir2[PATH_MAX];
    char *bn;
    int dlen;

    /* Send the initial chdir "." packet */
    if(send_chdir(c, ".")) {
        return -1;
    }

    strcpy(dir, "");

    /* Loop through each patch file, sending the appropriate packets for it. */
    TAILQ_FOREACH(i, q, qentry) {
        bn = strrchr(i->filename, '/');

        if(bn) {
            bn += 1;
            dlen = strlen(i->filename) - strlen(bn) - 1;
        }
        else {
            dlen = 0;
            bn = i->filename;
        }

        /* Copy over the directory that the file exists in. */
        strncpy(dir2, i->filename, dlen);
        dir2[dlen] = 0;

        /* Change the directory the client is in, if appropriate. */
        if(change_directory(c, dir, dir2)) {
            return -3;
        }

        /* Send the file info request. */
        if(send_file_info(c, filenum, bn)) {
            return -2;
        }

        /* We're now in dir2, so save it for the next pass. */
        strcpy(dir, dir2);
        ++filenum;
    }

    /* Change back to the base directory. */
    if(change_directory(c, dir, "")) {
        return -3;
    }

    /* Tethealla always preceeds the done packet with a one-directory up packet,
       so we probably should too. */
    if(send_simple(c, PATCH_ONE_DIR_UP)) {
        return -1;
    }

    /* Send the file list complete marker. */
    if(send_simple(c, PATCH_INFO_FINISHED)) {
        return -1;
    }

    return 0;
}

/* Fetch the given patch index. */
static patch_file_t *fetch_patch(uint32_t idx, struct file_queue *q) {
    patch_file_t *i = TAILQ_FIRST(q);

    while(i && idx) {
        i = TAILQ_NEXT(i, qentry);
        --idx;
    }

    return i;
}

/* Save the file info sent by the client in their list. */
static int store_file(patch_client_t *c, patch_file_info_reply *pkt) {
    patch_cfile_t *n;
    patch_file_t *f;
    patch_file_entry_t *ent;

    if(c->type == CLIENT_TYPE_PC_DATA) {
        f = fetch_patch(LE32(pkt->patch_id), &cfg->pc_files);
    }
    else {
        f = fetch_patch(LE32(pkt->patch_id), &cfg->bb_files);
    }

    if(!f) {
        return -1;
    }

    /* Add it to the list only if we need to send it. */
    if(f->flags & PATCH_FLAG_NO_IF) {
        /* With a single entry, this is easy... */
        if(f->entries->checksum != LE32(pkt->checksum) ||
           f->entries->size != LE32(pkt->size)) {
            n = (patch_cfile_t *)malloc(sizeof(patch_cfile_t));

            if(!n) {
                perror("malloc");
                return -1;
            }

            /* Store the file info. */
            n->file = f;
            n->ent = f->entries;

            /* Add it to the list. */
            TAILQ_INSERT_TAIL(&c->files, n, qentry);
        }
    }
    else {
        ent = f->entries;

        while(ent) {
            if(ent->client_checksum == LE32(pkt->checksum) ||
               ((f->flags & PATCH_FLAG_HAS_ELSE) && !ent->next &&
                 (ent->checksum != LE32(pkt->checksum) ||
                  ent->size != LE32(pkt->size)))) {
                n = (patch_cfile_t *)malloc(sizeof(patch_cfile_t));

                if(!n) {
                    perror("malloc");
                    return -1;
                }

                /* Store the file info. */
                n->file = f;
                n->ent = ent;

                /* Add it to the list. */
                TAILQ_INSERT_TAIL(&c->files, n, qentry);
                break;
            }

            ent = ent->next;
        }
    }

    return 0;
}

/* Act on a list done packet from the client. */
static int handle_list_done(patch_client_t *c) {
    uint32_t files = 0, size = 0;
    patch_cfile_t *i, *tmp;
    char dir[PATH_MAX], dir2[PATH_MAX];
    char *bn;
    int dlen;

    /* If we don't have anything to send, send out the send done packet. */
    if(TAILQ_EMPTY(&c->files)) {
        goto done;
    }

    /* If we've got files to send and we haven't started yet, start out. */
    if(c->sending_data == 0) {
        c->sending_data = 1;

        /* Look through the list, and tabulate the data we need to send. */
        TAILQ_FOREACH(i, &c->files, qentry) {
            ++files;
            size += i->ent->size;
        }

        /* Send the informational packet telling about what we're sending. */
        if(send_send_info(c, size, files)) {
            return -2;
        }

        /* Send the initial chdir "." packet */
        if(send_chdir(c, ".")) {
            return -1;
        }

        return 0;
    }

    /* Find the first thing on the top of the list. */
    i = TAILQ_FIRST(&c->files);

    /* Figure out if this is the first file to go, and if we need to figure out
       the current directory. */
    if(c->sending_data == 1) {
        strcpy(dir, "");
    }
    else if(c->sending_data == 2) {
        bn = strrchr(i->file->filename, '/');

        if(bn) {
            bn += 1;
            dlen = strlen(i->file->filename) - strlen(bn) - 1;
        }
        else {
            bn = i->file->filename;
            dlen = 0;
        }

        strncpy(dir, i->file->filename, dlen);
        dir[dlen] = 0;

        /* Figure out what the file is we're going to send. */
        tmp = TAILQ_NEXT(i, qentry);

        /* Remove the current head, we're done with it. */
        TAILQ_REMOVE(&c->files, i, qentry);
        free(i);
        i = tmp;
    }
    /* If we're just starting on a file, change the directory if appropriate. */
    if(c->sending_data < 3 && i) {
        bn = strrchr(i->file->filename, '/');

        if(bn) {
            bn += 1;
            dlen = strlen(i->file->filename) - strlen(bn) - 1;
        }
        else {
            bn = i->file->filename;
            dlen = 0;
        }

        /* Copy over the directory that the file exists in. */
        strncpy(dir2, i->file->filename, dlen);
        dir2[dlen] = 0;

        /* Change the directory the client is in, if appropriate. */
        if(change_directory(c, dir, dir2)) {
            return -3;
        }

        c->sending_data = 3;

        /* Send the file header. */
        return send_file_send(c, i->ent->size, bn);
    }

    /* If we've got this far and we have a file to send still, send the current
       chunk of the file. */
    if(i) {
        if(c->type == CLIENT_TYPE_PC_DATA) {
            dlen = send_file_chunk(c, i->ent->filename, cfg->pc_dir);
        }
        else {
            dlen = send_file_chunk(c, i->ent->filename, cfg->bb_dir);
        }

        if(dlen < 0) {
            /* Something went wrong, bail. */
            return -4;
        }
        else if(dlen > 0) {
            /* We're done with this file. */
            c->sending_data = 2;
            c->cur_chunk = 0;
            c->cur_pos = 0;
            return send_file_done(c);
        }

        return 0;
    }

    /* Change back to the base directory. dir should be set here, since
       c->sending_data has to be 2 if we're in this state. */
    if(change_directory(c, dir, "")) {
        return -3;
    }

    /* Tethealla always preceeds the done packet with a one-directory up packet,
       so we probably should too? */
    if(send_simple(c, PATCH_ONE_DIR_UP)) {
        return -1;
    }

done:
    c->sending_data = 0;
    return send_simple(c, PATCH_SEND_DONE);
}

/* Print information about this program to stdout. */
static void print_program_info() {
    printf("Sylverant Patch Server version %s\n", VERSION);
    printf("Copyright (C) 2009, 2010, 2011 Lawrence Sebald\n\n");
    printf("This program is free software: you can redistribute it and/or\n"
           "modify it under the terms of the GNU Affero General Public\n"
           "License version 3 as published by the Free Software Foundation.\n\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n\n"
           "You should have received a copy of the GNU Affero General Public\n"
           "License along with this program.  If not, see"
           "<http://www.gnu.org/licenses/>.\n");
}

/* Print help to the user to stdout. */
static void print_help(const char *bin) {
    printf("Usage: %s [arguments]\n"
           "-----------------------------------------------------------------\n"
           "--version       Print version info and exit\n"
           "--verbose       Log many messages that might help debug a problem\n"
           "--quiet         Only log warning and error messages\n"
           "--reallyquiet   Only log error messages\n"
           "--nodaemon      Don't daemonize\n"
           "--help          Print this help and exit\n\n"
           "Note that if more than one verbosity level is specified, the last\n"
           "one specified will be used. The default is --verbose.\n", bin);
    
}

/* Parse any command-line arguments passed in. */
static void parse_command_line(int argc, char *argv[]) {
    int i;

    for(i = 1; i < argc; ++i) {
        if(!strcmp(argv[i], "--version")) {
            print_program_info();
            exit(EXIT_SUCCESS);
        }
        else if(!strcmp(argv[i], "--verbose")) {
            debug_set_threshold(DBG_LOG);
        }
        else if(!strcmp(argv[i], "--quiet")) {
            debug_set_threshold(DBG_WARN);
        }
        else if(!strcmp(argv[i], "--reallyquiet")) {
            debug_set_threshold(DBG_ERROR);
        }
        else if(!strcmp(argv[i], "--nodaemon")) {
            dont_daemonize = 1;
        }
        else if(!strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }
        else {
            printf("Illegal command line argument: %s\n", argv[i]);
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

/* Load the configuration file and print out parameters with DBG_LOG. */
static void load_config() {
    char filename[strlen(sylverant_directory) + 25];
    patch_config_t *tmp;

    sprintf(filename, "%s/config/patch_config.xml", sylverant_directory);

    if(patch_read_config(filename, &tmp)) {
        debug(DBG_ERROR, "Cannot load patch server configuration file!\n");

        if(!cfg) {
            exit(EXIT_FAILURE);
        }
        else {
            debug(DBG_ERROR, "Using old configuration\n");
        }
    }

    if(cfg) {
        patch_free_config(cfg);
    }

    cfg = tmp;
}

/* Process one patch packet. */
static int process_patch_packet(patch_client_t *c, pkt_header_t *pkt) {
    switch(LE16(pkt->pkt_type)) {
        case PATCH_WELCOME_TYPE:
            if(send_simple(c, PATCH_LOGIN_TYPE)) {
                return -2;
            }
            break;

        case PATCH_LOGIN_TYPE:
            /* TODO: Process login? */
            if(c->type == CLIENT_TYPE_PC_PATCH) {
                if(send_message(c, cfg->pc_welcome, cfg->pc_welcome_size)) {
                    return -2;
                }

#ifdef ENABLE_IPV6
                if(c->is_ipv6) {
                    if(send_redirect6(c, cfg->server_ip6,
                                      htons(PC_DATA_PORT))) {
                        return -2;
                    }

                    c->disconnected = 1;
                    break;
                }
#endif

                if(send_redirect(c, cfg->server_ip, htons(PC_DATA_PORT))) {
                    return -2;
                }
            }
            else {
                if(send_message(c, cfg->bb_welcome, cfg->bb_welcome_size)) {
                    return -2;
                }

#ifdef ENABLE_IPV6
                if(c->is_ipv6) {
                    if(send_redirect6(c, cfg->server_ip6,
                                      htons(BB_DATA_PORT))) {
                        return -2;
                    }

                    c->disconnected = 1;
                    break;
                }
#endif

                if(send_redirect(c, cfg->server_ip, htons(BB_DATA_PORT))) {
                    return -2;
                }
            }

            /* Force the client to disconnect at this point to prevent problems
               later on down the line if it decides to reconnect before we close
               the current socket. */
            c->disconnected = 1;
            break;

        default:
            return -3;
    }

    return 0;
}

/* Process one data packet. */
static int process_data_packet(patch_client_t *c, pkt_header_t *pkt) {
    switch(LE16(pkt->pkt_type)) {
        case PATCH_WELCOME_TYPE:
            if(send_simple(c, PATCH_LOGIN_TYPE)) {
                return -2;
            }
            break;

        case PATCH_LOGIN_TYPE:
            if(send_simple(c, PATCH_START_LIST)) {
                return -2;
            }

            /* Send the list of patches. */
            if(c->type == CLIENT_TYPE_PC_DATA) {
                if(send_file_list(c, &cfg->pc_files)) {
                    return -2;
                }
            }
            else {
                if(send_file_list(c, &cfg->bb_files)) {
                    return -2;
                }
            }

            break;

        case PATCH_FILE_INFO_REPLY:
            /* Store the file in the list. */
            if(store_file(c, (patch_file_info_reply *)pkt)) {
                return -2;
            }
            break;

        case PATCH_FILE_LIST_DONE:
            /* Check if we have to send anything... */
            if(handle_list_done(c)) {
                return -2;
            }
            break;

        default:
            return -3;
    }

    return 0;
}

/* Read data from a client that is connected to either port. */
static int read_from_client(patch_client_t *c) {
    ssize_t sz;
    uint16_t pkt_sz;
    int rv = 0;
    unsigned char *rbp = recvbuf;
    void *tmp;

    /* If we've got anything buffered, copy it out to the main buffer to make
       the rest of this a bit easier. */
    if(c->recvbuf_cur) {
        memcpy(recvbuf, c->recvbuf, c->recvbuf_cur);
        
    }

    /* Attempt to read, and if we don't get anything, punt. */
    if((sz = recv(c->sock, recvbuf + c->recvbuf_cur, 65536 - c->recvbuf_cur,
                  0)) <= 0) {
        if(sz == -1) {
            perror("recv");
        }

        return -1;
    }

    sz += c->recvbuf_cur;
    c->recvbuf_cur = 0;

    /* As long as what we have is long enough, decrypt it. */
    if(sz >= 4) {
        while(sz >= 4) {
            /* Decrypt the packet header so we know what exactly we're looking
               for, in terms of packet length. */
            if(!c->pkt.pkt_type) {
                memcpy(&c->pkt, rbp, 4);
                CRYPT_CryptData(&c->client_cipher, &c->pkt, 4, 0);
            }

            pkt_sz = LE16(c->pkt.pkt_len);

            /* Do we have the whole packet? */
            if(sz >= (ssize_t)pkt_sz) {
                /* Yes, we do, decrypt it. */
                CRYPT_CryptData(&c->client_cipher, rbp + 4, pkt_sz - 4, 0);
                memcpy(rbp, &c->pkt, 4);

                /* Pass it onto the correct handler. */
                if(c->type == CLIENT_TYPE_PC_PATCH ||
                   c->type == CLIENT_TYPE_BB_PATCH) {
                    rv = process_patch_packet(c, (pkt_header_t *)rbp);
                }
                else if(c->type == CLIENT_TYPE_PC_DATA ||
                        c->type == CLIENT_TYPE_BB_DATA) {
                    rv = process_data_packet(c, (pkt_header_t *)rbp);
                }

                rbp += pkt_sz;
                sz -= pkt_sz;
                c->pkt.pkt_type = c->pkt.pkt_len = 0;
            }
            else {
                /* Nope, we're missing part, break out of the loop, and buffer
                   the remaining data. */
                break;
            }
        }
    }

    /* If we've still got something left here, buffer it for the next pass. */
    if(sz) {
        /* Reallocate the recvbuf for the client if its too small. */
        if(c->recvbuf_size < sz) {
            tmp = realloc(c->recvbuf, sz);

            if(!tmp) {
                perror("realloc");
                return -1;
            }

            c->recvbuf = (unsigned char *)tmp;
            c->recvbuf_size = sz;
        }

        memcpy(c->recvbuf, rbp, sz);
        c->recvbuf_cur = sz;
    }
    else {
        /* Free the buffer, if we've got nothing in it. */
        free(c->recvbuf);
        c->recvbuf = NULL;
        c->recvbuf_size = 0;
    }

    return rv;
}

static const void *my_ntop(struct sockaddr_storage *addr,
                           char str[INET6_ADDRSTRLEN]) {
    int family = addr->ss_family;

    switch(family) {
        case AF_INET:
        {
            struct sockaddr_in *a = (struct sockaddr_in *)addr;
            return inet_ntop(family, &a->sin_addr, str, INET6_ADDRSTRLEN);
        }

        case AF_INET6:
        {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;
            return inet_ntop(family, &a->sin6_addr, str, INET6_ADDRSTRLEN);
        }
    }

    return NULL;
}

/* Connection handling loop... */
static void handle_connections(int sockets[NUM_PORTS]) {
    int sock, nfds, j;
    socklen_t len;
    struct sockaddr_storage addr;
    struct sockaddr *addr_p = (struct sockaddr *)&addr;
    char ipstr[INET6_ADDRSTRLEN];
    fd_set readfds, writefds;
    struct timeval timeout;
    patch_client_t *i, *tmp;
    ssize_t sent;
    
    for(;;) {
        /* Set this up in case a signal comes in during the time between calling
           this and the select(). */
        if(!sigsetjmp(jmpbuf, 1)) {
            canjump = 1;
        }

        /* If we need to, rehash the patches and welcome message. */
        if(rehash && client_count == 0) {
            canjump = 0;
            rehash_files();
            rehash = 0;
            canjump = 1;
        }

        /* Clear out the fd_sets and set the timeout value for select. */
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        nfds = 0;

        /* Set the timeout differently if we're waiting on a rehash. */
        if(!rehash) {
            timeout.tv_sec = 9001;
        }
        else {
            timeout.tv_sec = 10;
        }

        timeout.tv_usec = 0;

        /* Fill the sockets into the fd_set so we can use select below. */
        TAILQ_FOREACH(i, &clients, qentry) {
            FD_SET(i->sock, &readfds);

            /* Only add to the write fd_set if we have something to send. */
            if(i->sendbuf_cur || i->sending_data) {
                FD_SET(i->sock, &writefds);
            }

            nfds = nfds > i->sock ? nfds : i->sock;
        }

        /* Add the listening sockets to the read fd_set if we aren't waiting on
           all clients to disconnect for a rehash operation. Since they won't be
           in the fd_set if we are waiting, we don't have to worry about clients
           connecting while we're trying to do a rehash operation. */
        if(!rehash) {
            for(j = 0; j < NUM_PORTS; ++j) {
                FD_SET(sockets[j], &readfds);
                nfds = nfds > sockets[j] ? nfds : sockets[j];
            }
        }

        /* Wait to see if we get any incoming data. */
        if(select(nfds + 1, &readfds, &writefds, NULL, &timeout) > 0) {
            /* Make sure a rehash event doesn't interrupt any of this stuff,
               it will get handled the next time through the loop. */
            canjump = 0;

            /* Check the listening sockets first. */
            for(j = 0; j < NUM_PORTS; ++j) {
                if(FD_ISSET(sockets[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((sock = accept(sockets[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }
                    else {
                        if(ports[j][2] == CLIENT_TYPE_WEB) {
                            /* Send the number of connected clients, and close
                               the socket. */
                            nfds = LE32(client_count);
                            send(sock, &nfds, 4, 0);
                            close(sock);
                            continue;
                        }

                        if(!create_connection(sock, ports[j][2], addr_p, len)) {
                            close(sock);
                        }
                        else {
                            my_ntop(&addr, ipstr);
                            if(ports[j][2] == CLIENT_TYPE_PC_PATCH ||
                               ports[j][2] == CLIENT_TYPE_BB_PATCH) {
                                debug(DBG_LOG, "Accepted PATCH connection "
                                      "from %s\n", ipstr);
                            }
                            else {
                                debug(DBG_LOG, "Accepted DATA connection "
                                      "from %s\n", ipstr);
                            }
                        }
                    }
                }
            }

            TAILQ_FOREACH(i, &clients, qentry) {
                /* Check if this connection was trying to send us something. */
                if(FD_ISSET(i->sock, &readfds)) {
                    if(read_from_client(i)) {
                        i->disconnected = 1;
                    }
                }

                /* If we have anything to write, check if we can right now. */
                if(FD_ISSET(i->sock, &writefds)) {
                    if(i->sendbuf_cur) {
                        sent = send(i->sock, i->sendbuf + i->sendbuf_start,
                                    i->sendbuf_cur - i->sendbuf_start, 0);

                        /* If we fail to send, and the error isn't EAGAIN,
                           bail. */
                        if(sent == -1) {
                            if(errno != EAGAIN) {
                                i->disconnected = 1;
                            }
                        }
                        else {
                            i->sendbuf_start += sent;

                            /* If we've sent everything, free the buffer. */
                            if(i->sendbuf_start == i->sendbuf_cur) {
                                free(i->sendbuf);
                                i->sendbuf = NULL;
                                i->sendbuf_cur = 0;
                                i->sendbuf_size = 0;
                                i->sendbuf_start = 0;
                            }
                        }
                    }
                    else if(i->sending_data) {
                        if(handle_list_done(i)) {
                            i->disconnected = 1;
                        }
                    }
                }
            }
        }

        /* Clean up any dead connections (its not safe to do a TAILQ_REMOVE in
           the middle of a TAILQ_FOREACH, and destroy_connection does indeed
           use TAILQ_REMOVE). */
        canjump = 0;
        i = TAILQ_FIRST(&clients);

        while(i) {
            tmp = TAILQ_NEXT(i, qentry);

            if(i->disconnected) {
                destroy_connection(i);
            }

            i = tmp;
        }
    }
}

static void rehash_files() {
    debug(DBG_LOG, "Reloading configuration...\n");
    load_config();
}

/* Signal handler registered to SIGHUP. Sending SIGHUP to the program will cause
   it to rehash its configuration and rescan the patches directory at its next
   earliest convenience. */
static void sig_handler(int signum) {
    rehash = 1;

    if(canjump) {
        canjump = 0;
        siglongjmp(jmpbuf, 1);
    }
}

/* Install the signal handler for SIGHUP. Calls the above function. */
static void install_signal_handler() {
    struct sigaction sa;

    sa.sa_handler = &sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    debug(DBG_LOG, "Installing SIGHUP handler...\n");

    if(sigaction(SIGHUP, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* Ignore SIGPIPEs */
    sa.sa_handler = SIG_IGN;

    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static int open_sock(int family, uint16_t port) {
    int sock = -1, val;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;

    /* Create the socket and listen for connections. */
    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if(sock < 0) {
        perror("socket");
        return -1;
    }

    /* Set SO_REUSEADDR so we don't run into issues when we kill the login
       server bring it back up quickly... */
    val = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int))) {
        perror("setsockopt");
        /* We can ignore this error, pretty much... its just a convenience thing
           anyway... */
    }

    if(family == PF_INET) {
        addr.sin_family = family;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        memset(addr.sin_zero, 0, 8);

        if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
            perror("bind");
            close(sock);
            return -1;
        }

        if(listen(sock, 10)) {
            perror("listen");
            close(sock);
            return -1;
        }
    }
    else if(family == PF_INET6) {
        /* Since we create separate sockets for IPv4 and IPv6, make this one
           support ONLY IPv6. */
        val = 1;
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(int))) {
            perror("setsockopt IPV6_V6ONLY");
            close(sock);
            return -1;
        }

        memset(&addr6, 0, sizeof(struct sockaddr_in6));

        addr6.sin6_family = family;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port);

        if(bind(sock, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6))) {
            perror("bind");
            close(sock);
            return -1;
        }

        if(listen(sock, 10)) {
            perror("listen");
            close(sock);
            return -1;
        }
    }
    else {
        debug(DBG_ERROR, "Unknown socket family\n");
        close(sock);
        return -1;
    }

    return sock;
}

static void open_log() {
    FILE *dbgfp;

    dbgfp = fopen("logs/patch_debug.log", "a");

    if(!dbgfp) {
        debug(DBG_ERROR, "Cannot open log file\n");
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    debug_set_file(dbgfp);
}

int main(int argc, char *argv[]) {
    int sockets[NUM_PORTS];
    int i;

    /* Parse the command line and read our configuration. */
    parse_command_line(argc, argv);
    load_config();

    /* Change to the Sylverant data directory for all future stuff. */
    chdir(sylverant_directory);

    /* If we're still alive and we're supposed to daemonize, do it now. */
    if(!dont_daemonize) {
        open_log();

        if(daemon(1, 0)) {
            debug(DBG_ERROR, "Cannot daemonize\n");
            perror("daemon");
            exit(EXIT_FAILURE);
        }
    }

    /* Initialize the random-number generator. */
    init_genrand(time(NULL));

    /* Install the SIGHUP signal handler. */
    install_signal_handler();

    /* Open up all the ports */
    for(i = 0; i < NUM_PORTS; ++i) {
        sockets[i] = open_sock(ports[i][0], ports[i][1]);

        if(sockets[i] < 0) {
            debug(DBG_ERROR, "Error opening port %d (%s), exiting\n",
                  ports[i][1], ports[i][0] == AF_INET ? "IPv4" : "IPv6");
            exit(EXIT_FAILURE);
        }
    }

    /* Enter the main connection handling loop. */
    handle_connections(sockets);

    /* Clean up after ourselves... */
    patch_free_config(cfg);

    return 0;
}
