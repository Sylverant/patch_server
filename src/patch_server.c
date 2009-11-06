/*
    Sylverant Patch Server

    Copyright (C) 2009 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
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

#define VERSION "0.1.0"

/* The offset from the defined server port to install our patch/data server
   sockets. */
#define PATCH_PORT_OFFSET -2000
#define DATA_PORT_OFFSET -1999
#define WEB_PORT_OFFSET -1998

static sylverant_config_t cfg;

static long welcome_msg_size = 0;
static unsigned short *welcome_msg = NULL;
static unsigned char recvbuf[65536];

static struct client_queue clients = TAILQ_HEAD_INITIALIZER(clients);
static struct file_queue files = TAILQ_HEAD_INITIALIZER(files);
static int file_count = 0;
static int client_count = 0;

/* Create a new connection, storing it in the list of clients. */
static patch_client_t *create_connection(int sock, in_addr_t ip, int type) {
    patch_client_t *rv = (patch_client_t *)malloc(sizeof(patch_client_t));
    uint32_t svect, cvect;

    if(!rv) {
        return NULL;
    }

    memset(rv, 0, sizeof(patch_client_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->ip_addr = ip;
    rv->type = type;

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

/* Make the given file descriptor do non-blocking I/O. */
static int make_nonblocking(int fd) {
    int flags;

    if((flags = fcntl(fd, F_GETFL, 0)) < 0) {
        return flags;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
static int send_file_list(patch_client_t *c) {
    uint32_t filenum = 0;
    patch_file_t *i;
    char dir[PATH_MAX], dir2[PATH_MAX];
    char *bn;
    int dlen;

    /* Send the initial chdir "." packet */
    if(send_chdir(c, ".")) {
        return -1;
    }

    strcpy(dir, "patches");

    /* Loop through each patch file, sending the appropriate packets for it. */
    TAILQ_FOREACH(i, &files, qentry) {
        bn = strrchr(i->filename, '/') + 1;
        dlen = strlen(i->filename) - strlen(bn) - 1;

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
    if(change_directory(c, dir, "patches")) {
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
static patch_file_t *fetch_patch(uint32_t idx) {
    patch_file_t *i = TAILQ_FIRST(&files);

    while(i && idx) {
        i = TAILQ_NEXT(i, qentry);
        --idx;
    }

    return i;
}

/* Save the file info sent by the client in their list. */
static int store_file(patch_client_t *c, patch_file_info_reply *pkt) {
    patch_cfile_t *n;
    patch_file_t *f = fetch_patch(LE32(pkt->patch_id));

    if(!f) {
        return -1;
    }

    /* Add it to the list only if we need to send it. */
    if(f->checksum != LE32(pkt->checksum) || f->size != LE32(pkt->size)){
        n = (patch_cfile_t *)malloc(sizeof(patch_cfile_t));

        if(!n) {
            perror("malloc");
            return -1;
        }

        /* Store the file info. */
        n->file = f;

        /* Add it to the list. */
        TAILQ_INSERT_TAIL(&c->files, n, qentry);
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
            size += i->file->size;
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
        strcpy(dir, "patches");
    }
    else if(c->sending_data == 2) {
        bn = strrchr(i->file->filename, '/') + 1;
        dlen = strlen(i->file->filename) - strlen(bn) - 1;
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
        bn = strrchr(i->file->filename, '/') + 1;
        dlen = strlen(i->file->filename) - strlen(bn) - 1;

        /* Copy over the directory that the file exists in. */
        strncpy(dir2, i->file->filename, dlen);
        dir2[dlen] = 0;

        /* Change the directory the client is in, if appropriate. */
        if(change_directory(c, dir, dir2)) {
            return -3;
        }

        c->sending_data = 3;

        /* Send the file header. */
        return send_file_send(c, i->file->size, bn);
    }

    /* If we've got this far and we have a file to send still, send the current
       chunk of the file. */
    if(i) {
        dlen = send_file_chunk(c, i->file->filename);

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
    if(change_directory(c, dir, "patches")) {
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
    printf("Copyright (C) 2009 Lawrence Sebald\n\n");
    printf("This program is free software: you can redistribute it and/or\n"
           "modify it under the terms of the GNU General Public License\n"
           "version 3 as published by the Free Software Foundation.\n\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n\n"
           "You should have received a copy of the GNU General Public License\n"
           "along with this program.  If not, see "
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
            exit(0);
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
        else if(!strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            exit(0);
        }
        else {
            printf("Illegal command line argument: %s\n", argv[i]);
            print_help(argv[0]);
            exit(1);
        }
    }
}

/* Load the configuration file and print out parameters with DBG_LOG. */
static void load_config() {
    struct in_addr tmp;

    debug(DBG_LOG, "Loading Sylverant configuration file... ");

    if(sylverant_read_config(&cfg)) {
        debug(DBG_ERROR, "Cannot load Sylverant configuration file!\n");
        exit(1);
    }

    debug(DBG_LOG, "Ok\n");

    debug(DBG_LOG, "Configured parameters:\n");

    tmp.s_addr = cfg.server_ip;
    debug(DBG_LOG, "Server (bound) IP: %s\n", inet_ntoa(tmp));

    if(cfg.override_on) {
        tmp.s_addr = cfg.override_ip;
        debug(DBG_LOG, "Server (reported) IP: %s\n", inet_ntoa(tmp));
        tmp.s_addr = cfg.netmask;
        debug(DBG_LOG, "Netmask: %s\n", inet_ntoa(tmp));
    }
    else {
        cfg.override_ip = cfg.server_ip;
    }

    debug(DBG_LOG, "Patch port: %d\n", cfg.server_port + PATCH_PORT_OFFSET);
    debug(DBG_LOG, "Data port: %d\n", cfg.server_port + DATA_PORT_OFFSET);
    debug(DBG_LOG, "Web Polling port: %d\n", cfg.server_port + WEB_PORT_OFFSET);

    if(cfg.patch.maxconn) {
        debug(DBG_LOG, "Max number of connections: %d\n", cfg.patch.maxconn);
    }

    if(cfg.patch.throttle) {
        debug(DBG_LOG, "Upload throttle: %d KB/s\n", cfg.patch.throttle);
    }
}

/* Read the welcome message from the appropriate file. */
static void read_welcome_message() {
    FILE *fp;
    long size, i, j, ch;
    unsigned short *buf;

    debug(DBG_LOG, "Loading welcome message file... ");

    /* Open up the file. */
    fp = fopen("config/patch_welcome", "rb");

    if(!fp) {
        debug(DBG_ERROR, "Cannot load the patch_welcome file.\n"
              "Please be sure it is in the corect directory.\n");
        exit(1);
    }

    /* Determine its length. */
    fseek(fp, 0, SEEK_END);
    welcome_msg_size = size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    ch = size >> 1;

    /* Allocate space to store the whole file, and read it in. */
    buf = (unsigned short *)malloc(size * sizeof(unsigned short));

    if(!buf) {
        perror("malloc");
        exit(1);
    }

    fread(buf, 1, size, fp);
    fclose(fp);

    /* Figure out how much shorter it'll eventually be, from removing any
       BOM. */
    for(i = 0; i < ch; ++i) {
        if(LE16(buf[i]) == 0xFEFF) {
            welcome_msg_size -= 2;
        }
    }

    /* Warn the user if the result is still too long. */
    if(welcome_msg_size > 4094) {
        debug(DBG_WARN, "Welcome message too long, truncating to 4094 bytes\n");
        welcome_msg_size = 4094;
    }

    /* Allocate space for our actual welcome message. */
    welcome_msg = (unsigned short *)malloc(welcome_msg_size + 2);

    if(!welcome_msg) {
        perror("malloc");
        exit(1);
    }

    /* Copy the final message. */
    for(i = 0, j = 0; i < ch && i < 2047; ++i) {
        if(LE16(buf[i]) != 0xFEFF) {
            welcome_msg[j] = buf[i];
            ++j;
        }
    }

    welcome_msg[j] = 0x0000;
    welcome_msg_size += 2;

    /* Clean up... */ 
    free(buf);

    debug(DBG_LOG, "Ok (%d bytes)\n", welcome_msg_size);
}

/* Process one patch packet. */
static int process_patch_packet(patch_client_t *c, pkt_header_t *pkt) {
    in_addr_t tmp;

    debug(DBG_LOG, "Patch: Receieved type 0x%04X\n", LE16(pkt->pkt_type));

    switch(LE16(pkt->pkt_type)) {
        case PATCH_WELCOME_TYPE:
            if(send_simple(c, PATCH_LOGIN_TYPE)) {
                return -2;
            }
            break;

        case PATCH_LOGIN_TYPE:
            /* TODO: Process login? */
            if(send_message(c, welcome_msg, welcome_msg_size)) {
                return -2;
            }

            /* If the client is on the local network, send out the local IP, not
               the override IP. */
            if(cfg.override_on && (c->ip_addr & cfg.netmask) ==
               (cfg.server_ip & cfg.netmask)) {
                tmp = cfg.server_ip;
            }
            else {
                tmp = cfg.override_ip;
            }

            if(send_redirect(c, tmp,
                             htons(cfg.server_port + DATA_PORT_OFFSET))) {
                return -2;
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
    debug(DBG_LOG, "Data: Receieved type 0x%04X\n", LE16(pkt->pkt_type));

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
            if(send_file_list(c)) {
                return -2;
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
                if(c->type == 0) {
                    rv = process_patch_packet(c, (pkt_header_t *)rbp);
                }
                else {
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

/* Connection handling loop... */
static void handle_connections() {
    int patch_sock, data_sock, web_sock, sock;
    struct sockaddr_in addr;
    socklen_t alen = sizeof(struct sockaddr_in);
    fd_set read, except, write;
    int nfds = 0;
    struct timeval timeout;
    patch_client_t *i, *tmp;
    ssize_t sent;

    /* Create the 3 sockets (and make them non-blocking, note that the sockets
       created by the clients are still blocking, so that we can use select to
       efficiently sleep while waiting for data). */
    patch_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    data_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    web_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(patch_sock < 0 || data_sock < 0) {
        perror("socket");
        exit(1);
    }

    make_nonblocking(patch_sock);
    make_nonblocking(data_sock);
    make_nonblocking(web_sock);

    /* Bind the three sockets to the appropriate ports. */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = cfg.server_ip;
    addr.sin_port = htons(cfg.server_port + PATCH_PORT_OFFSET);
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    if(bind(patch_sock, (struct sockaddr *)&addr, alen)) {
        perror("bind");
        exit(1);
    }

    addr.sin_port = htons(cfg.server_port + DATA_PORT_OFFSET);

    if(bind(data_sock, (struct sockaddr *)&addr, alen)) {
        perror("bind");
        exit(1);
    }

    addr.sin_port = htons(cfg.server_port + WEB_PORT_OFFSET);

    if(bind(web_sock, (struct sockaddr *)&addr, alen)) {
        perror("bind");
        exit(1);
    }

    /* Set them all up to listen for connections. */
    if(listen(patch_sock, 10)) {
        perror("listen");
        exit(1);
    }

    if(listen(data_sock, 10)) {
        perror("listen");
        exit(1);
    }

    if(listen(web_sock, 10)) {
        perror("listen");
        exit(1);
    }
    
    for(;;) {
        /* Check for connections to the patch port. */
        if((sock = accept(patch_sock, (struct sockaddr *)&addr, &alen)) < 0 &&
           errno != EAGAIN) {
            perror("accept");
            exit(1);
        }

        if(sock > 0) {
            if(create_connection(sock, addr.sin_addr.s_addr, 0) == NULL) {
                close(sock);
            }

            debug(DBG_LOG, "Accepted patch connection from %s\n",
                  inet_ntoa(addr.sin_addr));
        }

        /* Check for connections to the data port. */
        if((sock = accept(data_sock, (struct sockaddr *)&addr, &alen)) < 0 &&
           errno != EAGAIN) {
            perror("accept");
            exit(1);
        }

        if(sock > 0) {
            if(create_connection(sock, addr.sin_addr.s_addr, 1) == NULL) {
                close(sock);
            }

            debug(DBG_LOG, "Accepted data connection from %s\n",
                  inet_ntoa(addr.sin_addr));
        }

        /* Check for connections to the web port. */
        if((sock = accept(web_sock, (struct sockaddr *)&addr, &alen)) < 0 &&
           errno != EAGAIN) {
            perror("accept");
            exit(1);
        }

        if(sock > 0) {
            debug(DBG_LOG, "Accepted web connection from %s\n",
                  inet_ntoa(addr.sin_addr));

            /* Send the number of connected clients, and close the socket. */
            nfds = LE32(client_count);
            send(sock, &nfds, 4, 0);
            close(sock);
        }

        /* Clear out the fd_sets and set the timeout value for select. */
        FD_ZERO(&read);
        FD_ZERO(&except);
        nfds = 0;
        timeout.tv_sec = 0;
        timeout.tv_usec = 2000;

        /* Fill the sockets into the fd_set so we can use select below. */
        TAILQ_FOREACH(i, &clients, qentry) {
            FD_SET(i->sock, &read);
            FD_SET(i->sock, &except);
            FD_SET(i->sock, &write);
            nfds = nfds > i->sock ? nfds : i->sock;
        }

        /* Wait to see if we get any incoming data. */
        if(select(nfds + 1, &read, &write, &except, &timeout) > 0) {
            TAILQ_FOREACH(i, &clients, qentry) {
                /* Make sure there wasn't some kind of error with this
                   connection. */
                if(FD_ISSET(i->sock, &except)) {
                    debug(DBG_WARN, "Error with connection!\n");
                    i->disconnected = 1;
                }

                /* Check if this connection was trying to send us something. */
                if(FD_ISSET(i->sock, &read)) {
                    if(read_from_client(i)) {
                        i->disconnected = 1;
                    }
                }

                /* If we have anything to write, check if we can right now. */
                if(FD_ISSET(i->sock, &write)) {
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

/* Clear the list of files. */
static void clear_patch_list() {
    patch_file_t *i, *tmp;

    /* Loop through all the entries in the file list, freeing all the memory. */
    i = TAILQ_FIRST(&files);
    while(i) {
        tmp = TAILQ_NEXT(i, qentry);

        free(i->filename);
        TAILQ_REMOVE(&files, i, qentry);
        free(i);

        i = tmp;
    }

    file_count = 0;
}

/* Build the patched file list. */
static void build_patch_list(const char *path) {
    patch_file_t *f;
    DIR *d;
    struct dirent *de;
    struct stat st;
    char tmp[PATH_MAX];
    void *data;
    FILE *fd;

    /* Open up the directory to read the list of files. */
    d = opendir(path);

    if(!d) {
        perror("opendir");
        exit(1);
    }

    /* Loop through each item in the directory we have open. */
    while((de = readdir(d))) {
        /* Grab the directory information about this file. */
        sprintf(tmp, "%s/%s", path, de->d_name);
        stat(tmp, &st);

        /* If we've found a directory that we should recursively scan, go ahead
           and do that. */
        if(st.st_mode & S_IFDIR) {
            if(strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                build_patch_list(tmp);
            }
        }
        /* Otherwise, if we have a regular file, process it. */
        else if(st.st_mode & S_IFREG) {
            f = (patch_file_t *)malloc(sizeof(patch_file_t));
            if(!f) {
                perror("malloc");
                exit(1);
            }

            f->filename = strdup(tmp);
            if(!f->filename) {
                perror("strdup");
                exit(1);
            }

            /* Read the whole file in to evaluate the checksum. */
            data = malloc(st.st_size);
            if(!data) {
                perror("malloc");
                exit(1);
            }

            fd = fopen(tmp, "rb");
            if(!fd) {
                perror("fopen");
                exit(1);
            }

            fread(data, 1, st.st_size, fd);
            fclose(fd);
            f->checksum = crc32(data, st.st_size);
            free(data);

            /* Fill in the information that we require. */
            f->size = st.st_size;

            /* Add this patch onto the end of the list. */
            TAILQ_INSERT_TAIL(&files, f, qentry);
            ++file_count;

            debug(DBG_LOG, "Patched file: %s\n", f->filename);
            debug(DBG_LOG, "Checksum: 0x%08X\n", f->checksum);
            debug(DBG_LOG, "Size: %lld bytes\n", (long long)f->size);
        }
    }

    /* Close the directory, we're done. */
    closedir(d);
}

/* Signal handler registered to SIGUSR1. Used to rescan the directory for newly
   updated files without restarting the server completely. */
static void sig_handler(int signum) {
    clear_patch_list();
    debug(DBG_LOG, "Rescanning patches directory...\n");
    build_patch_list("patches");
    debug(DBG_LOG, "Ok\n");
}

/* Install the signal handler for SIGUSR1. Calls the above function. */
static void install_signal_handler() {
    struct sigaction sa;

    sa.sa_handler = &sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    debug(DBG_LOG, "Installing SIGUSR1 handler... ");

    if(sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    debug(DBG_LOG, "Ok\n");
}

int main(int argc, char *argv[]) {
    /* Parse the command line and read our configuration. */
    parse_command_line(argc, argv);
    load_config();

    /* Change to the Sylverant data directory for all future stuff. */
    chdir(SYLVERANT_DIRECTORY);

    /* Attempt to read the Welcome message from the text file. */
    read_welcome_message();

    /* Build the list of patched files. */
    debug(DBG_LOG, "Building patch list...\n");
    build_patch_list("patches");
    debug(DBG_LOG, "Ok\n");

    /* Initialize the random-number generator. */
    init_genrand(time(NULL));

    /* Install the USR1 signal handler. */
    install_signal_handler();

    /* Enter the main connection handling loop. */
    handle_connections();

    return 0;
}
