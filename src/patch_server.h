/*
    Sylverant Patch Server

    Copyright (C) 2009 Lawrence Sebald

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

#ifndef PATCH_SERVER_H
#define PATCH_SERVER_H

#include <inttypes.h>
#include <sys/queue.h>
#include <netinet/in.h>

#include <sylverant/encryption.h>

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* The common packet header on top of all packets. */
typedef struct pkt_header {
    uint16_t pkt_len;
    uint16_t pkt_type;
} PACKED pkt_header_t;

#undef PACKED

/* Patch file structure. */
typedef struct patch_file {
    TAILQ_ENTRY(patch_file) qentry;

    off_t size;
    uint32_t checksum;
    char *filename;
} patch_file_t;

/* Client-side file structure. */
typedef struct patch_cfile {
    TAILQ_ENTRY(patch_cfile) qentry;

    patch_file_t *file;
} patch_cfile_t;

TAILQ_HEAD(cfile_queue, patch_cfile);

/* Patch server client structure. */
typedef struct patch_client {
    TAILQ_ENTRY(patch_client) qentry;

    int type;
    in_addr_t ip_addr;
    int sock;
    int disconnected;
    CRYPT_SETUP client_cipher;
    CRYPT_SETUP server_cipher;

    unsigned char *recvbuf;
    int recvbuf_cur;
    int recvbuf_size;
    pkt_header_t pkt;

    unsigned char *sendbuf;
    int sendbuf_cur;
    int sendbuf_size;
    int sendbuf_start;

    struct cfile_queue files;
    int sending_data;
    int cur_chunk;
    int cur_pos;
} patch_client_t;

TAILQ_HEAD(client_queue, patch_client);
TAILQ_HEAD(file_queue, patch_file);

#endif /* !PATCH_SERVER_H */
