/*
    Sylverant Patch Server

    Copyright (C) 2009, 2011 Lawrence Sebald

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

    uint32_t size;
    uint32_t checksum;
    char *filename;
    char *server_filename;
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
    int sock;
    int disconnected;
    int is_ipv6;

    struct sockaddr_storage ip_addr;
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

#define CLIENT_TYPE_PC_PATCH 0
#define CLIENT_TYPE_PC_DATA  1
#define CLIENT_TYPE_WEB      2
#define CLIENT_TYPE_BB_PATCH 3
#define CLIENT_TYPE_BB_DATA  4

TAILQ_HEAD(client_queue, patch_client);
TAILQ_HEAD(file_queue, patch_file);

/* Patch server configuration structure. */
typedef struct patch_config {
    uint8_t server_ip6[16];
    uint32_t server_ip;

    int disallow_pc;
    int disallow_bb;

    uint16_t *pc_welcome;
    uint16_t *bb_welcome;
    uint16_t pc_welcome_size;
    uint16_t bb_welcome_size;

    char *pc_dir;
    char *bb_dir;

    struct file_queue pc_files;
    struct file_queue bb_files;
} patch_config_t;

/* In patch_config.c */
int patch_read_config(const char *fn, patch_config_t **cfg);
void patch_free_config(patch_config_t *cfg);

#endif /* !PATCH_SERVER_H */
