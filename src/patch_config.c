/*
    This file is part of Sylverant Patch Server.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sylverant/debug.h>

#include "patch_server.h"

#ifndef LIBXML_TREE_ENABLED
#error You must have libxml2 with tree support built-in.
#endif

#define XC (const xmlChar *)

static int handle_server(xmlNode *n, patch_config_t *cur) {
    xmlChar *ip, *ip6;
    int rv;

    /* Grab the attributes of the tag. */
    ip = xmlGetProp(n, XC"addr");
    ip6 = xmlGetProp(n, XC"ip6");

    /* Make sure we have at least an IPv4 address... */
    if(!ip) {
        debug(DBG_ERROR, "IP not given for server\n");
        rv = -1;
        goto err;
    }

    /* Parse the IP address out */
    rv = inet_pton(AF_INET, (char *)ip, &cur->server_ip);

    if(rv < 1) {
        debug(DBG_ERROR, "Invalid IP address given for server: %s\n",
              (char *)ip);
        rv = -2;
        goto err;
    }

    /* See if we have a configured IPv6 address */
    if(ip6) {
        rv = inet_pton(AF_INET6, (char *)ip6, cur->server_ip6);

        /* This isn't actually fatal, for now, anyway. */
        if(rv < 1) {
            debug(DBG_WARN, "Invalid IPv6 address given: %s\n", (char *)ip6);
        }
    }

    rv = 0;

err:
    xmlFree(ip);
    return rv;
}

static int handle_versions(xmlNode *n, patch_config_t *cfg) {
    xmlChar *pc, *bb;
    int rv = 0;
    
    /* Grab the attributes of the tag. */
    pc = xmlGetProp(n, XC"pc");
    bb = xmlGetProp(n, XC"bb");

    /* Make sure we have the data */
    if(!pc || !bb) {
        debug(DBG_ERROR, "Missing version\n");
        rv = -1;
        goto err;
    }

    /* Parse everything out */
    if(!xmlStrcmp(pc, XC"false")) {
        cfg->disallow_pc = 1;
    }

    if(!xmlStrcmp(bb, XC"false")) {
        cfg->disallow_bb = 1;
    }

err:
    xmlFree(pc);
    return rv;
}

static int handle_welcome(xmlNode *n, patch_config_t *cfg) {
    xmlChar *ver = NULL, *msg = NULL;
    int rv = 0;
    int ispc = 0;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;
    char buf[4096];
    uint16_t *tmp;

    /* Make the converting context */
    ic = iconv_open("UTF-16LE", "UTF-8");
    if(ic == (iconv_t)-1) {
        debug(DBG_ERROR, "Cannot create iconv context\n");
        return -1;
    }

    /* Clear the buffer */
    memset(buf, 0, 4096);

    /* Grab the attributes first... */
    ver = xmlGetProp(n, XC"version");

    /* Make sure we got it and it is valid */
    if(!ver) {
        debug(DBG_ERROR, "Version not specified for welcome message\n");
        rv = -2;
        goto err;
    }

    if(!xmlStrcmp(ver, XC"PC")) {
        ispc = 1;
    }
    else if(!xmlStrcmp(ver, XC"BB")) {
        ispc = 0;
    }
    else {
        debug(DBG_ERROR, "Invalid version given: %s\n", (char *)ver);
        rv = -3;
        goto err;
    }

    /* Grab the message from the node */
    if((msg = xmlNodeListGetString(n->doc, n->children, 1))) {
        /* Convert the message to UTF-16LE */
        in = (size_t)xmlStrlen(msg);
        out = 4094;
        inptr = (ICONV_CONST char *)msg;
        outptr = buf;
        iconv(ic, &inptr, &in, &outptr, &out);

        /* Allocate space for the string to stay in, and copy it there */
        tmp = (uint16_t *)malloc(4096 - out);
        if(!tmp) {
            debug(DBG_ERROR, "Cannot allocate space for welcome message\n"
                  "%s\n", strerror(errno));
            rv = -4;
            goto err;
        }

        memcpy(tmp, buf, 4096 - out);

        /* Put it where it belongs */
        if(ispc) {
            cfg->pc_welcome = tmp;
            cfg->pc_welcome_size = (uint16_t)(4096 - out);
        }
        else {
            cfg->bb_welcome = tmp;
            cfg->bb_welcome_size = (uint16_t)(4096 - out);
        }
    }
    else {
        debug(DBG_ERROR, "Welcome message not specified properly\n");
        rv = -5;
        goto err;
    }

err:
    iconv_close(ic);
    xmlFree(msg);
    xmlFree(ver);

    return rv;
}

static int handle_clientfile(xmlNode *n, patch_file_t *f) {
    xmlChar *fn;

    /* Grab the long description from the node */
    if((fn = xmlNodeListGetString(n->doc, n->children, 1))) {
        f->filename = (char *)fn;
    }

    return 0;
}

static int handle_file(xmlNode *n, patch_file_t *f) {
    xmlChar *fn;

    /* Grab the long description from the node */
    if((fn = xmlNodeListGetString(n->doc, n->children, 1))) {
        f->server_filename = (char *)fn;
    }

    return 0;
}

static int handle_checksum(xmlNode *n, patch_file_t *f) {
    xmlChar *csum;
    int rv = 0;

    /* Grab the long description from the node */
    if((csum = xmlNodeListGetString(n->doc, n->children, 1))) {
        errno = 0;
        f->checksum = (uint32_t)strtoul((char *)csum, NULL, 16);

        if(errno) {
            debug(DBG_ERROR, "Invalid checksum for patch on line %hu: %s\n",
                  n->line, (char *)csum);
            rv = -1;
        }
    }

    xmlFree(csum);
    return rv;
}

static int handle_size(xmlNode *n, patch_file_t *f) {
    xmlChar *size;
    int rv = 0;

    /* Grab the long description from the node */
    if((size = xmlNodeListGetString(n->doc, n->children, 1))) {
        errno = 0;
        f->size = (uint32_t)strtoul((char *)size, NULL, 0);

        if(errno) {
            debug(DBG_ERROR, "Invalid size for patch on line %hu: %s\n",
                  n->line, (char *)size);
            rv = -1;
        }
    }

    xmlFree(size);
    return rv;
}

static int handle_patch(xmlNode *n, struct file_queue *q) {
    xmlChar *enabled;
    int rv;
    patch_file_t *file = NULL;
    int have_cfile = 0, have_file = 0, have_checksum = 0, have_size = 0;

    /* Grab the attributes we're expecting */
    enabled = xmlGetProp(n, XC"enabled");

    /* Make sure we have all of them... */
    if(!enabled) {
        debug(DBG_ERROR, "Required patch attributes missing\n");
        rv = -1;
        goto err;
    }

    /* If the patch isn't enabled, we can ignore it. */
    if(!xmlStrcmp(enabled, XC"false")) {
        rv = 0;
        goto err;
    }

    /* Allocate space for the file */
    file = (patch_file_t *)malloc(sizeof(patch_file_t));
    if(!file) {
        debug(DBG_ERROR, "Cannot allocate space for patch info\n"
              "%s\n", strerror(errno));
        rv = -2;
        goto err;
    }

    memset(file, 0, sizeof(patch_file_t));

    /* Now that we're done with that, deal with any children of the node */
    n = n->children;
    while(n) {
        if(n->type != XML_ELEMENT_NODE) {
            /* Ignore non-elements. */
            n = n->next;
            continue;
        }
        else if(!xmlStrcmp(n->name, XC"clientfile")) {
            if(have_cfile) {
                debug(DBG_ERROR, "Duplicate client filename for patch on line"
                      "%hu\n", n->line);
                rv = -3;
                goto err;
            }

            if(handle_clientfile(n, file)) {
                rv = -4;
                goto err;
            }

            have_cfile = 1;
        }
        else if(!xmlStrcmp(n->name, XC"file")) {
            if(have_file) {
                debug(DBG_ERROR, "Duplicate server filename for patch on line"
                      "%hu\n", n->line);
                rv = -5;
                goto err;
            }

            if(handle_file(n, file)) {
                rv = -6;
                goto err;
            }

            have_file = 1;
        }
        else if(!xmlStrcmp(n->name, XC"checksum")) {
            if(have_checksum) {
                debug(DBG_ERROR, "Duplicate checksum for patch on line %hu\n",
                      n->line);
                rv = -7;
                goto err;
            }

            if(handle_checksum(n, file)) {
                rv = -8;
                goto err;
            }

            have_checksum = 1;
        }
        else if(!xmlStrcmp(n->name, XC"size")) {
            if(have_size) {
                debug(DBG_ERROR, "Duplicate size for patch on line %hu\n",
                      n->line);
                rv = -9;
                goto err;
            }

            if(handle_size(n, file)) {
                rv = -10;
                goto err;
            }

            have_size = 1;
        }
        else {
            debug(DBG_WARN, "Invalid Tag %s on line %hu\n", (char *)n->name,
                  n->line);
        }
        
        n = n->next;
    }

    /* If we got this far, make sure we got all the required attributes */
    if(!have_cfile || !have_file || !have_checksum || !have_size) {
        debug(DBG_ERROR, "One or more required attributes not set for patch\n");
        rv = -11;
        goto err;
    }

    /* We've got everything, store it */
    TAILQ_INSERT_TAIL(q, file, qentry);
    rv = 0;

err:
    if(rv && file) {
        xmlFree(file->filename);
        xmlFree(file->server_filename);
        free(file);
    }

    xmlFree(enabled);

    return rv;
}

static int handle_patches(xmlNode *n, patch_config_t *cfg) {
    xmlChar *ver, *dir;
    int rv = 0;
    struct file_queue *q;

    /* Grab the attributes we're expecting */
    ver = xmlGetProp(n, XC"version");
    dir = xmlGetProp(n, XC"dir");

    /* Make sure we have all of them... */
    if(!ver || !dir) {
        debug(DBG_ERROR, "One or more required patches attributes missing\n");
        rv = -1;
        goto err;
    }

    /* Make sure the version is sane */
    if(!xmlStrcmp(ver, XC"PC")) {
        q = &cfg->pc_files;
        cfg->pc_dir = (char *)dir;
    }
    else if(!xmlStrcmp(ver, XC"BB")) {
        q = &cfg->bb_files;
        cfg->bb_dir = (char *)dir;
    }
    else {
        debug(DBG_ERROR, "Invalid version for patches tag: %s\n", (char *)ver);
        rv = -2;
        goto err;
    }

    /* Now that we're done with that, deal with any children of the node */
    n = n->children;
    while(n) {
        if(n->type != XML_ELEMENT_NODE) {
            /* Ignore non-elements. */
            n = n->next;
            continue;
        }
        else if(!xmlStrcmp(n->name, XC"patch")) {
            if(handle_patch(n, q)) {
                rv = -3;
                goto err;
            }
        }
        else {
            debug(DBG_WARN, "Invalid Tag %s on line %hu\n", (char *)n->name,
                  n->line);
        }

        n = n->next;
    }

err:
    xmlFree(ver);

    if(rv < 0) {
        xmlFree(dir);
    }

    return rv;
}

int patch_read_config(const char *fn, patch_config_t **cfg) {
    xmlParserCtxtPtr cxt;
    xmlDoc *doc;
    xmlNode *n;
    int irv = 0;
    patch_config_t *rv;

    /* Allocate space for the base of the config. */
    rv = (patch_config_t *)malloc(sizeof(patch_config_t));

    if(!rv) {
        *cfg = NULL;
        debug(DBG_ERROR, "Couldn't allocate space for config\n");
        perror("malloc");
        return -1;
    }

    /* Clear out the config. */
    memset(rv, 0, sizeof(patch_config_t));
    TAILQ_INIT(&rv->pc_files);
    TAILQ_INIT(&rv->bb_files);

    /* Create an XML Parsing context */
    cxt = xmlNewParserCtxt();
    if(!cxt) {
        debug(DBG_ERROR, "Couldn't create parsing context for config\n");
        irv = -2;
        goto err;
    }

    /* Open the configuration file for reading. */
    doc = xmlReadFile(fn, NULL, 0 /* XML_PARSE_DTDVALID */);

    if(!doc) {
        xmlParserError(cxt, "Error in parsing config\n");
        irv = -3;
        goto err_cxt;
    }

    /* Make sure the document validated properly. */
    if(!cxt->valid) {
        xmlParserValidityError(cxt, "Validity Error parsing config\n");
        irv = -4;
        goto err_doc;
    }

    /* If we've gotten this far, we have a valid document, now go through and
       add in entries for everything... */
    n = xmlDocGetRootElement(doc);

    if(!n) {
        debug(DBG_WARN, "Empty config document\n");
        irv = -5;
        goto err_doc;
    }

    /* Make sure the config looks sane. */
    if(xmlStrcmp(n->name, XC"patch_config")) {
        debug(DBG_WARN, "Config does not appear to be the right type\n");
        irv = -6;
        goto err_doc;
    }

    n = n->children;
    while(n) {
        if(n->type != XML_ELEMENT_NODE) {
            /* Ignore non-elements. */
            n = n->next;
            continue;
        }
        else if(!xmlStrcmp(n->name, XC"server")) {
            if(handle_server(n, rv)) {
                irv = -7;
                goto err_doc;
            }
        }
        else if(!xmlStrcmp(n->name, XC"versions")) {
            if(handle_versions(n, rv)) {
                irv = -8;
                goto err_doc;
            }
        }
        else if(!xmlStrcmp(n->name, XC"welcome")) {
            if(handle_welcome(n, rv)) {
                irv = -9;
                goto err_doc;
            }
        }
        else if(!xmlStrcmp(n->name, XC"patches")) {
            if(handle_patches(n, rv)) {
                irv = -10;
                goto err_doc;
            }
        }
        else {
            debug(DBG_WARN, "Invalid Tag %s on line %hu\n", (char *)n->name,
                  n->line);
        }

        n = n->next;
    }

    *cfg = rv;

    /* Cleanup/error handling below... */
err_doc:
    xmlFreeDoc(doc);
err_cxt:
    xmlFreeParserCtxt(cxt);
err:
    if(irv && irv > -7) {
        free(rv);
        *cfg = NULL;
    }
    else if(irv) {
        patch_free_config(rv);
        *cfg = NULL;
    }

    return irv;
}

void patch_free_config(patch_config_t *cfg) {
    patch_file_t *i, *tmp;

    /* Make sure we actually have a valid configuration pointer. */
    if(cfg) {
        /* Clean up any stored pointers */
        free(cfg->pc_welcome);
        free(cfg->bb_welcome);
        xmlFree(cfg->pc_dir);
        xmlFree(cfg->bb_dir);

        /* Clean up the file queues */
        i = TAILQ_FIRST(&cfg->pc_files);
        while(i) {
            tmp = TAILQ_NEXT(i, qentry);

            TAILQ_REMOVE(&cfg->pc_files, i, qentry);
            xmlFree(i->filename);
            xmlFree(i->server_filename);
            free(i);

            i = tmp;
        }

        i = TAILQ_FIRST(&cfg->bb_files);
        while(i) {
            tmp = TAILQ_NEXT(i, qentry);

            TAILQ_REMOVE(&cfg->bb_files, i, qentry);
            xmlFree(i->filename);
            xmlFree(i->server_filename);
            free(i);

            i = tmp;
        }

        /* Clean up the base structure. */
        free(cfg);
    }
}
