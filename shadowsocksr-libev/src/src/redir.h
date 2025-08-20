/*
 * redir.h - Define the redirector's buffers and callbacks
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include "encrypt.h"
#include "obfs/obfs.h"
#include "jconf.h"

#include "common.h"

typedef struct listen_ctx {
    ev_io io;

    struct cork_dllist_item entries; // for inactive profile list
    struct cork_dllist connections_eden; // For connections just created but not attach to a server

//    int remote_num;
    int timeout;
    int fd;
//    int method;
    int mptcp;
//    struct sockaddr **remote_addr;

//    // SSR
//    char *protocol_name;
//    char *protocol_param;
//    char *obfs_name;
//    char *obfs_param;
//    void **list_protocol_global;
//    void **list_obfs_global;

    int server_num;
    server_def_t servers[MAX_SERVER_NUM];
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io;
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    buffer_t *buf;
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    uint32_t counter;
    struct server *server;

//       //     SSR
//    int remote_index;
} remote_t;

typedef struct server {
    int fd;
    buffer_t *buf;
    struct sockaddr_storage destaddr;
    enc_ctx_t *e_ctx;
    enc_ctx_t *d_ctx;
    server_ctx_t *recv_ctx;
    server_ctx_t *send_ctx;
    listen_ctx_t *listener;
    remote_t *remote;

    char *hostname;
    size_t hostname_len;

    struct cork_dllist_item entries;
    struct cork_dllist_item entries_all; // for all_connections

    server_def_t *server_env;

    // SSR
    obfs *protocol;
    obfs *obfs;
//    obfs_class *protocol_plugin;
//    obfs_class *obfs_plugin;
} server_t;

#endif // _LOCAL_H
