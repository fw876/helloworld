/*
 * redir.c - Provide a transparent TCP proxy through remote shadowsocks
 *            server
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
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

#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <udns.h>
#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http.h"
#include "tls.h"
#include "netutils.h"
#include "utils.h"
#include "redir.h"
#include "common.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#include "includeobfs.h" // I don't want to modify makefile
#include "jconf.h"

static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd, listen_ctx_t* profile);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

int verbose        = 0;
int keep_resolving = 1;

static int ipv6first = 0;
static int mode = TCP_ONLY;
#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif

static struct cork_dllist inactive_profiles;
static listen_ctx_t *current_profile;
static struct cork_dllist all_connections;

int
getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t socklen = sizeof(*destaddr);
    int error         = 0;

    error = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &socklen);
    if (error) { // Didn't find a proper way to detect IP version.
        error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
        if (error) {
            return -1;
        }
    }
    return 0;
}

int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        int err = set_reuseport(listen_sock);
        if (err == 0) {
            LOGI("tcp port reuse enabled");
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    server_def_t *server_env = server->server_env;

    ssize_t r = recv(server->fd, remote->buf->array + remote->buf->len,
                     BUF_SIZE - remote->buf->len, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf->len += r;

    if (verbose) {
        uint16_t port = 0;
        char ipstr[INET6_ADDRSTRLEN];
        memset(&ipstr, 0, INET6_ADDRSTRLEN);

        if (AF_INET == server->destaddr.ss_family) {
            struct sockaddr_in *sa = (struct sockaddr_in *)&(server->destaddr);
            dns_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
            port = ntohs(sa->sin_port);
        } else {
            // TODO: The code below need to be test in IPv6 envirment, which I
            //       don't have.
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&(server->destaddr);
            dns_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
            port = ntohs(sa->sin6_port);
        }

        LOGI("redir to %s:%d, len=%zu, recv=%zd", ipstr, port, remote->buf->len, r);
    }

    if (!remote->send_ctx->connected) {
        // SNI
        int ret       = 0;
        uint16_t port = 0;

        if (AF_INET6 == server->destaddr.ss_family) { // IPv6
            port = ntohs(((struct sockaddr_in6 *)&(server->destaddr))->sin6_port);
        } else {                             // IPv4
            port = ntohs(((struct sockaddr_in *)&(server->destaddr))->sin_port);
        }
        if (port == http_protocol->default_port)
            ret = http_protocol->parse_packet(remote->buf->array,
                                              remote->buf->len, &server->hostname);
        else if (port == tls_protocol->default_port)
            ret = tls_protocol->parse_packet(remote->buf->array,
                                             remote->buf->len, &server->hostname);
        if (ret > 0) {
            server->hostname_len = ret;
        }

        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    }
    // SSR beg
    if (server_env->protocol_plugin) {
        obfs_class *protocol_plugin = server_env->protocol_plugin;
        if (protocol_plugin->client_pre_encrypt) {
            remote->buf->len = protocol_plugin->client_pre_encrypt(server->protocol, &remote->buf->array, remote->buf->len, &remote->buf->capacity);
        }
    }
    int err = ss_encrypt(&server_env->cipher, remote->buf, server->e_ctx, BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server_env->obfs_plugin) {
        obfs_class *obfs_plugin = server_env->obfs_plugin;
        if (obfs_plugin->client_encode) {
            remote->buf->len = obfs_plugin->client_encode(server->obfs, &remote->buf->array, remote->buf->len, &remote->buf->capacity);
        }
    }
    // SSR end

    if (!remote->send_ctx->connected) {
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    }

    if (r > 0 && remote->buf->len == 0) { // SSR pause recv
        remote->buf->idx = 0;
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        return;
    }
    int s = send(remote->fd, remote->buf->array, remote->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx  = s;
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    } else {
        remote->buf->idx = 0;
        remote->buf->len = 0;
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->array + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        }
    }
}

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    ev_timer_stop(EV_A_ watcher);

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;
    server_def_t *server_env      = server->server_env;

    ev_timer_again(EV_A_ & remote->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf->array, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    // SSR beg
    if (server_env->obfs_plugin) {
        obfs_class *obfs_plugin = server_env->obfs_plugin;
        if (obfs_plugin->client_decode) {
            int needsendback;
            server->buf->len = obfs_plugin->client_decode(server->obfs, &server->buf->array, server->buf->len, &server->buf->capacity, &needsendback);
            if ((int)server->buf->len < 0) {
                LOGE("client_decode");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            if (needsendback) {
                obfs_class *obfs_plugin = server_env->obfs_plugin;
                if (obfs_plugin->client_encode) {
                    remote->buf->len = obfs_plugin->client_encode(server->obfs, &remote->buf->array, 0, &remote->buf->capacity);
                    ssize_t s = send(remote->fd, remote->buf->array, remote->buf->len, 0);
                    if (s == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            ERROR("remote_send_cb_send");
                            // close and free
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                        }
                        return;
                    } else if (s < (ssize_t)(remote->buf->len)) {
                        // partly sent, move memory, wait for the next time to send
                        remote->buf->len -= s;
                        remote->buf->idx += s;
                        return;
                    } else {
                        // all sent out, wait for reading
                        remote->buf->len = 0;
                        remote->buf->idx = 0;
                        ev_io_stop(EV_A_ & remote->send_ctx->io);
                        ev_io_start(EV_A_ & server->recv_ctx->io);
                    }
                }
            }
        }
    }
    if ( server->buf->len == 0 )
        return;

    int err = ss_decrypt(&server_env->cipher, server->buf, server->d_ctx, BUF_SIZE);
    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server_env->protocol_plugin) {
        obfs_class *protocol_plugin = server_env->protocol_plugin;
        if (protocol_plugin->client_post_decrypt) {
            server->buf->len = protocol_plugin->client_post_decrypt(server->protocol, &server->buf->array, server->buf->len, &server->buf->capacity);
            if ((int)server->buf->len < 0) {
                LOGE("client_post_decrypt");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            if ( server->buf->len == 0 )
                return;
        }
    }
    // SSR end

    int s = send(server->fd, server->buf->array, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;
    server_def_t *server_env = server->server_env;

    if (!remote_send_ctx->connected) {
        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(struct sockaddr_storage));
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            //ev_io_stop(EV_A_ & server->recv_ctx->io);
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
            ev_timer_start(EV_A_ & remote->recv_ctx->watcher);

            // send destaddr
            buffer_t ss_addr_to_send;
            buffer_t *abuf = &ss_addr_to_send;
            balloc(abuf, BUF_SIZE);

            if (server->hostname_len > 0
                    && validate_hostname(server->hostname, server->hostname_len)) { // HTTP/SNI
                uint16_t port;
                if (AF_INET6 == server->destaddr.ss_family) { // IPv6
                    port = (((struct sockaddr_in6 *)&(server->destaddr))->sin6_port);
                } else {                             // IPv4
                    port = (((struct sockaddr_in *)&(server->destaddr))->sin_port);
                }

                abuf->array[abuf->len++] = 3;          // Type 3 is hostname
                abuf->array[abuf->len++] = server->hostname_len;
                memcpy(abuf->array + abuf->len, server->hostname, server->hostname_len);
                abuf->len += server->hostname_len;
                memcpy(abuf->array + abuf->len, &port, 2);
            } else if (AF_INET6 == server->destaddr.ss_family) { // IPv6
                abuf->array[abuf->len++] = 4;          // Type 4 is IPv6 address

                size_t in6_addr_len = sizeof(struct in6_addr);
                memcpy(abuf->array + abuf->len,
                       &(((struct sockaddr_in6 *)&(server->destaddr))->sin6_addr),
                       in6_addr_len);
                abuf->len += in6_addr_len;
                memcpy(abuf->array + abuf->len,
                       &(((struct sockaddr_in6 *)&(server->destaddr))->sin6_port),
                       2);
            } else {                             // IPv4
                abuf->array[abuf->len++] = 1; // Type 1 is IPv4 address

                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(abuf->array + abuf->len,
                       &((struct sockaddr_in *)&(server->destaddr))->sin_addr, in_addr_len);
                abuf->len += in_addr_len;
                memcpy(abuf->array + abuf->len,
                       &((struct sockaddr_in *)&(server->destaddr))->sin_port, 2);
            }

            abuf->len += 2;

            if (remote->buf->len > 0) {
                brealloc(remote->buf, remote->buf->len + abuf->len, BUF_SIZE);
                memmove(remote->buf->array + abuf->len, remote->buf->array, remote->buf->len);
                memcpy(remote->buf->array, abuf->array, abuf->len);
                remote->buf->len += abuf->len;
            } else {
                brealloc(remote->buf, abuf->len, BUF_SIZE);
                memcpy(remote->buf->array, abuf->array, abuf->len);
                remote->buf->len = abuf->len;
            }
            bfree(abuf);
            
            // SSR beg
            server_info _server_info;
            if (server_env->obfs_plugin) {
                server_env->obfs_plugin->get_server_info(server->obfs, &_server_info);
                _server_info.head_len = get_head_size(remote->buf->array, remote->buf->len, 30);
                server_env->obfs_plugin->set_server_info(server->obfs, &_server_info);
            }
            if (server_env->protocol_plugin) {
                obfs_class *protocol_plugin = server_env->protocol_plugin;
                if (protocol_plugin->client_pre_encrypt) {
                    remote->buf->len = protocol_plugin->client_pre_encrypt(server->protocol, &remote->buf->array, remote->buf->len, &remote->buf->capacity);
                }
            }

            int err = ss_encrypt(&server_env->cipher, remote->buf, server->e_ctx, BUF_SIZE);
            if (err) {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            if (server_env->obfs_plugin) {
                obfs_class *obfs_plugin = server_env->obfs_plugin;
                if (obfs_plugin->client_encode) {
                    remote->buf->len = obfs_plugin->client_encode(server->obfs, &remote->buf->array, remote->buf->len, &remote->buf->capacity);
                }
            }
            // SSR end

            ev_io_start(EV_A_ & remote->recv_ctx->io);
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->array + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->buf                 = ss_malloc(sizeof(buffer_t));
    remote->recv_ctx            = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx            = ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);
    ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb,
                  timeout, 0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote != NULL) {
        if (remote->server != NULL) {
            remote->server->remote = NULL;
        }
        if (remote->buf != NULL) {
            bfree(remote->buf);
            ss_free(remote->buf);
        }
        ss_free(remote->recv_ctx);
        ss_free(remote->send_ctx);
        ss_free(remote);
    }
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

static server_t *
new_server(int fd, listen_ctx_t* profile) {
    server_t *server = ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));

    server->listener = profile;
    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd = fd;
    server->recv_ctx->server = server;
    server->send_ctx->server = server;

    server->hostname     = NULL;
    server->hostname_len = 0;

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    cork_dllist_add(&profile->connections_eden, &server->entries);
    cork_dllist_add(&all_connections, &server->entries_all);

    return server;
}

static void
release_profile(listen_ctx_t *profile)
{
    int i;

    for(i = 0; i < profile->server_num; i++)
    {
        server_def_t *server_env = &profile->servers[i];

        ss_free(server_env->host);

        if(server_env->addr != server_env->addr_udp)
        {
            ss_free(server_env->addr_udp);
        }
        ss_free(server_env->addr);

        ss_free(server_env->psw);

        ss_free(server_env->protocol_name);
        ss_free(server_env->obfs_name);
        ss_free(server_env->protocol_param);
        ss_free(server_env->obfs_param);
        ss_free(server_env->protocol_global);
        ss_free(server_env->obfs_global);
        if(server_env->protocol_plugin){
            free_obfs_class(server_env->protocol_plugin);
        }
        if(server_env->obfs_plugin){
            free_obfs_class(server_env->obfs_plugin);
        }
        ss_free(server_env->id);
        ss_free(server_env->group);

        enc_release(&server_env->cipher);
    }
    ss_free(profile);
}

static void
check_and_free_profile(listen_ctx_t *profile)
{
    int i;

    if(profile == current_profile)
    {
        return;
    }
    // if this connection is created from an inactive profile, then we need to free the profile
    // when the last connection of that profile is colsed
    if(!cork_dllist_is_empty(&profile->connections_eden))
    {
        return;
    }

    for(i = 0; i < profile->server_num; i++)
    {
        if(!cork_dllist_is_empty(&profile->servers[i].connections))
        {
            return;
        }
    }

    // No connections anymore
    cork_dllist_remove(&profile->entries);
    release_profile(profile);
}

static void
free_server(server_t *server)
{
    if(server != NULL) {
        listen_ctx_t *profile = server->listener;
        server_def_t *server_env = server->server_env;

        cork_dllist_remove(&server->entries);
        cork_dllist_remove(&server->entries_all);

        if (server->remote != NULL) {
            server->remote->server = NULL;
        }
        if (server->buf != NULL) {
            bfree(server->buf);
            ss_free(server->buf);
        }
        if (server->hostname != NULL) {
            ss_free(server->hostname);
        }

//        if (server != NULL) {
//            if (server->remote != NULL) {
//                server->remote->server = NULL;
//            }
        if (server_env) {
            if (server->e_ctx != NULL) {
                enc_ctx_release(&server_env->cipher, server->e_ctx);
                ss_free(server->e_ctx);
            }
            if (server->d_ctx != NULL) {
                enc_ctx_release(&server_env->cipher, server->d_ctx);
                ss_free(server->d_ctx);
            }
//            if (server->buf != NULL) {
//                bfree(server->buf);
//                ss_free(server->buf);
//            }
            // SSR beg
            if (server_env->obfs_plugin) {
                server_env->obfs_plugin->dispose(server->obfs);
                server->obfs = NULL;
//                free_obfs_class(server->obfs_plugin);
//                server->obfs_plugin = NULL;
            }
            if (server_env->protocol_plugin) {
                server_env->protocol_plugin->dispose(server->protocol);
                server->protocol = NULL;
//                free_obfs_class(server->protocol_plugin);
//                server->protocol_plugin = NULL;
            }
            // SSR end
        }

        ss_free(server->recv_ctx);
        ss_free(server->send_ctx);
        ss_free(server);

        // after free server, we need to check the profile
        check_and_free_profile(profile);
    }
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        close(server->fd);
        free_server(server);
    }
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    struct sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(struct sockaddr_storage));

    int err;

    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    err = getdestaddr(serverfd, &destaddr);
    if (err) {
        ERROR("getdestaddr");
        return;
    }

    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // pick a server
    int index = rand() % listener->server_num;
    server_def_t *server_env = &listener->servers[index];

    struct sockaddr *remote_addr = (struct sockaddr *) server_env->addr;

    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (remotefd == -1) {
        ERROR("socket");
        return;
    }

    // Set flags
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Setup
    int keepAlive    = 1;
    int keepIdle     = 40;
    int keepInterval = 20;
    int keepCount    = 5;
    setsockopt(remotefd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
    setsockopt(remotefd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
    setsockopt(remotefd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
    setsockopt(remotefd, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

    // Setup
    setnonblocking(remotefd);

    // Enable MPTCP
    if (listener->mptcp == 1) {
        int err = setsockopt(remotefd, SOL_TCP, MPTCP_ENABLED, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable multipath TCP");
        }
    }

    server_t *server = new_server(serverfd, listener);
    remote_t *remote = new_remote(remotefd, listener->timeout);
    server->destaddr = destaddr;
    server->server_env = server_env;

    // expelled from eden
    cork_dllist_remove(&server->entries);
    cork_dllist_add(&server_env->connections, &server->entries);

    int r = connect(remotefd, remote_addr, get_sockaddr_len(remote_addr));

    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
        ERROR("connect");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    // init server cipher
    if (server_env->cipher.enc_method > TABLE) {
        server->e_ctx = ss_malloc(sizeof(struct enc_ctx));
        server->d_ctx = ss_malloc(sizeof(struct enc_ctx));
        enc_ctx_init(&server_env->cipher, server->e_ctx, 1);
        enc_ctx_init(&server_env->cipher, server->d_ctx, 0);
    } else {
        server->e_ctx = NULL;
        server->d_ctx = NULL;
    }

    // SSR beg
//    remote->remote_index = index;
//    server->obfs_plugin = new_obfs_class(listener->obfs_name);
//    if (server->obfs_plugin) {
//        server->obfs = server->obfs_plugin->new_obfs();
//    }
//    server->protocol_plugin = new_obfs_class(listener->protocol_name);
//    if (server->protocol_plugin) {
//        server->protocol = server->protocol_plugin->new_obfs();
//    }
//    if (listener->list_obfs_global[remote->remote_index] == NULL && server->obfs_plugin) {
//        listener->list_obfs_global[remote->remote_index] = server->obfs_plugin->init_data();
//    }
//    if (listener->list_protocol_global[remote->remote_index] == NULL && server->protocol_plugin) {
//        listener->list_protocol_global[remote->remote_index] = server->protocol_plugin->init_data();
//    }
    server_info _server_info;
    memset(&_server_info, 0, sizeof(server_info));
    strcpy(_server_info.host, server_env->host);
    _server_info.port = server_env->port;
    _server_info.param = server_env->obfs_param;
    _server_info.g_data = server_env->obfs_global;
    _server_info.head_len = (AF_INET6 == server->destaddr.ss_family ? 19 : 7);
    _server_info.iv = server->e_ctx->evp.iv;
    _server_info.iv_len = enc_get_iv_len(&server_env->cipher);
    _server_info.key = enc_get_key(&server_env->cipher);
    _server_info.key_len = enc_get_key_len(&server_env->cipher);
    _server_info.tcp_mss = 1452;
    _server_info.buffer_size = BUF_SIZE;
    _server_info.cipher_env = &server_env->cipher;

    if (server_env->obfs_plugin) {
        server->obfs = server_env->obfs_plugin->new_obfs();
        server_env->obfs_plugin->set_server_info(server->obfs, &_server_info);
    }

    _server_info.param = server_env->protocol_param;
    _server_info.g_data = server_env->protocol_global;

    if (server_env->protocol_plugin) {
        server->protocol = server_env->protocol_plugin->new_obfs();
        _server_info.overhead = server_env->protocol_plugin->get_overhead(server->protocol)
            + (server_env->obfs_plugin ? server_env->obfs_plugin->get_overhead(server->obfs) : 0);
        server_env->protocol_plugin->set_server_info(server->protocol, &_server_info);
    }
    // SSR end

    server->remote   = remote;
    remote->server   = server;

    if (verbose) {
        int port = ((struct sockaddr_in*)&destaddr)->sin_port;
        port = (uint16_t)(port >> 8 | port << 8);
        LOGI("connect to %s:%d", inet_ntoa(((struct sockaddr_in*)&destaddr)->sin_addr), port);
    }

    // listen to remote connected event
    ev_io_start(EV_A_ & remote->send_ctx->io);
    ev_timer_start(EV_A_ & remote->send_ctx->watcher);
    ev_io_start(EV_A_ & server->recv_ctx->io);
}

void
signal_cb(int dummy)
{
    keep_resolving = 0;
    exit(-1);
}

static void
init_obfs(server_def_t *serv, char *protocol, char *protocol_param, char *obfs, char *obfs_param)
{
    serv->protocol_name = protocol;
    serv->protocol_param = protocol_param;
    serv->protocol_plugin = new_obfs_class(protocol);
    serv->obfs_name = obfs;
    serv->obfs_param = obfs_param;
    serv->obfs_plugin = new_obfs_class(obfs);

    if (serv->obfs_plugin) {
        serv->obfs_global = serv->obfs_plugin->init_data();
    }
    if (serv->protocol_plugin) {
        serv->protocol_global = serv->protocol_plugin->init_data();
    }
}

int
main(int argc, char **argv)
{
    srand(time(NULL));

    int i, c;
    int pid_flags    = 0;
    int mptcp        = 0;
    int mtu          = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *protocol = NULL; // SSR
    char *protocol_param = NULL; // SSR
    char *method = NULL;
    char *obfs = NULL; // SSR
    char *obfs_param = NULL; // SSR
    char *pid_path = NULL;
    char *conf_path = NULL;
    int use_new_profile = 0;
    jconf_t *conf = NULL;

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    ss_addr_t tunnel_addr = { .host = NULL, .port = NULL };

    int option_index                    = 0;
    static struct option long_options[] = {
        { "mtu",   required_argument, 0, 0 },
        { "mptcp", no_argument,       0, 0 },
        { "help",  no_argument,       0, 0 },
        {       0,                 0, 0, 0 }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:c:b:a:n:huUvA6"
                            "O:o:G:g:",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) {
                mtu = atoi(optarg);
                LOGI("set MTU to %d", mtu);
            } else if (option_index == 1) {
                mptcp = 1;
                LOGI("enable multipath TCP");
            } else if (option_index == 2) {
                usage();
                exit(EXIT_SUCCESS);
            }
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host   = optarg;
                remote_addr[remote_num++].port = NULL;
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        // SSR beg
        case 'O':
            protocol = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'o':
            obfs = optarg;
            break;
        case 'G':
            protocol_param = optarg;
            break;
        case 'g':
            obfs_param = optarg;
            break;
        // SSR end
        case 'c':
            conf_path = optarg;
            break;
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'A':
            LOGI("The 'A' argument is deprecate! Ignored.");
            break;
        case '6':
            ipv6first = 1;
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = DEFAULT_CONF_PATH;
        }
    }

    if (conf_path != NULL) {
        conf = read_jconf(conf_path);
        if(conf->conf_ver != CONF_VER_LEGACY){
            use_new_profile = 1;
        } else {
            if (remote_num == 0) {
                remote_num = conf->server_legacy.remote_num;
                for (i = 0; i < remote_num; i++)
                    remote_addr[i] = conf->server_legacy.remote_addr[i];
            }
            if (remote_port == NULL) {
                remote_port = conf->server_legacy.remote_port;
            }
            if (local_addr == NULL) {
                local_addr = conf->server_legacy.local_addr;
            }
            if (local_port == NULL) {
                local_port = conf->server_legacy.local_port;
            }
            if (password == NULL) {
                password = conf->server_legacy.password;
            }
            // SSR beg
            if (protocol == NULL) {
                protocol = conf->server_legacy.protocol;
                LOGI("protocol %s", protocol);
            }
            if (protocol_param == NULL) {
                protocol_param = conf->server_legacy.protocol_param;
                LOGI("protocol_param %s", protocol_param);
            }
            if (method == NULL) {
                method = conf->server_legacy.method;
                LOGI("method %s", method);
            }
            if (obfs == NULL) {
                obfs = conf->server_legacy.obfs;
                LOGI("obfs %s", obfs);
            }
            if (obfs_param == NULL) {
                obfs_param = conf->server_legacy.obfs_param;
                LOGI("obfs_param %s", obfs_param);
            }
            // SSR end
        }

        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
        /*
         * no need to check the return value here since we will show
         * the user an error message if setrlimit(2) fails
         */
        if (nofile > 1024) {
            if (verbose) {
                LOGI("setting NOFILE to %d", nofile);
            }
            set_nofile(nofile);
        }
#endif
    }
    if (protocol && strcmp(protocol, "verify_sha1") == 0) {
        LOGI("The verify_sha1 protocol is deprecate! Fallback to origin protocol.");
        protocol = NULL;
    }

    if (remote_num == 0 || remote_port == NULL ||
        local_port == NULL || password == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (method == NULL) {
        method = "rc4-md5";
    }

    if (timeout == NULL) {
        timeout = "600";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGINT, signal_cb);
    signal(SIGTERM, signal_cb);

    // Setup profiles
    listen_ctx_t *profile = (listen_ctx_t *)ss_malloc(sizeof(listen_ctx_t));
    memset(profile, 0, sizeof(listen_ctx_t));

    cork_dllist_init(&all_connections);
    cork_dllist_init(&profile->connections_eden);

    profile->timeout = atoi(timeout);
    profile->mptcp = mptcp;

    if(use_new_profile) {
        char port[6];

        ss_server_new_1_t *servers = &conf->server_new_1;
        profile->server_num = servers->server_num;
        for(i = 0; i < servers->server_num; i++){
            server_def_t *serv = &profile->servers[i];
            ss_server_t *serv_cfg = &servers->servers[i];

            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));

            char *host = serv_cfg->server;
            snprintf(port, sizeof(port), "%d", serv_cfg->server_port);
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }

            serv->addr = serv->addr_udp = storage;
            serv->addr_len = serv->addr_udp_len = get_sockaddr_len((struct sockaddr *) storage);
            serv->port = serv->udp_port = serv_cfg->server_port;

            // set udp port
            if (serv_cfg->server_udp_port != 0 && serv_cfg->server_udp_port != serv_cfg->server_port) {
                storage = ss_malloc(sizeof(struct sockaddr_storage));
                snprintf(port, sizeof(port), "%d", serv_cfg->server_udp_port);
                if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                    FATAL("failed to resolve the provided hostname");
                }
                serv->addr_udp = storage;
                serv->addr_udp_len = get_sockaddr_len((struct sockaddr *) storage);
                serv->udp_port = serv_cfg->server_udp_port;
            }
            serv->host = ss_strdup(host);

            // Setup keys
            LOGI("initializing ciphers... %s", serv_cfg->method);
            enc_init(&serv->cipher, serv_cfg->password, serv_cfg->method);
            serv->psw = ss_strdup(serv_cfg->password);
            if (serv_cfg->protocol && strcmp(serv_cfg->protocol, "verify_sha1") == 0) {
                ss_free(serv_cfg->protocol);
            }

            cork_dllist_init(&serv->connections);

            // init obfs
            init_obfs(serv, ss_strdup(serv_cfg->protocol), ss_strdup(serv_cfg->protocol_param), ss_strdup(serv_cfg->obfs), ss_strdup(serv_cfg->obfs_param));

            serv->enable = serv_cfg->enable;
            serv->id = ss_strdup(serv_cfg->id);
            serv->group = ss_strdup(serv_cfg->group);
            serv->udp_over_tcp = serv_cfg->udp_over_tcp;
        }
    } else {
        profile->server_num = remote_num;
        for(i = 0; i < remote_num; i++) {
            server_def_t *serv = &profile->servers[i];
            char *host = remote_addr[i].host;
            char *port = remote_addr[i].port == NULL ? remote_port :
                         remote_addr[i].port;

            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }
            serv->host = ss_strdup(host);
            serv->addr = serv->addr_udp = storage;
            serv->addr_len = serv->addr_udp_len = get_sockaddr_len((struct sockaddr *)storage);
            serv->port = serv->udp_port = atoi(port);

            // Setup keys
            LOGI("initializing ciphers... %s", method);
            enc_init(&serv->cipher, password, method);
            serv->psw = ss_strdup(password);

            cork_dllist_init(&serv->connections);

            // init obfs
            init_obfs(serv, ss_strdup(protocol), ss_strdup(protocol_param), ss_strdup(obfs), ss_strdup(obfs_param));

            serv->enable = 1;
        }
    }

    // Init profiles
    cork_dllist_init(&inactive_profiles);
    current_profile = profile;


    struct ev_loop *loop = EV_DEFAULT;

    listen_ctx_t *listen_ctx = current_profile;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port);
        if (listenfd == -1) {
            FATAL("bind() error");
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            FATAL("listen() error");
        }
        setnonblocking(listenfd);

        listen_ctx->fd = listenfd;

        ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx->io);
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("UDP relay enabled");
        init_udprelay(local_addr, local_port, (struct sockaddr*)listen_ctx->servers[0].addr_udp,
                      listen_ctx->servers[0].addr_udp_len, tunnel_addr, mtu, listen_ctx->timeout, NULL, &listen_ctx->servers[0].cipher, listen_ctx->servers[0].protocol_name, listen_ctx->servers[0].protocol_param);
    }

    if (mode == UDP_ONLY) {
        LOGI("TCP relay disabled");
    }

    LOGI("listening at %s:%s", local_addr, local_port);

    // setuid
    if (user != NULL && ! run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0){
        LOGI("running from root user");
    }

    ev_run(loop, 0);

    // TODO: release?

    return 0;
}
