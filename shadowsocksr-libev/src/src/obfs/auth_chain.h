/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_CHAIN_H
#define _OBFS_AUTH_CHAIN_H

#include "obfs.h"


void *auth_chain_a_init_data();

void *auth_chain_b_init_data();

void *auth_chain_c_init_data();

void *auth_chain_d_init_data();

void *auth_chain_e_init_data();

void *auth_chain_f_init_data();


obfs *auth_chain_a_new_obfs();

obfs *auth_chain_b_new_obfs();

obfs *auth_chain_c_new_obfs();

obfs *auth_chain_d_new_obfs();

obfs *auth_chain_e_new_obfs();

obfs *auth_chain_f_new_obfs();


void auth_chain_a_dispose(obfs *self);

void auth_chain_b_dispose(obfs *self);

void auth_chain_c_dispose(obfs *self);

void auth_chain_d_dispose(obfs *self);

void auth_chain_e_dispose(obfs *self);

void auth_chain_f_dispose(obfs *self);


void auth_chain_a_set_server_info(obfs *self, server_info *server);

void auth_chain_b_set_server_info(obfs *self, server_info *server);

void auth_chain_c_set_server_info(obfs *self, server_info *server);

void auth_chain_d_set_server_info(obfs *self, server_info *server);

void auth_chain_e_set_server_info(obfs *self, server_info *server);

void auth_chain_f_set_server_info(obfs *self, server_info *server);


int auth_chain_a_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);

int auth_chain_a_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);

int auth_chain_a_client_udp_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);

int auth_chain_a_client_udp_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);


int auth_chain_a_get_overhead(obfs *self);

int auth_chain_b_get_overhead(obfs *self);

int auth_chain_c_get_overhead(obfs *self);

int auth_chain_d_get_overhead(obfs *self);

int auth_chain_e_get_overhead(obfs *self);

int auth_chain_f_get_overhead(obfs *self);


#endif // _OBFS_AUTH_CHAIN_H
