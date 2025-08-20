#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include "auth.h"
#include "obfsutil.h"
#include "crc32.h"
#include "base64.h"
#include "encrypt.h"
#include "obfs.h"

uint32_t g_endian_test = 1;

typedef struct shift128plus_ctx {
    uint64_t v[2];
} shift128plus_ctx;

uint64_t shift128plus_next(shift128plus_ctx *ctx) {
    uint64_t x = ctx->v[0];
    uint64_t y = ctx->v[1];
    ctx->v[0] = y;
    x ^= x << 23;
    x ^= (y ^ (x >> 17) ^ (y >> 26));
    ctx->v[1] = x;
    return x + y;
}

void i64_memcpy(uint8_t *target, uint8_t *source) {
    for (int i = 0; i < 8; ++i)
        target[i] = source[7 - i];
}

int find_pos(int arr[], int length, int key) {
    int low = 0;
    int high = length - 1;
    int middle = -1;

    if (key > arr[high])
        return length;

    while (low < high) {
        middle = (low + high) / 2;
        if (key > arr[middle]) {
            low = middle + 1;
        } else if (key <= arr[middle]) {
            high = middle;
        }
    }
    return low;
}

int data_size_list_compare(const void *a, const void *b) {
    return (*(int *) a - *(int *) b);
}

void shift128plus_init_from_bin(shift128plus_ctx *ctx, uint8_t *bin, int bin_size) {
    uint8_t fill_bin[16] = {0};
    memcpy(fill_bin, bin, bin_size);
    if (*(uint8_t *) &g_endian_test == 1) {
        memcpy(ctx, fill_bin, 16);
    } else {
        i64_memcpy((uint8_t *) ctx, fill_bin);
        i64_memcpy((uint8_t *) ctx + 8, fill_bin + 8);
    }
}

void shift128plus_init_from_bin_datalen(shift128plus_ctx *ctx, uint8_t *bin, int bin_size, int datalen) {
    uint8_t fill_bin[16] = {0};
    memcpy(fill_bin, bin, bin_size);
    fill_bin[0] = datalen;
    fill_bin[1] = datalen >> 8;
    if (*(uint8_t *) &g_endian_test == 1) {
        memcpy(ctx, fill_bin, 16);
    } else {
        i64_memcpy((uint8_t *) ctx, fill_bin);
        i64_memcpy((uint8_t *) ctx + 8, fill_bin + 8);
    }
    for (int i = 0; i < 4; ++i) {
        shift128plus_next(ctx);
    }
}

typedef struct auth_chain_global_data {
    uint8_t local_client_id[4];
    uint32_t connection_id;
} auth_chain_global_data;

typedef struct auth_chain_b_data {
    int *data_size_list;
    int data_size_list_length;
    int *data_size_list2;
    int data_size_list2_length;
} auth_chain_b_data;

typedef struct auth_chain_c_data {
    int *data_size_list0;
    int data_size_list0_length;
} auth_chain_c_data;

typedef struct auth_chain_local_data {
    int has_sent_header;
    char *recv_buffer;
    int recv_buffer_size;
    uint32_t recv_id;
    uint32_t pack_id;
    char *salt;
    uint8_t *user_key;
    char uid[4];
    int user_key_len;
    int last_data_len;
    uint8_t last_client_hash[16];
    uint8_t last_server_hash[16];
    shift128plus_ctx random_client;
    shift128plus_ctx random_server;
    int cipher_init_flag;
    cipher_env_t cipher;
    enc_ctx_t *cipher_client_ctx;
    enc_ctx_t *cipher_server_ctx;

    unsigned int (*get_tcp_rand_len)(
            struct auth_chain_local_data *local,
            server_info *server,
            int datalength,
            shift128plus_ctx *random,
            uint8_t *last_hash
    );

    void *auth_chain_special_data;
} auth_chain_local_data;

void auth_chain_local_data_init(auth_chain_local_data *local) {
    local->has_sent_header = 0;
    local->recv_buffer = (char *) malloc(16384);
    local->recv_buffer_size = 0;
    local->recv_id = 1;
    local->pack_id = 1;
    local->salt = "";
    local->user_key = 0;
    local->user_key_len = 0;
    local->cipher_init_flag = 0;
    local->cipher_client_ctx = 0;
    local->cipher_server_ctx = 0;
    local->get_tcp_rand_len = NULL;
}

unsigned int auth_chain_a_get_rand_len(
        auth_chain_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    if (datalength > 1440)
        return 0;
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength);
    if (datalength > 1300)
        return (unsigned int) (shift128plus_next(random) % 31);
    if (datalength > 900)
        return (unsigned int) (shift128plus_next(random) % 127);
    if (datalength > 400)
        return (unsigned int) (shift128plus_next(random) % 521);
    return (unsigned int) (shift128plus_next(random) % 1021);
}

unsigned int auth_chain_b_get_rand_len(
        auth_chain_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    if (datalength > 1440)
        return 0;
    uint16_t overhead = server->overhead;
    auth_chain_b_data *special_data = (auth_chain_b_data *) local->auth_chain_special_data;

    int other_data_size = datalength + overhead;

    // auth_chain_b_get_rand_len
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength);
    int pos = find_pos(special_data->data_size_list, special_data->data_size_list_length, other_data_size);
    uint64_t final_pos = pos + shift128plus_next(random) % special_data->data_size_list_length;
    if (final_pos < special_data->data_size_list_length) {
        return special_data->data_size_list[final_pos] - other_data_size;
    }

    int pos2 = find_pos(special_data->data_size_list2, special_data->data_size_list2_length, other_data_size);
    uint64_t final_pos2 = pos2 + shift128plus_next(random) % special_data->data_size_list2_length;
    if (final_pos2 < special_data->data_size_list2_length) {
        return special_data->data_size_list2[final_pos2] - other_data_size;
    }
    if (final_pos2 < pos2 + special_data->data_size_list2_length - 1) {
        return 0;
    }

    if (datalength > 1300)
        return (unsigned int) (shift128plus_next(random) % 31);
    if (datalength > 900)
        return (unsigned int) (shift128plus_next(random) % 127);
    if (datalength > 400)
        return (unsigned int) (shift128plus_next(random) % 521);
    return (unsigned int) (shift128plus_next(random) % 1021);
}

unsigned int auth_chain_c_get_rand_len(
        auth_chain_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    uint16_t overhead = server->overhead;
    auth_chain_c_data *special_data = (auth_chain_c_data *) local->auth_chain_special_data;

    int other_data_size = datalength + overhead;

    // must init random in here to make sure output sync in server and client
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength);
    if (other_data_size >= special_data->data_size_list0[special_data->data_size_list0_length - 1]) {
        if (datalength > 1440)
            return 0;
        if (datalength > 1300)
            return (unsigned int) (shift128plus_next(random) % 31);
        if (datalength > 900)
            return (unsigned int) (shift128plus_next(random) % 127);
        if (datalength > 400)
            return (unsigned int) (shift128plus_next(random) % 521);
        return (unsigned int) (shift128plus_next(random) % 1021);
    }

    int pos = find_pos(special_data->data_size_list0, special_data->data_size_list0_length, other_data_size);
    // random select a size in the leftover data_size_list0
    uint64_t final_pos = pos + shift128plus_next(random) % (special_data->data_size_list0_length - pos);
    return special_data->data_size_list0[final_pos] - other_data_size;
}

unsigned int auth_chain_d_get_rand_len(
        auth_chain_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    uint16_t overhead = server->overhead;
    auth_chain_c_data *special_data = (auth_chain_c_data *) local->auth_chain_special_data;

    int other_data_size = datalength + overhead;

    // if other_data_size > the bigest item in data_size_list0, not padding any data
    if (other_data_size >= special_data->data_size_list0[special_data->data_size_list0_length - 1]) {
        return 0;
    }

    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength);
    int pos = find_pos(special_data->data_size_list0, special_data->data_size_list0_length, other_data_size);
    // random select a size in the leftover data_size_list0
    uint64_t final_pos = pos + shift128plus_next(random) % (special_data->data_size_list0_length - pos);
    return special_data->data_size_list0[final_pos] - other_data_size;
}

unsigned int auth_chain_e_get_rand_len(
        auth_chain_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength);
    uint16_t overhead = server->overhead;
    auth_chain_c_data *special_data = (auth_chain_c_data *) local->auth_chain_special_data;

    int other_data_size = datalength + overhead;

    // if other_data_size > the bigest item in data_size_list0, not padding any data
    if (other_data_size >= special_data->data_size_list0[special_data->data_size_list0_length - 1]) {
        return 0;
    }

    // use the mini size in the data_size_list0
    int pos = find_pos(special_data->data_size_list0, special_data->data_size_list0_length, other_data_size);
    return special_data->data_size_list0[pos] - other_data_size;
}

unsigned int auth_chain_f_get_rand_len(
        auth_chain_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    return auth_chain_e_get_rand_len(
            local,
            server,
            datalength,
            random,
            last_hash
    );
}

void auth_chain_b_init_data_size(obfs *self, server_info *server) {
    auth_chain_b_data *special_data = (auth_chain_b_data *)
            ((auth_chain_local_data *) self->l_data)->auth_chain_special_data;

    shift128plus_ctx *random = (shift128plus_ctx *) malloc(sizeof(shift128plus_ctx));

    shift128plus_init_from_bin(random, server->key, 16);
    special_data->data_size_list_length = shift128plus_next(random) % 8 + 4;
    special_data->data_size_list = (int *) malloc(special_data->data_size_list_length * sizeof(int));
    for (int i = 0; i < special_data->data_size_list_length; i++) {
        special_data->data_size_list[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list,
          special_data->data_size_list_length,
          sizeof(int),
          data_size_list_compare
    );

    special_data->data_size_list2_length = shift128plus_next(random) % 16 + 8;
    special_data->data_size_list2 = (int *) malloc(special_data->data_size_list2_length * sizeof(int));
    for (int i = 0; i < special_data->data_size_list2_length; i++) {
        special_data->data_size_list2[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list2,
          special_data->data_size_list2_length,
          sizeof(int),
          data_size_list_compare
    );

    free(random);
}

void auth_chain_c_init_data_size(obfs *self, server_info *server) {

    auth_chain_c_data *special_data = (auth_chain_c_data *)
            ((auth_chain_local_data *) self->l_data)->auth_chain_special_data;

    shift128plus_ctx *random = (shift128plus_ctx *) malloc(sizeof(shift128plus_ctx));

    shift128plus_init_from_bin(random, server->key, 16);
    special_data->data_size_list0_length = shift128plus_next(random) % (8 + 16) + (4 + 8);
    special_data->data_size_list0 = (int *) malloc(special_data->data_size_list0_length * sizeof(int));
    for (int i = 0; i < special_data->data_size_list0_length; i++) {
        special_data->data_size_list0[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list0,
          special_data->data_size_list0_length,
          sizeof(int),
          data_size_list_compare
    );

    free(random);
}

#define AUTH_CHAIN_D_MAX_DATA_SIZE_LIST_LIMIT_SIZE 64

void auth_chain_d_check_and_patch_data_size(obfs *self, shift128plus_ctx *random) {
    auth_chain_c_data *special_data = (auth_chain_c_data *)
            ((auth_chain_local_data *) self->l_data)->auth_chain_special_data;

    while (special_data->data_size_list0[special_data->data_size_list0_length - 1] < 1300
           && special_data->data_size_list0_length < AUTH_CHAIN_D_MAX_DATA_SIZE_LIST_LIMIT_SIZE) {

        // data_size_list0.size + 1
        special_data->data_size_list0[special_data->data_size_list0_length] =
                shift128plus_next(random) % 2340 % 2040 % 1440;
        ++(special_data->data_size_list0_length);
    }
}

void auth_chain_d_init_data_size(obfs *self, server_info *server) {

    auth_chain_c_data *special_data = (auth_chain_c_data *)
            ((auth_chain_local_data *) self->l_data)->auth_chain_special_data;

    shift128plus_ctx *random = (shift128plus_ctx *) malloc(sizeof(shift128plus_ctx));

    shift128plus_init_from_bin(random, server->key, 16);
    special_data->data_size_list0_length = shift128plus_next(random) % (8 + 16) + (4 + 8);
    special_data->data_size_list0 = (int *) malloc(AUTH_CHAIN_D_MAX_DATA_SIZE_LIST_LIMIT_SIZE * sizeof(int));
    for (int i = 0; i < special_data->data_size_list0_length; i++) {
        special_data->data_size_list0[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list0,
          special_data->data_size_list0_length,
          sizeof(int),
          data_size_list_compare
    );

    int old_len = special_data->data_size_list0_length;
    auth_chain_d_check_and_patch_data_size(self, random);
    if (old_len != special_data->data_size_list0_length) {
        // if check_and_patch_data_size are work, re-sort again.
        // stdlib qsort
        qsort(special_data->data_size_list0,
              special_data->data_size_list0_length,
              sizeof(int),
              data_size_list_compare
        );
    }

    free(random);
}

void auth_chain_f_init_data_size(obfs *self, server_info *server, const uint8_t *key_change_datetime_key_bytes) {

    auth_chain_c_data *special_data = (auth_chain_c_data *)
            ((auth_chain_local_data *) self->l_data)->auth_chain_special_data;

    shift128plus_ctx *random = (shift128plus_ctx *) malloc(sizeof(shift128plus_ctx));

    uint8_t *newKey = (uint8_t *) malloc(sizeof(uint8_t) * server->key_len);
    memcpy(newKey, server->key, server->key_len);
    for (int i = 0; i != 8; ++i) {
        newKey[i] ^= key_change_datetime_key_bytes[i];
    }

    shift128plus_init_from_bin(random, newKey, 16);
    free(newKey);
    newKey = NULL;

    special_data->data_size_list0_length = shift128plus_next(random) % (8 + 16) + (4 + 8);
    special_data->data_size_list0 = (int *) malloc(AUTH_CHAIN_D_MAX_DATA_SIZE_LIST_LIMIT_SIZE * sizeof(int));
    for (int i = 0; i < special_data->data_size_list0_length; i++) {
        special_data->data_size_list0[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list0,
          special_data->data_size_list0_length,
          sizeof(int),
          data_size_list_compare
    );

    int old_len = special_data->data_size_list0_length;
    auth_chain_d_check_and_patch_data_size(self, random);
    if (old_len != special_data->data_size_list0_length) {
        // if check_and_patch_data_size are work, re-sort again.
        // stdlib qsort
        qsort(special_data->data_size_list0,
              special_data->data_size_list0_length,
              sizeof(int),
              data_size_list_compare
        );
    }

    free(random);
}

void *auth_chain_a_init_data() {
    auth_chain_global_data *global = (auth_chain_global_data *) malloc(sizeof(auth_chain_global_data));
    rand_bytes(global->local_client_id, 4);
    rand_bytes((uint8_t *) &global->connection_id, 4);
    global->connection_id &= 0xFFFFFF;
    return global;
}

void *auth_chain_b_init_data() {
    return auth_chain_a_init_data();
}

void *auth_chain_c_init_data() {
    return auth_chain_a_init_data();
}

void *auth_chain_d_init_data() {
    return auth_chain_c_init_data();
}

void *auth_chain_e_init_data() {
    return auth_chain_d_init_data();
}

void *auth_chain_f_init_data() {
    return auth_chain_e_init_data();
}

obfs *auth_chain_a_new_obfs() {
    obfs *self = new_obfs();
    self->l_data = malloc(sizeof(auth_chain_local_data));
    auth_chain_local_data_init((auth_chain_local_data *) self->l_data);
    ((auth_chain_local_data *) self->l_data)->salt = "auth_chain_a";
    ((auth_chain_local_data *) self->l_data)->get_tcp_rand_len = auth_chain_a_get_rand_len;
    return self;
}

obfs *auth_chain_b_new_obfs() {
    obfs *self = new_obfs();
    self->l_data = malloc(sizeof(auth_chain_local_data));
    auth_chain_local_data_init((auth_chain_local_data *) self->l_data);
    ((auth_chain_local_data *) self->l_data)->salt = "auth_chain_b";
    ((auth_chain_local_data *) self->l_data)->get_tcp_rand_len = auth_chain_b_get_rand_len;
    auth_chain_b_data *special_data = (auth_chain_b_data *) malloc(sizeof(auth_chain_b_data));
    special_data->data_size_list = NULL;
    special_data->data_size_list_length = 0;
    special_data->data_size_list2 = NULL;
    special_data->data_size_list2_length = 0;
    ((auth_chain_local_data *) self->l_data)->auth_chain_special_data = special_data;
    return self;
}

obfs *auth_chain_c_new_obfs() {
    obfs *self = new_obfs();
    self->l_data = malloc(sizeof(auth_chain_local_data));
    auth_chain_local_data_init((auth_chain_local_data *) self->l_data);
    ((auth_chain_local_data *) self->l_data)->salt = "auth_chain_c";
    ((auth_chain_local_data *) self->l_data)->get_tcp_rand_len = auth_chain_c_get_rand_len;
    auth_chain_c_data *special_data = (auth_chain_c_data *) malloc(sizeof(auth_chain_c_data));
    special_data->data_size_list0 = NULL;
    special_data->data_size_list0_length = 0;
    ((auth_chain_local_data *) self->l_data)->auth_chain_special_data = special_data;
    return self;
}

obfs *auth_chain_d_new_obfs() {
    obfs *self = auth_chain_c_new_obfs();
    ((auth_chain_local_data *) self->l_data)->salt = "auth_chain_d";
    ((auth_chain_local_data *) self->l_data)->get_tcp_rand_len = auth_chain_d_get_rand_len;
    return self;
}

obfs *auth_chain_e_new_obfs() {
    obfs *self = auth_chain_d_new_obfs();
    ((auth_chain_local_data *) self->l_data)->salt = "auth_chain_e";
    ((auth_chain_local_data *) self->l_data)->get_tcp_rand_len = auth_chain_e_get_rand_len;
    return self;
}

obfs *auth_chain_f_new_obfs() {
    obfs *self = auth_chain_e_new_obfs();
    ((auth_chain_local_data *) self->l_data)->salt = "auth_chain_f";
    ((auth_chain_local_data *) self->l_data)->get_tcp_rand_len = auth_chain_f_get_rand_len;
    return self;
}

int auth_chain_a_get_overhead(obfs *self) {
    return 4;
}

int auth_chain_b_get_overhead(obfs *self) {
    return auth_chain_a_get_overhead(self);
}

int auth_chain_c_get_overhead(obfs *self) {
    return auth_chain_a_get_overhead(self);
}

int auth_chain_d_get_overhead(obfs *self) {
    return auth_chain_c_get_overhead(self);
}

int auth_chain_e_get_overhead(obfs *self) {
    return auth_chain_d_get_overhead(self);
}

int auth_chain_f_get_overhead(obfs *self) {
    return auth_chain_e_get_overhead(self);
}

void auth_chain_a_dispose(obfs *self) {
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    if (local->user_key != NULL) {
        free(local->user_key);
        local->user_key = NULL;
    }
    if (local->cipher_init_flag) {
        if (local->cipher_client_ctx) {
            enc_ctx_release(&local->cipher, local->cipher_client_ctx);
        }
        if (local->cipher_server_ctx) {
            enc_ctx_release(&local->cipher, local->cipher_server_ctx);
        }
        enc_release(&local->cipher);
        local->cipher_init_flag = 0;
    }
    free(local);
    self->l_data = NULL;
    dispose_obfs(self);
}

void auth_chain_b_dispose(obfs *self) {
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;
    auth_chain_b_data *special_data = (auth_chain_b_data *) local->auth_chain_special_data;
    if (local->auth_chain_special_data != NULL) {
        if (special_data->data_size_list != NULL) {
            free(special_data->data_size_list);
            special_data->data_size_list = NULL;
            special_data->data_size_list_length = 0;
        }
        if (special_data->data_size_list2 != NULL) {
            free(special_data->data_size_list2);
            special_data->data_size_list2 = NULL;
            special_data->data_size_list2_length = 0;
        }
        free(local->auth_chain_special_data);
        local->auth_chain_special_data = NULL;
    }
    auth_chain_a_dispose(self);
}

void auth_chain_c_dispose(obfs *self) {
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;
    auth_chain_c_data *special_data = (auth_chain_c_data *) local->auth_chain_special_data;
    if (local->auth_chain_special_data != NULL) {
        if (special_data->data_size_list0 != NULL) {
            free(special_data->data_size_list0);
            special_data->data_size_list0 = NULL;
            special_data->data_size_list0_length = 0;
        }
        free(local->auth_chain_special_data);
        local->auth_chain_special_data = NULL;
    }
    auth_chain_a_dispose(self);
}

void auth_chain_d_dispose(obfs *self) {
    auth_chain_c_dispose(self);
}

void auth_chain_e_dispose(obfs *self) {
    auth_chain_d_dispose(self);
}

void auth_chain_f_dispose(obfs *self) {
    auth_chain_e_dispose(self);
}

void auth_chain_a_set_server_info(obfs *self, server_info *server) {
    // dont change server.overhead in there
    // the server.overhead are counted from the local.c
    // the input's server.overhead is the total server.overhead that sum of all the plugin's overhead
    memmove(&self->server, server, sizeof(server_info));
}

void auth_chain_b_set_server_info(obfs *self, server_info *server) {
    memmove(&self->server, server, sizeof(server_info));
    // auth_chain_b_init_data_size() init in there
    auth_chain_b_init_data_size(self, &self->server);
}

void auth_chain_c_set_server_info(obfs *self, server_info *server) {
    memmove(&self->server, server, sizeof(server_info));
    // auth_chain_c_init_data_size() init in there
    auth_chain_c_init_data_size(self, &self->server);
}

void auth_chain_d_set_server_info(obfs *self, server_info *server) {
    memmove(&self->server, server, sizeof(server_info));
    // auth_chain_d_init_data_size() init in there
    auth_chain_d_init_data_size(self, &self->server);
}

void auth_chain_e_set_server_info(obfs *self, server_info *server) {
    auth_chain_d_set_server_info(self, server);
}

void auth_chain_f_set_server_info(obfs *self, server_info *server) {
    memmove(&self->server, server, sizeof(server_info));

    uint64_t key_change_interval = 60 * 60 * 24;     // a day by second
    if (server->param != NULL && server->param[0] != 0) {
        char *delim1 = strchr(server->param, '#');
        if (delim1 != NULL && delim1[1] != '\0') {
            ++delim1;
            char *delim2 = strchr(delim1, '#');
            if (delim2 == NULL) {
                delim2 = strchr(delim1, '\0');
            }
            unsigned long l = delim2 - delim1;
            if (l > 2) {
                long long n = strtoll(delim1, &delim2, 0);
                if (n != 0 && n != LLONG_MAX && n != LLONG_MIN && n > 0) {
                    key_change_interval = (uint64_t) n;
                }
            }
        }
    }

    uint8_t *key_change_datetime_key_bytes = (uint8_t *) malloc(sizeof(uint8_t) * 8);
    uint64_t key_change_datetime_key = (uint64_t) (time(NULL)) / key_change_interval;
    for (int i = 7; i >= 0; --i) {
        key_change_datetime_key_bytes[7 - i] = (uint8_t) ((key_change_datetime_key >> (8 * i)) & 0xFF);
    }

    auth_chain_f_init_data_size(self, &self->server, key_change_datetime_key_bytes);

    free(key_change_datetime_key_bytes);
    key_change_datetime_key_bytes = NULL;
}

unsigned int udp_get_rand_len(shift128plus_ctx *random, uint8_t *last_hash) {
    shift128plus_init_from_bin(random, last_hash, 16);
    return shift128plus_next(random) % 127;
}

unsigned int get_rand_start_pos(int rand_len, shift128plus_ctx *random) {
    if (rand_len > 0)
        return shift128plus_next(random) % 8589934609 % rand_len;
    return 0;
}

unsigned int get_client_rand_len(auth_chain_local_data *local, server_info *server, int datalength) {
    return local->get_tcp_rand_len(local, server, datalength, &local->random_client, local->last_client_hash);
}

unsigned int get_server_rand_len(auth_chain_local_data *local, server_info *server, int datalength) {
    return local->get_tcp_rand_len(local, server, datalength, &local->random_server, local->last_server_hash);
}

int auth_chain_a_pack_data(char *data, int datalength, char *outdata, auth_chain_local_data *local,
                           server_info *server) {
    unsigned int rand_len = get_client_rand_len(local, server, datalength);
    int out_size = (int) rand_len + datalength + 2;
    outdata[0] = (char) ((uint8_t) datalength ^ local->last_client_hash[14]);
    outdata[1] = (char) ((uint8_t) (datalength >> 8) ^ local->last_client_hash[15]);

    {
        uint8_t *rnd_data = (uint8_t *)malloc(rand_len);
        rand_bytes(rnd_data, (int) rand_len);
        if (datalength > 0) {
            int start_pos = get_rand_start_pos(rand_len, &local->random_client);
            size_t out_len;
            ss_encrypt_buffer(&local->cipher, local->cipher_client_ctx,
                              data, datalength, &outdata[2 + start_pos], &out_len);
            memcpy(outdata + 2, rnd_data, start_pos);
            memcpy(outdata + 2 + start_pos + datalength, rnd_data + start_pos, rand_len - start_pos);
        } else {
            memcpy(outdata + 2, rnd_data, rand_len);
        }
        free(rnd_data);
    }

    uint8_t key_len = (uint8_t) (local->user_key_len + 4);
    uint8_t *key = (uint8_t *)malloc(key_len);
    memcpy(key, local->user_key, local->user_key_len);
    memintcopy_lt(key + key_len - 4, local->pack_id);
    ++local->pack_id;

    ss_md5_hmac_with_key((char *) local->last_client_hash, outdata, out_size, key, key_len);
    memcpy(outdata + out_size, local->last_client_hash, 2);
    free(key);
    return out_size + 2;
}

int auth_chain_a_pack_auth_data(auth_chain_global_data *global, server_info *server, auth_chain_local_data *local,
                                char *data, int datalength, char *outdata) {
    const int authhead_len = 4 + 8 + 4 + 16 + 4;
    const char *salt = local->salt;
    int out_size = authhead_len;

    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t *) &global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }

    char encrypt[20];

    uint8_t *key = (uint8_t *)malloc(server->iv_len + server->key_len);
    uint8_t key_len = (uint8_t) (server->iv_len + server->key_len);
    memcpy(key, server->iv, server->iv_len);
    memcpy(key + server->iv_len, server->key, server->key_len);

    time_t t = time(NULL);
    memintcopy_lt(encrypt, (uint32_t) t);
    memcpy(encrypt + 4, global->local_client_id, 4);
    memintcopy_lt(encrypt + 8, global->connection_id);
    encrypt[12] = (char) server->overhead;
    encrypt[13] = (char) (server->overhead >> 8);
    encrypt[14] = 0;
    encrypt[15] = 0;

    // first 12 bytes
    {
        rand_bytes((uint8_t *) outdata, 4);
        ss_md5_hmac_with_key((char *) local->last_client_hash, (char *) outdata, 4, key, key_len);
        memcpy(outdata + 4, local->last_client_hash, 8);
    }
    free(key);
    // uid & 16 bytes auth data
    {
        uint8_t uid[4];
        if (local->user_key == NULL) {
            if (server->param != NULL && server->param[0] != 0) {
                char *param = server->param;
                char *delim = strchr(param, ':');
                if (delim != NULL) {
                    char uid_str[16] = "";
                    strncpy(uid_str, param, delim - param);
                    char key_str[128];
                    strcpy(key_str, delim + 1);
                    long uid_long = strtol(uid_str, NULL, 10);
                    memintcopy_lt((char *) local->uid, (uint32_t) uid_long);

                    local->user_key_len = (int) strlen(key_str);
                    local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
                    memcpy(local->user_key, key_str, local->user_key_len);
                }
            }
            if (local->user_key == NULL) {
                rand_bytes((uint8_t *) local->uid, 4);

                local->user_key_len = (int) server->key_len;
                local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
                memcpy(local->user_key, server->key, local->user_key_len);
            }
        }
        for (int i = 0; i < 4; ++i) {
            uid[i] = local->uid[i] ^ local->last_client_hash[8 + i];
        }

        char encrypt_key_base64[256] = {0};
        unsigned char *encrypt_key = (unsigned char *)malloc(local->user_key_len);
        memcpy(encrypt_key, local->user_key, local->user_key_len);
        base64_encode(encrypt_key, (unsigned int) local->user_key_len, encrypt_key_base64);
        free(encrypt_key);

        int salt_len = (int)strlen(salt);
        int base64_len = (local->user_key_len + 2) / 3 * 4;
        memcpy(encrypt_key_base64 + base64_len, salt, salt_len);

        char enc_key[16];
        int enc_key_len = base64_len + salt_len;
        bytes_to_key_with_size(encrypt_key_base64, (size_t) enc_key_len, (uint8_t *) enc_key, 16);
        char encrypt_data[16];
        ss_aes_128_cbc(encrypt, encrypt_data, enc_key);
        memcpy(encrypt, uid, 4);
        memcpy(encrypt + 4, encrypt_data, 16);
    }
    // final HMAC
    {
        ss_md5_hmac_with_key((char *) local->last_server_hash, encrypt, 20, local->user_key, local->user_key_len);
        memcpy(outdata + 12, encrypt, 20);
        memcpy(outdata + 12 + 20, local->last_server_hash, 4);
    }

    char password[256] = {0};
    base64_encode(local->user_key, local->user_key_len, password);
    base64_encode(local->last_client_hash, 16, password + strlen(password));
    local->cipher_init_flag = 1;
    enc_init(&local->cipher, password, "rc4");
    local->cipher_client_ctx = malloc(sizeof(enc_ctx_t));
    local->cipher_server_ctx = malloc(sizeof(enc_ctx_t));
    enc_ctx_init(&local->cipher, local->cipher_client_ctx, 1);
    enc_ctx_init(&local->cipher, local->cipher_server_ctx, 0);

    out_size += auth_chain_a_pack_data(data, datalength, outdata + out_size, local, server);

    return out_size;
}

int auth_chain_a_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    server_info *server = (server_info *) &self->server;
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;
    char *out_buffer = (char *) malloc((size_t) (datalength * 2 + 4096));
    char *buffer = out_buffer;
    char *data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = 1200;
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_chain_a_pack_auth_data((auth_chain_global_data *) self->server.g_data, &self->server, local,
                                               data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    int unit_size = server->tcp_mss - server->overhead;
    while (len > unit_size) {
        pack_len = auth_chain_a_pack_data(data, unit_size, buffer, local, &self->server);
        buffer += pack_len;
        data += unit_size;
        len -= unit_size;
    }
    if (len > 0) {
        pack_len = auth_chain_a_pack_data(data, len, buffer, local, &self->server);
        buffer += pack_len;
    }
    len = (int) (buffer - out_buffer);
    if ((int) *capacity < len) {
        *pplaindata = (char *) realloc(*pplaindata, *capacity = (size_t) (len * 2));
        // TODO check realloc failed
        plaindata = *pplaindata;
    }
    local->last_data_len = datalength;
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_chain_a_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;
    server_info *server = (server_info *) &self->server;
    uint8_t *recv_buffer = (uint8_t *) local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    int key_len = local->user_key_len + 4;
    uint8_t *key = (uint8_t *) malloc((size_t) key_len);
    memcpy(key, local->user_key, local->user_key_len);

    char *out_buffer = (char *) malloc((size_t) local->recv_buffer_size);
    char *buffer = out_buffer;
    char error = 0;
    while (local->recv_buffer_size > 4) {
        memintcopy_lt(key + key_len - 4, local->recv_id);

        int data_len = (int) (((unsigned) (recv_buffer[1] ^ local->last_server_hash[15]) << 8) +
                              (recv_buffer[0] ^ local->last_server_hash[14]));
        int rand_len = get_server_rand_len(local, server, data_len);
        int len = rand_len + data_len;
        if (len >= 4096) {
            local->recv_buffer_size = 0;
            error = 1;
            break;
        }
        if ((len += 4) > local->recv_buffer_size)
            break;

        char hash[16];
        ss_md5_hmac_with_key(hash, (char *) recv_buffer, len - 2, key, key_len);
        if (memcmp(hash, recv_buffer + len - 2, 2)) {
            local->recv_buffer_size = 0;
            error = 1;
            break;
        }

        int pos;
        if (data_len > 0 && rand_len > 0) {
            pos = 2 + get_rand_start_pos(rand_len, &local->random_server);
        } else {
            pos = 2;
        }
        size_t out_len;
        ss_decrypt_buffer(&local->cipher, local->cipher_server_ctx,
                          (char *) recv_buffer + pos, data_len, buffer, &out_len);

        if (local->recv_id == 1) {
            server->tcp_mss = (uint8_t) buffer[0] | ((uint8_t) buffer[1] << 8);
            memmove(buffer, buffer + 2, out_len -= 2);
        }
        memcpy(local->last_server_hash, hash, 16);
        ++local->recv_id;
        buffer += out_len;
        memmove(recv_buffer, recv_buffer + len, local->recv_buffer_size -= len);
    }
    int len;
    if (error == 0) {
        len = (int) (buffer - out_buffer);
        if ((int) *capacity < len) {
            *pplaindata = (char *) realloc(*pplaindata, *capacity = (size_t) (len * 2));
            plaindata = *pplaindata;
        }
        memmove(plaindata, out_buffer, len);
    } else {
        len = -1;
    }
    free(out_buffer);
    free(key);
    return len;
}

int auth_chain_a_client_udp_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    server_info *server = (server_info *) &self->server;
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;
    char *out_buffer = (char *)malloc(datalength + 1024);

    if (local->user_key == NULL) {
        if (self->server.param != NULL && self->server.param[0] != 0) {
            char *param = self->server.param;
            char *delim = strchr(param, ':');
            if (delim != NULL) {
                char uid_str[16] = "";
                strncpy(uid_str, param, delim - param);
                char key_str[128];
                strcpy(key_str, delim + 1);
                long uid_long = strtol(uid_str, NULL, 10);
                memintcopy_lt(local->uid, (uint32_t) uid_long);

                local->user_key_len = (int) strlen(key_str);
                local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
                memcpy(local->user_key, key_str, local->user_key_len);
            }
        }
        if (local->user_key == NULL) {
            rand_bytes((uint8_t *) local->uid, 4);

            local->user_key_len = (int) self->server.key_len;
            local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
            memcpy(local->user_key, self->server.key, local->user_key_len);
        }
    }

    char auth_data[3];
    uint8_t hash[16];
    ss_md5_hmac_with_key((char *) hash, auth_data, 3, server->key, server->key_len);
    int rand_len = udp_get_rand_len(&local->random_client, hash);
    uint8_t *rnd_data = (uint8_t *)malloc(rand_len);
    rand_bytes(rnd_data, (int) rand_len);
    int outlength = datalength + rand_len + 8;

    char password[256] = {0};
    base64_encode(local->user_key, local->user_key_len, password);
    base64_encode(hash, 16, password + strlen(password));

    {
        enc_init(&local->cipher, password, "rc4");
        enc_ctx_t ctx;
        enc_ctx_init(&local->cipher, &ctx, 1);
        size_t out_len;
        ss_encrypt_buffer(&local->cipher, &ctx,
                          plaindata, datalength, out_buffer, &out_len);
        enc_ctx_release(&local->cipher, &ctx);
        enc_release(&local->cipher);
    }
    uint8_t uid[4];
    for (int i = 0; i < 4; ++i) {
        uid[i] = local->uid[i] ^ hash[i];
    }
    memmove(out_buffer + datalength, rnd_data, rand_len);
    memmove(out_buffer + outlength - 8, auth_data, 3);
    memmove(out_buffer + outlength - 5, uid, 4);
    free(rnd_data);

    ss_md5_hmac_with_key((char *) hash, out_buffer, outlength - 1, local->user_key, local->user_key_len);
    memmove(out_buffer + outlength - 1, hash, 1);

    if ((int) *capacity < outlength) {
        *pplaindata = (char *) realloc(*pplaindata, *capacity = (size_t) (outlength * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, outlength);
    free(out_buffer);
    return outlength;
}

int auth_chain_a_client_udp_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    if (datalength <= 8)
        return 0;

    char *plaindata = *pplaindata;
    server_info *server = (server_info *) &self->server;
    auth_chain_local_data *local = (auth_chain_local_data *) self->l_data;

    uint8_t hash[16];
    ss_md5_hmac_with_key((char *) hash, plaindata, datalength - 1, local->user_key, local->user_key_len);

    if (*hash != ((uint8_t *) plaindata)[datalength - 1])
        return 0;

    ss_md5_hmac_with_key((char *) hash, plaindata + datalength - 8, 7, server->key, server->key_len);

    int rand_len = udp_get_rand_len(&local->random_server, hash);
    int outlength = datalength - rand_len - 8;

    char password[256] = {0};
    base64_encode(local->user_key, local->user_key_len, password);
    base64_encode(hash, 16, password + strlen(password));

    {
        enc_init(&local->cipher, password, "rc4");
        enc_ctx_t ctx;
        enc_ctx_init(&local->cipher, &ctx, 0);
        size_t out_len;
        ss_decrypt_buffer(&local->cipher, &ctx, plaindata, outlength, plaindata, &out_len);
        enc_ctx_release(&local->cipher, &ctx);
        enc_release(&local->cipher);
    }

    return outlength;
}
