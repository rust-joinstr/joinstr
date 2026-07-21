#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
// EXTRA BEGIN
typedef struct DartCObject *WireSyncRust2DartDco;
typedef struct WireSyncRust2DartSse {
  uint8_t *ptr;
  int32_t len;
} WireSyncRust2DartSse;

typedef int64_t DartPort;
typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);
void store_dart_post_cobject(DartPostCObjectFnType ptr);
// EXTRA END
typedef struct _Dart_Handle* Dart_Handle;

typedef struct wire_cst_ffi_pool_config {
  double denomination_btc;
  uint32_t fee;
  uint64_t max_duration;
  uint32_t peers;
  int32_t network;
} wire_cst_ffi_pool_config;

typedef struct wire_cst_list_prim_u_8_strict {
  uint8_t *ptr;
  int32_t len;
} wire_cst_list_prim_u_8_strict;

typedef struct wire_cst_ffi_coin {
  struct wire_cst_list_prim_u_8_strict *txid;
  uint32_t vout;
  uint64_t value_sat;
  struct wire_cst_list_prim_u_8_strict *script_pubkey;
  uint32_t sequence;
  uint32_t coin_path_depth;
  uint32_t *coin_path_index;
} wire_cst_ffi_coin;

typedef struct wire_cst_ffi_peer_config {
  struct wire_cst_list_prim_u_8_strict *mnemonic;
  struct wire_cst_list_prim_u_8_strict *electrum_address;
  uint16_t electrum_port;
  struct wire_cst_ffi_coin input;
  struct wire_cst_list_prim_u_8_strict *output_address;
  struct wire_cst_list_prim_u_8_strict *relay;
  int32_t network;
  struct wire_cst_list_prim_u_8_strict *proxy;
} wire_cst_ffi_peer_config;

typedef struct wire_cst_list_ffi_coin {
  struct wire_cst_ffi_coin *ptr;
  int32_t len;
} wire_cst_list_ffi_coin;

typedef struct wire_cst_ffi_pool {
  struct wire_cst_list_prim_u_8_strict *id;
  struct wire_cst_list_prim_u_8_strict *raw_json;
  uint64_t denomination_sat;
  uint32_t peers;
  uint64_t expires_at_unix_sec;
  struct wire_cst_list_prim_u_8_strict *relay;
  uint32_t fee_rate;
  struct wire_cst_list_prim_u_8_strict *public_key;
  struct wire_cst_list_prim_u_8_strict *version;
} wire_cst_ffi_pool;

typedef struct wire_cst_list_ffi_pool {
  struct wire_cst_ffi_pool *ptr;
  int32_t len;
} wire_cst_list_ffi_pool;

typedef struct wire_cst_ffi_coinjoin_update {
  int32_t step;
  struct wire_cst_list_prim_u_8_strict *txid;
  struct wire_cst_list_prim_u_8_strict *error;
  struct wire_cst_list_prim_u_8_strict *output_event_id;
  struct wire_cst_list_prim_u_8_strict *input_event_id;
  struct wire_cst_list_prim_u_8_strict *psbt;
} wire_cst_ffi_coinjoin_update;

typedef struct wire_cst_joinstr_error {
  struct wire_cst_list_prim_u_8_strict *message;
} wire_cst_joinstr_error;

void frbgen_joinstr_flutter_wire__crate__api__joinstr__initiate_coinjoin(int64_t port_,
                                                                         struct wire_cst_ffi_pool_config *config,
                                                                         struct wire_cst_ffi_peer_config *peer,
                                                                         struct wire_cst_list_prim_u_8_strict *progress);

void frbgen_joinstr_flutter_wire__crate__api__joinstr__join_coinjoin(int64_t port_,
                                                                     struct wire_cst_list_prim_u_8_strict *pool_raw_json,
                                                                     struct wire_cst_ffi_peer_config *peer,
                                                                     struct wire_cst_list_prim_u_8_strict *progress);

void frbgen_joinstr_flutter_wire__crate__api__joinstr__list_coins(int64_t port_,
                                                                  struct wire_cst_list_prim_u_8_strict *mnemonic,
                                                                  struct wire_cst_list_prim_u_8_strict *electrum_address,
                                                                  uint16_t electrum_port,
                                                                  uint32_t range_start,
                                                                  uint32_t range_end,
                                                                  int32_t network,
                                                                  struct wire_cst_list_prim_u_8_strict *proxy);

void frbgen_joinstr_flutter_wire__crate__api__joinstr__list_pools(int64_t port_,
                                                                  uint64_t back,
                                                                  uint64_t timeout,
                                                                  struct wire_cst_list_prim_u_8_strict *relay,
                                                                  struct wire_cst_list_prim_u_8_strict *proxy);

struct wire_cst_ffi_peer_config *frbgen_joinstr_flutter_cst_new_box_autoadd_ffi_peer_config(void);

struct wire_cst_ffi_pool_config *frbgen_joinstr_flutter_cst_new_box_autoadd_ffi_pool_config(void);

uint32_t *frbgen_joinstr_flutter_cst_new_box_autoadd_u_32(uint32_t value);

struct wire_cst_list_ffi_coin *frbgen_joinstr_flutter_cst_new_list_ffi_coin(int32_t len);

struct wire_cst_list_ffi_pool *frbgen_joinstr_flutter_cst_new_list_ffi_pool(int32_t len);

struct wire_cst_list_prim_u_8_strict *frbgen_joinstr_flutter_cst_new_list_prim_u_8_strict(int32_t len);
static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_cst_new_box_autoadd_ffi_peer_config);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_cst_new_box_autoadd_ffi_pool_config);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_cst_new_box_autoadd_u_32);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_cst_new_list_ffi_coin);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_cst_new_list_ffi_pool);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_cst_new_list_prim_u_8_strict);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_wire__crate__api__joinstr__initiate_coinjoin);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_wire__crate__api__joinstr__join_coinjoin);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_wire__crate__api__joinstr__list_coins);
    dummy_var ^= ((int64_t) (void*) frbgen_joinstr_flutter_wire__crate__api__joinstr__list_pools);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    return dummy_var;
}
