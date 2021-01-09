/*
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_TLS_H_
#define BOTAN_FFI_TLS_H_

#include <botan/ffi.h>

#ifdef __cplusplus
extern "C" {
#endif

// Policy
// Session_Manager
// Sessions

// Version
// Ciphersuite

// Callbacks
// Channel
// Client
// Server

/**
* TLS Policy objects
*/
typedef struct botan_tls_policy_struct* botan_tls_policy_t;

int botan_tls_policy_default_init(botan_tls_policy_t* policy);
int botan_tls_policy_nsa_suiteb_init(botan_tls_policy_t* policy);
int botan_tls_policy_bsi_tr_02102_2_init(botan_tls_policy_t* policy);
int botan_tls_policy_text_init(botan_tls_policy_t* policy, const char* policy_text);
int botan_tls_policy_destroy(botan_tls_policy_t policy);

/*
* TLS Session Managers
*/
typedef struct botan_tls_session_manager_struct* botan_tls_session_manager_t;

int botan_tls_session_manager_memory_init(botan_tls_session_manager_t* mgr,
                                          size_t max_sessions);

int botan_tls_session_manager_sql_init(botan_tls_session_manager_t* mgr,
                                       const char* sql_db_filename,
                                       const char* db_passphrase,
                                       size_t max_sessions);

// TODO botan_tls_session_manager_custom_init taking function callbacks

int botan_tls_session_manager_destroy(botan_tls_session_manager_t mgr);

/**
* TLS Session objects
*/
typedef struct botan_tls_session_struct* botan_tls_session_t;

BOTAN_TEST_API int botan_tls_session_encrypt(botan_tls_session_t session,
                                             botan_rng_t rng,
                                             uint8_t key[], size_t* key_len);

BOTAN_TEST_API int botan_tls_session_decrypt(botan_tls_session_t* session,
                                             const uint8_t key[], size_t key_len,
                                             const uint8_t blob[], size_t blob_len);

BOTAN_TEST_API int botan_tls_session_get_version(botan_tls_session_t session, uint16_t* tls_version);
BOTAN_TEST_API int botan_tls_session_get_ciphersuite(botan_tls_session_t session, uint16_t* ciphersuite);

BOTAN_TEST_API int botan_tls_session_get_peer_certs(botan_tls_session_t session, botan_x509_cert_t certs[], size_t* cert_len);

/**
* TLS Channel Callbacks
*/
typedef struct botan_tls_channel_struct* botan_tls_channel_t;

typedef void (*botan_tls_channel_output_fn)(void* application_data, const uint8_t* data, size_t data_len);

typedef void (*botan_tls_channel_data_cb)(void* application_data, const uint8_t* data, size_t data_len);

typedef void (*botan_tls_channel_alert_cb)(void* application_data, uint16_t alert_code);

typedef void (*botan_tls_channel_session_established)(void* application_data,
                                                      botan_tls_channel_t channel,
                                                      botan_tls_session_t session);

BOTAN_TEST_API int botan_tls_channel_init_client(botan_tls_channel_t* channel,
                                                 botan_tls_channel_output_fn output_fn,
                                                 botan_tls_channel_data_cb data_cb,
                                                 botan_tls_channel_alert_cb alert_cb,
                                                 botan_tls_channel_session_established session_cb,
                                                 botan_tls_session_manager_t session_manager,
                                                 const char* server_name);

BOTAN_TEST_API int botan_tls_channel_init_server(botan_tls_channel_t* channel,
                                                 botan_tls_channel_output_fn output_fn,
                                                 botan_tls_channel_data_cb data_cb,
                                                 botan_tls_channel_alert_cb alert_cb,
                                                 botan_tls_channel_session_established session_cb,
                                                 botan_tls_session_manager_t session_manager);

BOTAN_TEST_API int botan_tls_channel_received_data(botan_tls_channel_t chan,
                                                   const uint8_t input[], size_t len);

/**
* Returns 0 for client, 1 for server, negative for error
*/
BOTAN_TEST_API int botan_tls_channel_type(botan_tls_channel_t chan);

BOTAN_TEST_API int botan_tls_channel_send(botan_tls_channel_t chan,
                                          const uint8_t input[], size_t len);

BOTAN_TEST_API int botan_tls_channel_close(botan_tls_channel_t chan);

BOTAN_TEST_API int botan_tls_channel_destroy(botan_tls_channel_t chan);

#ifdef __cplusplus
}
#endif

#endif
