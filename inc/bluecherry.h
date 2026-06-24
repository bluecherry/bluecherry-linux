/**
 * @file bluecherry.h
 * @author Daan Pape <daan@dptechnics.com>
 * @brief This code connects to the BlueCherry platform as a lite device.
 * @version 1.0.0
 * @date 2026-06-24
 * @copyright Copyright (c) 2026 DPTechnics BV
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#ifndef BLUECHERRY_H
#define BLUECHERRY_H

#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The maximum size of a BlueCherry message payload.
 */
#define BLUECHERRY_MAX_MESSAGE_LEN 1024

/*
 * @brief The timeout in seconds for a SSL handshake to complete.
 */
#define SSL_HANDSHAKE_TIMEOUT_SEC 30

/**
 * @brief The size of the private key buffer.
 */
#define BLUECHERRY_ZTP_PKEY_BUF_SIZE 256

/**
 * @brief The size of the CSR/certificate buffer.
 */
#define BLUECHERRY_ZTP_CERT_BUF_SIZE 576

/**
 * @brief The number of characters in a BlueCherry Type ID or Device ID.
 */
#define BLUECHERRY_ZTP_ID_LEN 8

/**
 * @brief The size of the CSR subject buffer.
 */
#define BLUECHERRY_ZTP_SUBJ_BUF_SIZE 32

/**
 * @brief The length of a MAC address in bytes.
 */
#define BLUECHERRY_ZTP_MAC_LEN 6

/**
 * @brief The length of an IMEI number.
 */
#define BLUECHERRY_ZTP_IMEI_LEN 15

/**
 * @brief The maximum number of device identification parameters.
 */
#define BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS 3

/**
 * @brief The maximum time in seconds to wait for a CoAP ring.
 */
#define BLUECHERRY_ZTP_COAP_TIMEOUT 30

/**
 * @brief Header of the function that handles reading/writing of certificates and keys
 * for zero-touch provisioning.
 *
 * @param read True when reading, false when writing.
 * @param secure True when handling the private key, false when handling the certificate.
 * @param args Optional user arguments, key or certificate passed as arguments when writing.
 *
 * @return The certificate or key when reading, NULL when writing.
 */
typedef const char* (*bluecherry_ztp_bio_handler_t)(bool read, bool secure, void* args);

/**
 * @brief Header of the function that handles incoming MQTT messages.
 *
 * This is the header of the function that is called when a new incoming MQTT message has arrived
 * from the BlueCherry cloud.
 *
 * @param topic The topic as the topic index.
 * @param len The length of the incoming data.
 * @param data The incoming data buffer.
 * @param args Optional user arguments, passed when the handler was installed.
 *
 * @return None
 */
typedef void (*bluecherry_msg_handler_t)(uint8_t topic, uint16_t len, const uint8_t* data,
                                         void* args);

/**
 * @brief This enumeration list all different types of device identification
 * parameters.
 */
typedef enum {
  BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC = 0,
  BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI,
  BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE
} bluecherry_ztp_device_id_type;

/**
 * @brief The different states the BlueCherry connection can be in.
 */
typedef enum {
  BLUECHERRY_STATE_UNINITIALIZED = 0,
  BLUECHERRY_STATE_AWAIT_CONNECTION,
  BLUECHERRY_STATE_CONNECTED_IDLE,
  BLUECHERRY_STATE_CONNECTED_AWAITING_RESPONSE,
  BLUECHERRY_STATE_CONNECTED_TIMED_OUT,
  BLUECHERRY_STATE_CONNECTED_RECEIVED_ACK,
  BLUECHERRY_STATE_CONNECTED_PENDING_MESSAGES
} bluecherry_state;

/**
 * @brief The types of CoAP packets.
 */
typedef enum {
  BLUECHERRY_COAP_TYPE_CON = 0,
  BLUECHERRY_COAP_TYPE_NON = 1,
  BLUECHERRY_COAP_TYPE_ACK = 2,
  BLUECHERRY_COAP_TYPE_RST = 3
} _bluecherry_coap_type;

/**
 * @brief The types of CoAP responses.
 */
typedef enum {
  BLUECHERRY_COAP_RSP_VALID = 0x43,
  BLUECHERRY_COAP_RSP_CONTINUE = 0x61
} _bluecherry_coap_response;

/**
 * @brief The possible types of BlueCherry events.
 */
typedef enum {
  BLUECHERRY_EVENT_TYPE_OTA_INITIALIZE = 1,
  BLUECHERRY_EVENT_TYPE_OTA_CHUNK = 2,
  BLUECHERRY_EVENT_TYPE_OTA_FINISH = 3,
  BLUECHERRY_EVENT_TYPE_OTA_ERROR = 4
} _bluecherry_event_type;

/**
 * @brief The size of the BlueCherry CoAP header.
 */
static const size_t BLUECHERRY_COAP_HEADER_SIZE = 5;

/**
 * @brief The size of the BlueCherry MQTT header.
 */
static const size_t BLUECHERRY_MQTT_HEADER_SIZE = 2;

/**
 * @brief The maximum number of CoAP retransmits.
 */
static const uint8_t BLUECHERRY_MAX_RETRANSMITS = 4;

/**
 * @brief The CoAP acknowledgement base timeout period.
 */
static const double BLUECHERRY_ACK_TIMEOUT = 2.0;

/**
 * @brief The CoAP acknowledgement timeout period randomness factor.
 */
static const double BLUECHERRY_ACK_RANDOM_FACTOR = 1.5;

/**
 * @brief The maximum number of milliseconds to wait for a datagram to arrive on a socket.
 */
static const uint32_t BLUECHERRY_SSL_READ_TIMEOUT = 100;

typedef union {
  /**
   * @brief Pointer to the BlueCherry Type ID, as this is always programmed in
   * the application, no extra memory is required.
   */
  const char* bcTypeId;

  /**
   * @brief A MAC address used for authentication.
   */
  unsigned char mac[BLUECHERRY_ZTP_MAC_LEN];

  /**
   * @brief An IMEI number in ASCII format + 0-terminator.
   */
  char imei[BLUECHERRY_ZTP_IMEI_LEN + 1];

  /**
   * @brief A 64-bit OOB challenge.
   */
  unsigned long long oobChallenge;
} _bluecherry_ztp_device_id_value_t;

/**
 * @brief This structure represents a device identifier.
 */
typedef struct {
  /**
   * @brief The type of device identifier.
   */
  bluecherry_ztp_device_id_type type;

  /**
   * @brief The value of the device identifier.
   */
  _bluecherry_ztp_device_id_value_t value;
} _bluecherry_ztp_device_id_param_t;

/**
 * @brief This structure represents a buffer and length of a CSR stored in PEM
 * format.
 */
typedef struct {
  /**
   * @brief The buffer used to store a CSR.
   */
  unsigned char buffer[BLUECHERRY_ZTP_CERT_BUF_SIZE];

  /**
   * @brief The data length of the CSR.
   */
  size_t length;
} _bluecherry_ztp_csr_t;

/**
 * @brief This structure represents the device identification parameters.
 */
typedef struct {
  /**
   * @brief The array of device identification parameters.
   */
  _bluecherry_ztp_device_id_param_t param[BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS];

  /**
   * @brief The number of parameters in the list.
   */
  int count;
} _bluecherry_ztp_device_id_t;

/**
 * @brief The CBOR context structure.
 */
typedef struct {
  /**
   * @brief Output buffer pointer.
   */
  uint8_t* buffer;

  /**
   * @brief Maximum size of the buffer.
   */
  size_t capacity;

  /**
   * @brief Current write position in the buffer.
   */
  size_t position;
} _ztp_cbor_t;

/**
 * @brief This structure represents a scheduled BlueCherry message.
 */
typedef struct {
  /**
   * @brief The length of the data.
   */
  size_t len;

  /**
   * @brief A pointer to the data.
   */
  uint8_t* data;
} _bluecherry_msg_t;

/**
 * @brief An entry in the message queue.
 */
typedef struct _bluecherry_msg_node {
  _bluecherry_msg_t msg;
  struct _bluecherry_msg_node* next;
} _bluecherry_msg_queue_entry_t;

/**
 * @brief Thread-safe BlueCherry message queue.
 */
typedef struct {
  _bluecherry_msg_queue_entry_t* head;
  _bluecherry_msg_queue_entry_t* tail;
  pthread_mutex_t lock;
  pthread_cond_t cond;
  int count;
} _bluecherry_queue_t;

/**
 * @brief The operational data used by the BlueCherry cloud connection.
 */
typedef struct {
  /**
   * @brief The current state of the BlueCherry cloud connection.
   */
  bluecherry_state state;

  /**
   * @brief The OpenSSL connection handle.
   */
  SSL* ssl;

  /**
   * @brief The OpenSSL context holding certificates and configuration.
   */
  SSL_CTX* ssl_ctx;

  /**
   * @brief The server CA certificate.
   */
  X509* cacert;

  /**
   * @brief The device certificate.
   */
  X509* devcert;

  /**
   * @brief The CSR object used during ZTP.
   */
  X509_REQ* ztp_csr_req;

  /**
   * @brief The device private key.
   */
  EVP_PKEY* devkey;

  /**
   * @brief The device ZTP identification data.
   */
  _bluecherry_ztp_device_id_t ztp_devIdParams;

  /**
   * @brief The CSR context.
   */
  _bluecherry_ztp_csr_t ztp_csr;

  /**
   * @brief The socket used to communicate with the BlueCherry cloud.
   */
  int sock;

  /**
   * @brief The outgoing message queue.
   */
  _bluecherry_queue_t out_queue;

  /**
   * @brief The message handler or NULL to ignore incoming messages.
   */
  bluecherry_msg_handler_t msg_handler;

  /**
   * @brief Optional user arguments to pass to the incoming message handler.
   */
  void* msg_handler_args;

  /**
   * @brief The current CoAP message id that is used.
   */
  uint16_t cur_message_id;

  /**
   * @brief The last CoAP message id that was acknowledged from the cloud.
   */
  uint16_t last_acked_message_id;

  /**
   * @brief The last CoAP transmission time.
   */
  time_t last_tx_time;

  /**
   * @brief The length of the last incoming buffer data.
   */
  size_t in_buf_len;

  /**
   * @brief The buffer to receive incoming server data in.
   */
  uint8_t in_buf[BLUECHERRY_MAX_MESSAGE_LEN];
} _bluecherry_t;

/**
 * @brief Initialize the BlueCherry subsystem without ZTP.
 *
 * This function will initialize the BlueCherry IoT module without zero-touch provisioning enabled.
 *
 * @param device_cert The BlueCherry device certificate in PEM format.
 * @param device_key The BlueCherry device certificate's key in PEM format.
 * @param msg_handler The handler used for incoming messages or NULL to ignore them.
 * @param msg_handler_args Optional user pointer which is passed to the message handler.
 * @param auto_sync When set to true, the library will automatically perform syncs in the background.
 *
 * @return True on success, false on failure.
 */
bool bluecherry_init(const char* device_cert, const char* device_key,
                     bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                     bool auto_sync);

/**
 * @brief Initialize the BlueCherry subsystem with ZTP.
 *
 * This function will initialize the BlueCherry IoT module with zero-touch provisioning enabled.
 *
 * @param ztp_bio_handler The handler used for reading/writing keys and certificates. This must be
 * implemented by the application.
 * @param ztp_bio_handler_args Optional user pointer which is passed to the ZTP bio handler.
 * @param bc_device_type The BlueCherry device type string.
 * @param msg_handler The handler used for incoming messages or NULL to ignore them.
 * @param msg_handler_args Optional user pointer which is passed to the message handler.
 * @param auto_sync When set to true, the library will automatically perform syncs in the background.
 *
 * @return True on success, false on failure.
 */
bool bluecherry_init_ztp(bluecherry_ztp_bio_handler_t ztp_bio_handler,
                         void* ztp_bio_handler_args, const char* bc_device_type,
                         bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                         bool auto_sync);

/**
 * @brief Synchronize incoming and outgoing BlueCherry messages.
 *
 * This function will communicate with the BlueCherry cloud and send any enqueued MQTT messages
 * and check if there are any incoming MQTT messages.
 *
 * @param blocking When true, the function will block until a message is sent or received, or the
 *                  BLUECHERRY_AUTO_SYNC_SECONDS timeout expires.
 *
 * @return True on success, false on failure.
 */
bool bluecherry_sync(bool blocking);

/**
 * @brief Enqueue an MQTT message for publishing.
 *
 * This function will add the MQTT message to the outgoing message queue. After bluecherry_sync, the
 * messages will be forwarded to the designated broker.
 *
 * @param topic The topic of the message, passed as the topic index.
 * @param len The length of the topic payload data.
 * @param data The topic payload data.
 *
 * @return True on success, false on failure.
 */
bool bluecherry_publish(uint8_t topic, uint16_t len, const uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif
