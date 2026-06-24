/**
 * @file bclite.c
 * @author Daan Pape <daan@dptechnics.com>
 * @author Thibo Verheyde <thibo@dptechnics.com>
 * @author Arnoud Devoogdt <arnoud@dptechnics.com>
 * @brief This code connects to the BlueCherry platform.
 * @version 1.3.4
 * @date 2025-10-27
 * @copyright Copyright (c) 2025 DPTechnics BV
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

#include "bclite.h"

#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#ifdef BC_LOG_ENABLE
#define BC_LOGE(fmt, ...) fprintf(stderr, "ERROR [BlueCherry]: " fmt "\n", ##__VA_ARGS__)
#define BC_LOGW(fmt, ...) fprintf(stderr, "WARN  [BlueCherry]: " fmt "\n", ##__VA_ARGS__)
#define BC_LOGI(fmt, ...) fprintf(stdout, "INFO  [BlueCherry]: " fmt "\n", ##__VA_ARGS__)
#define BC_LOGD(fmt, ...) fprintf(stdout, "DEBUG [BlueCherry]: " fmt "\n", ##__VA_ARGS__)
#else
#define BC_LOGE(fmt, ...)
#define BC_LOGW(fmt, ...)
#define BC_LOGI(fmt, ...)
#define BC_LOGD(fmt, ...)
#endif

/**
 * @brief The operational data used by the BlueCherry cloud  connection.
 */
static _bluecherry_t _bluecherry_opdata = { 0 };

/**
 * @brief The hostname of the BlueCherry cloud.
 */
static const char* BLUECHERRY_HOST = "coap.bluecherry.io";

/**
 * @brief The port of the BlueCherry cloud.
 */
static const char* BLUECHERRY_PORT = "5684";

/**
 * @brief The port of the BlueCherry ZTP server.
 */
static const char* BLUECHERRY_ZTP_PORT = "5688";

/**
 * @brief The buffer used to store a private key.
 */
static char ztp_pkeyBuf[BLUECHERRY_ZTP_PKEY_BUF_SIZE];

/**
 * @brief The buffer used to store a certificate.
 */
static char ztp_certBuf[BLUECHERRY_ZTP_CERT_BUF_SIZE];

/**
 * @brief The BlueCherry device ID received from the server.
 */
static char ztp_bcDevId[BLUECHERRY_ZTP_ID_LEN + 1];

/**
 * @brief The size of the buffer used for the CSR subject.
 */
static char ztp_subjBuf[BLUECHERRY_ZTP_SUBJ_BUF_SIZE];

/**
 * @brief The BlueCherry type ID associated with this firmware.
 */
static const char* bcTypeId;

/**
 * @brief The BlueCherry CA root + intermediate certificate used for CoAP DTLS
 * communication.
 */
static const char* BLUECHERRY_CA = "-----BEGIN CERTIFICATE-----\r\n\
MIIBlTCCATqgAwIBAgICEAAwCgYIKoZIzj0EAwMwGjELMAkGA1UEBhMCQkUxCzAJ\r\n\
BgNVBAMMAmNhMB4XDTI0MDMyNDEzMzM1NFoXDTQ0MDQwODEzMzM1NFowJDELMAkG\r\n\
A1UEBhMCQkUxFTATBgNVBAMMDGludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqG\r\n\
SM49AwEHA0IABJGFt28UrHlbPZEjzf4CbkvRaIjxDRGoeHIy5ynfbOHJ5xgBl4XX\r\n\
hp/r8zOBLqSbu6iXGwgjp+wZJe1GCDi6D1KjZjBkMB0GA1UdDgQWBBR/rtuEomoy\r\n\
49ovMAnj5Hpmk2gTGjAfBgNVHSMEGDAWgBR3Vw0Y1sUvMhkX7xySsX55tvsu8TAS\r\n\
BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAwNJ\r\n\
ADBGAiEApN7DmuufC/aqyt6g2Y8qOWg6AXFUyTcub8/Y28XY3KgCIQCs2VUXCPwn\r\n\
k8jR22wsqNvZfbndpHthtnPqI5+yFXrY4A==\r\n\
-----END CERTIFICATE-----\r\n\
-----BEGIN CERTIFICATE-----\r\n\
MIIBmDCCAT+gAwIBAgIUDjfXeosg0fphnshZoXgQez0vO5UwCgYIKoZIzj0EAwMw\r\n\
GjELMAkGA1UEBhMCQkUxCzAJBgNVBAMMAmNhMB4XDTI0MDMyMzE3MzU1MloXDTQ0\r\n\
MDQwNzE3MzU1MlowGjELMAkGA1UEBhMCQkUxCzAJBgNVBAMMAmNhMFkwEwYHKoZI\r\n\
zj0CAQYIKoZIzj0DAQcDQgAEB00rHNthOOYyKj80cd/DHQRBGSbJmIRW7rZBNA6g\r\n\
fbEUrY9NbuhGS6zKo3K59zYc5R1U4oBM3bj6Q7LJfTu7JqNjMGEwHQYDVR0OBBYE\r\n\
FHdXDRjWxS8yGRfvHJKxfnm2+y7xMB8GA1UdIwQYMBaAFHdXDRjWxS8yGRfvHJKx\r\n\
fnm2+y7xMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49\r\n\
BAMDA0cAMEQCID7AcgACnXWzZDLYEainxVDxEJTUJFBhcItO77gcHPZUAiAu/ZMO\r\n\
VYg4UI2D74WfVxn+NyVd2/aXTvSBp8VgyV3odA==\r\n\
-----END CERTIFICATE-----\r\n";

/**
 * @brief The entrypoint of the automatic BlueCherry synchronisation thread.
 *
 * This function implements the automatic BlueCherry synchronisation.
 *
 * @param args A NULL pointer.
 *
 * @return NULL
 */
static void* _bluecherry_sync_task(void* args)
{
  (void)args;
  while(true) {
    bool pending = (_bluecherry_opdata.state == BLUECHERRY_STATE_CONNECTED_PENDING_MESSAGES);
    bluecherry_sync(!pending);
    nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 10000000 }, NULL);
  }
  return NULL;
}

#pragma region SSL NET SOCKET

/**
 * @brief Read up to len bytes from the DTLS socket.
 *
 * Blocks for at most BLUECHERRY_SSL_READ_TIMEOUT ms. Returns the number of bytes
 * read (>0), 0 on read timeout (caller should retry), or -1 on a fatal error.
 *
 * @param buf Pointer to a buffer to read the results in.
 * @param len The maximum number of bytes to read.
 *
 * @return Bytes read, 0 on timeout, -1 on error.
 */
static int _bluecherry_ssl_read(unsigned char* buf, size_t len)
{
  int ret = SSL_read(_bluecherry_opdata.ssl, buf, (int)len);
  if(ret > 0) {
    return ret;
  }

  int err = SSL_get_error(_bluecherry_opdata.ssl, ret);
  if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
     (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))) {
    DTLSv1_handle_timeout(_bluecherry_opdata.ssl);
    return 0;
  }

  BC_LOGE("SSL_read failed (SSL error %d)", err);
  return -1;
}

/**
 * @brief Write a buffer to the DTLS socket.
 *
 * Retries on transient want-write conditions. Returns the number of bytes written
 * (>0) or -1 on a fatal error.
 *
 * @param buf Pointer to the buffer to write.
 * @param len The length of the data to write.
 *
 * @return Bytes written or -1 on error.
 */
static int _bluecherry_ssl_write(const unsigned char* buf, size_t len)
{
  while(true) {
    int ret = SSL_write(_bluecherry_opdata.ssl, buf, (int)len);
    if(ret > 0) {
      return ret;
    }

    int err = SSL_get_error(_bluecherry_opdata.ssl, ret);
    if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      continue;
    }

    BC_LOGE("SSL_write failed (SSL error %d)", err);
    return -1;
  }
}

/**
 * @brief Finalize the CSR generation process.
 *
 * Cleans up OpenSSL objects used during ZTP key and CSR generation. On failure
 * the key and certificate buffers are cleared so they are not inadvertently reused.
 *
 * @param result The result of the CSR generation process.
 *
 * @return The value of result, passed through for convenience.
 */
static bool _ztp_finish_csr_gen(bool result)
{
  if(_bluecherry_opdata.devkey) {
    EVP_PKEY_free(_bluecherry_opdata.devkey);
    _bluecherry_opdata.devkey = NULL;
  }
  if(_bluecherry_opdata.ztp_csr_req) {
    X509_REQ_free(_bluecherry_opdata.ztp_csr_req);
    _bluecherry_opdata.ztp_csr_req = NULL;
  }

  if(!result) {
    ztp_pkeyBuf[0] = '\0';
    ztp_certBuf[0] = '\0';
  }

  return result;
}

/**
 * @brief Cleanup all OpenSSL resources.
 *
 * Frees the SSL session, SSL context, and all loaded certificate and key objects.
 *
 * @return None.
 */
static void _bluecherry_cleanup_ssl(void)
{
  if(_bluecherry_opdata.ssl) {
    SSL_free(_bluecherry_opdata.ssl);
    _bluecherry_opdata.ssl = NULL;
  }
  if(_bluecherry_opdata.ssl_ctx) {
    SSL_CTX_free(_bluecherry_opdata.ssl_ctx);
    _bluecherry_opdata.ssl_ctx = NULL;
  }
  if(_bluecherry_opdata.cacert) {
    X509_free(_bluecherry_opdata.cacert);
    _bluecherry_opdata.cacert = NULL;
  }
  if(_bluecherry_opdata.devcert) {
    X509_free(_bluecherry_opdata.devcert);
    _bluecherry_opdata.devcert = NULL;
  }
  if(_bluecherry_opdata.devkey) {
    EVP_PKEY_free(_bluecherry_opdata.devkey);
    _bluecherry_opdata.devkey = NULL;
  }
  if(_bluecherry_opdata.ztp_csr_req) {
    X509_REQ_free(_bluecherry_opdata.ztp_csr_req);
    _bluecherry_opdata.ztp_csr_req = NULL;
  }
}

/**
 * @brief Cleanup the network socket.
 *
 * Shuts down and closes the UDP socket used for DTLS communication.
 *
 * @return None.
 */
static void _bluecherry_cleanup_network(void)
{
  if(_bluecherry_opdata.sock > 0) {
    shutdown(_bluecherry_opdata.sock, 0);
    close(_bluecherry_opdata.sock);
    _bluecherry_opdata.sock = -1;
  }
}

/**
 * @brief Cleanup the current DTLS session without touching credentials.
 *
 * Closes the socket and frees the per-connection SSL object. The SSL_CTX and
 * loaded certificates/key are left intact so the next call to
 * _bluecherry_dtls_connect() can reuse them.
 *
 * @return None.
 */
static void _bluecherry_cleanup_session(void)
{
  _bluecherry_cleanup_network();
  if(_bluecherry_opdata.ssl) {
    SSL_free(_bluecherry_opdata.ssl);
    _bluecherry_opdata.ssl = NULL;
  }
}

/**
 * @brief Initialise the OpenSSL context for DTLS client operation.
 *
 * Creates an SSL_CTX with DTLS_client_method(), enables peer certificate
 * verification, and zeros all per-connection handles. OpenSSL seeds its RNG
 * from the OS (/dev/urandom) automatically, so no explicit seeding is needed.
 *
 * @return true if the setup was successful, false otherwise.
 */
static bool _bluecherry_setup_ssl(void)
{
  _bluecherry_opdata.ssl = NULL;
  _bluecherry_opdata.ssl_ctx = NULL;
  _bluecherry_opdata.cacert = NULL;
  _bluecherry_opdata.devcert = NULL;
  _bluecherry_opdata.devkey = NULL;
  _bluecherry_opdata.ztp_csr_req = NULL;
  _bluecherry_opdata.sock = -1;

  _bluecherry_opdata.ssl_ctx = SSL_CTX_new(DTLS_client_method());
  if(!_bluecherry_opdata.ssl_ctx) {
    BC_LOGE("Could not create SSL context");
    return false;
  }

  SSL_CTX_set_verify(_bluecherry_opdata.ssl_ctx, SSL_VERIFY_PEER, NULL);
  /* BlueCherry server does not include the RFC 5746 renegotiation_info extension.
   * Allow connecting to it without blocking on "unsafe legacy renegotiation". */
  SSL_CTX_set_options(_bluecherry_opdata.ssl_ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  return true;
}

/**
 * @brief Load CA and optional device credentials into the SSL context.
 *
 * Parses a PEM CA chain (may contain multiple certificates) into the SSL_CTX
 * trust store. If devCert and devKey are provided they are also loaded and
 * configured for mutual TLS.
 *
 * @param caCert Pointer to the CA certificate chain in PEM format.
 * @param devCert Pointer to the device certificate in PEM format, or NULL.
 * @param devKey Pointer to the device private key in PEM format, or NULL.
 *
 * @return true if the configuration was successful, false otherwise.
 */
static bool _bluecherry_configure_credentials(const char* caCert, const char* devCert,
                                              const char* devKey)
{
  BIO* bio = BIO_new_mem_buf(caCert, -1);
  if(!bio) {
    BC_LOGE("Could not create BIO for CA certificate");
    return false;
  }

  X509_STORE* store = SSL_CTX_get_cert_store(_bluecherry_opdata.ssl_ctx);
  bool loaded = false;
  X509* cert;
  while((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
    X509_STORE_add_cert(store, cert);
    X509_free(cert);
    loaded = true;
  }
  BIO_free(bio);

  if(!loaded) {
    BC_LOGE("Could not parse CA certificate chain");
    return false;
  }

  if(devCert && devKey) {
    bio = BIO_new_mem_buf(devCert, -1);
    if(!bio) {
      BC_LOGE("Could not create BIO for device certificate");
      return false;
    }
    _bluecherry_opdata.devcert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!_bluecherry_opdata.devcert) {
      BC_LOGE("Could not parse device certificate");
      return false;
    }

    bio = BIO_new_mem_buf(devKey, -1);
    if(!bio) {
      BC_LOGE("Could not create BIO for device private key");
      return false;
    }
    _bluecherry_opdata.devkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!_bluecherry_opdata.devkey) {
      BC_LOGE("Could not parse device private key");
      return false;
    }

    if(SSL_CTX_use_certificate(_bluecherry_opdata.ssl_ctx, _bluecherry_opdata.devcert) != 1) {
      BC_LOGE("Could not load device certificate into SSL context");
      return false;
    }
    if(SSL_CTX_use_PrivateKey(_bluecherry_opdata.ssl_ctx, _bluecherry_opdata.devkey) != 1) {
      BC_LOGE("Could not load device private key into SSL context");
      return false;
    }
    if(SSL_CTX_check_private_key(_bluecherry_opdata.ssl_ctx) != 1) {
      BC_LOGE("Device private key does not match certificate");
      return false;
    }
  }

  return true;
}

/**
 * @brief Connect to the BlueCherry DTLS server and perform the TLS handshake.
 *
 * Resolves the hostname, creates a connected UDP socket, wraps it in an OpenSSL
 * DTLS BIO, and drives the handshake loop with DTLS retransmit support. The
 * operational read timeout is set after the handshake completes.
 *
 * @param host The hostname of the BlueCherry server.
 * @param port The port of the BlueCherry server (as a string).
 *
 * @return true if the connection was successful, false otherwise.
 */
static bool _bluecherry_dtls_connect(const char* host, const char* port)
{
  bool success = false;
  struct addrinfo hints = { 0 };
  struct addrinfo* res = NULL;
  int ret;

  _bluecherry_cleanup_session();

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  ret = getaddrinfo(host, port, &hints, &res);
  if(ret != 0 || res == NULL) {
    BC_LOGE("DNS lookup failed: %s", gai_strerror(ret));
    goto cleanup;
  }

  _bluecherry_opdata.sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(_bluecherry_opdata.sock < 0) {
    BC_LOGE("socket() failed: %s", strerror(errno));
    goto cleanup;
  }

  ret = connect(_bluecherry_opdata.sock, res->ai_addr, res->ai_addrlen);
  if(ret != 0) {
    BC_LOGE("connect() failed: %s", strerror(errno));
    goto cleanup;
  }

  _bluecherry_opdata.ssl = SSL_new(_bluecherry_opdata.ssl_ctx);
  if(!_bluecherry_opdata.ssl) {
    BC_LOGE("Could not create SSL object");
    goto cleanup;
  }

  {
    BIO* bio = BIO_new_dgram(_bluecherry_opdata.sock, BIO_NOCLOSE);
    if(!bio) {
      BC_LOGE("Could not create DTLS BIO");
      goto cleanup;
    }
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, res->ai_addr);
    SSL_set_bio(_bluecherry_opdata.ssl, bio, bio);
  }

  SSL_set_tlsext_host_name(_bluecherry_opdata.ssl, host);
  SSL_set1_host(_bluecherry_opdata.ssl, host);

  {
    /* Short per-recv timeout drives DTLS retransmit during the handshake. */
    struct timeval hs_tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(_bluecherry_opdata.sock, SOL_SOCKET, SO_RCVTIMEO, &hs_tv, sizeof(hs_tv));

    time_t start = time(NULL);
    while(true) {
      ret = SSL_connect(_bluecherry_opdata.ssl);
      if(ret == 1) {
        break;
      }

      int err = SSL_get_error(_bluecherry_opdata.ssl, ret);
      if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
         (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK))) {
        if(difftime(time(NULL), start) >= SSL_HANDSHAKE_TIMEOUT_SEC) {
          BC_LOGE("DTLS handshake timeout");
          goto cleanup;
        }
        DTLSv1_handle_timeout(_bluecherry_opdata.ssl);
        continue;
      }
      BC_LOGE("DTLS handshake failed (SSL error %d)", err);
      goto cleanup;
    }
  }

  {
    /* Switch to the short operational read timeout used by CoAP RXTX. */
    struct timeval op_tv = { .tv_sec = 0,
                             .tv_usec = (suseconds_t)BLUECHERRY_SSL_READ_TIMEOUT * 1000 };
    setsockopt(_bluecherry_opdata.sock, SOL_SOCKET, SO_RCVTIMEO, &op_tv, sizeof(op_tv));
  }

  success = true;

cleanup:
  if(res) {
    freeaddrinfo(res);
  }
  if(!success) {
    _bluecherry_cleanup_session();
  }

  return success;
}

#pragma endregion
#pragma region CoAP RXTX
/**
 * @brief Parse the type and message ID from a received CoAP packet.
 *
 * @param buf Pointer to the input packet buffer.
 * @param len Number of bytes in the packet buffer.
 * @param type Output pointer for the packet type.
 * @param msg_id Output pointer for the parsed message ID.
 *
 * @return true if parsing succeeded, false if the packet is malformed.
 */
static bool _bluecherry_parse_ack_meta(const uint8_t* buf, size_t len, uint8_t* type,
                                       uint16_t* msg_id)
{
  if(len < 4) {
    return false;
  }

  size_t offset = 0;
  uint8_t header = buf[offset++];
  if(((header >> 6) & 0x03) != 1) {
    return false;
  }

  *type = (header >> 4) & 0x03;
  uint8_t token_len = header & 0x0F;

  if(len < (size_t)(4 + token_len)) {
    return false;
  }

  offset += token_len;
  offset++;  // code byte

  *msg_id = buf[offset++];
  *msg_id <<= 8;
  *msg_id |= buf[offset++];

  return true;
}

/**
 * @brief Perform CoAP transmit and receive operations with the BlueCherry cloud.
 *
 * Adds a CoAP header to the message, transmits it over DTLS, and waits for the
 * matching ACK with standard CoAP binary-exponential retransmit logic.
 *
 * @param msg The message to send, or NULL to send an empty sync packet.
 *
 * @return true on success, false on failure or timeout.
 */
static bool _bluecherry_coap_rxtx(_bluecherry_msg_t* msg)
{
  uint8_t no_payload_hdr[BLUECHERRY_COAP_HEADER_SIZE];
  uint8_t* data = msg == NULL ? no_payload_hdr : msg->data;
  size_t data_len = msg == NULL ? BLUECHERRY_COAP_HEADER_SIZE : msg->len;

  if(data_len < BLUECHERRY_COAP_HEADER_SIZE) {
    BC_LOGE("Cannot send CoAP message smaller than %zu B", BLUECHERRY_COAP_HEADER_SIZE);
    return false;
  }

  uint16_t tx_message_id = _bluecherry_opdata.cur_message_id + 1;
  if(tx_message_id == 0) {
    tx_message_id = 1;
  }

  uint8_t missed_msg_count =
      (uint8_t)(tx_message_id - _bluecherry_opdata.last_acked_message_id - 1);

  data[0] = 0x40;
  data[1] = missed_msg_count;
  data[2] = tx_message_id >> 8;
  data[3] = tx_message_id & 0xFF;
  data[4] = 0xFF;

  double timeout =
      BLUECHERRY_ACK_TIMEOUT * (1 + (rand() / (RAND_MAX + 1.0)) * (BLUECHERRY_ACK_RANDOM_FACTOR - 1));

  for(uint8_t attempt = 1; attempt <= BLUECHERRY_MAX_RETRANSMITS; ++attempt) {
    _bluecherry_opdata.last_tx_time = time(NULL);

    if(_bluecherry_ssl_write(data, data_len) < 0) {
      return false;
    }

    _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_AWAITING_RESPONSE;

    while(true) {
      int ret = _bluecherry_ssl_read(_bluecherry_opdata.in_buf, BLUECHERRY_MAX_MESSAGE_LEN);
      if(ret > 0) {
        _bluecherry_opdata.in_buf_len = (size_t)ret;

        uint8_t rsp_type = 0;
        uint16_t rsp_message_id = 0;
        if(!_bluecherry_parse_ack_meta(_bluecherry_opdata.in_buf, _bluecherry_opdata.in_buf_len,
                                       &rsp_type, &rsp_message_id)) {
          BC_LOGW("Ignoring malformed CoAP packet while awaiting ACK");
          continue;
        }

        if(rsp_type != BLUECHERRY_COAP_TYPE_ACK) {
          BC_LOGW("Ignoring non-ACK CoAP packet while awaiting ACK");
          continue;
        }

        if(rsp_message_id != tx_message_id) {
          BC_LOGW("Received ACK with mismatching message ID %" PRIu16 " while awaiting %" PRIu16,
                  rsp_message_id, tx_message_id);
          continue;
        }

        _bluecherry_opdata.cur_message_id = tx_message_id;
        _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_RECEIVED_ACK;
        return true;
      } else if(ret < 0) {
        return false;
      }

      if(difftime(time(NULL), _bluecherry_opdata.last_tx_time) >= timeout) {
        break;
      }
    }

    timeout *= 2;
  }

  _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_TIMED_OUT;
  return false;
}

/**
 * @brief Common CoAP transmit and receive function for ZTP operations.
 *
 * This function handles the common logic for transmitting and receiving CoAP messages
 * during the Zero Touch Provisioning (ZTP) process. It constructs the CoAP message with
 * the provided header and payload, sends it over the DTLS connection, and waits for
 * a response.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 * @param header Pointer to the CoAP header to be used for the message.
 * @param header_len Length of the CoAP header.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_common(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                             uint16_t* rx_len, const uint8_t* header,
                                             size_t header_len)
{
  static time_t last_tx_time = 0;

  _bluecherry_opdata.cur_message_id += 1;
  if(_bluecherry_opdata.cur_message_id == 0) {
    _bluecherry_opdata.cur_message_id = 1;
  }

  size_t data_len = header_len;
  uint8_t data[header_len + 1 + tx_len];

  memcpy(data, header, header_len);

  if(tx_len > 0) {
    data[header_len] = 0xFF;
    memcpy(data + header_len + 1, tx_buf, tx_len);
    data_len = header_len + 1 + tx_len;
  }

  double timeout = 2.0 * (1 + (rand() / (RAND_MAX + 1.0)) * (1.5 - 1));

  for(uint8_t attempt = 1; attempt <= 4; ++attempt) {
    last_tx_time = time(NULL);

    if(_bluecherry_ssl_write(data, data_len) < 0) {
      return false;
    }

    while(true) {
      uint8_t temp_buf[1024];
      int ret = _bluecherry_ssl_read(temp_buf, sizeof(temp_buf));

      if(ret > 0) {
        if(ret > 7) {
          memcpy(rx_buf, temp_buf + 7, (size_t)(ret - 7));
          *rx_len = (uint16_t)(ret - 7);
        } else {
          *rx_len = 0;
        }
        return true;
      } else if(ret < 0) {
        return false;
      }

      if(difftime(time(NULL), last_tx_time) >= timeout) {
        break;
      }
    }

    timeout *= 2;
  }

  return false;
}

/**
 * @brief CoAP transmit and receive function for requesting device ID.
 *
 * This function constructs and sends a CoAP message to request the device ID
 * from the BlueCherry cloud server. It uses a predefined CoAP header for the
 * device ID request and handles the transmission and reception of the message.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_devid(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                            uint16_t* rx_len)
{
  const uint8_t header[] = { 0x40,
                             0x01,
                             _bluecherry_opdata.cur_message_id >> 8,
                             _bluecherry_opdata.cur_message_id & 0xFF,
                             0xB2,
                             0x76,
                             0x31,
                             0x05,
                             0x64,
                             0x65,
                             0x76,
                             0x69,
                             0x64 };

  return _bluecherry_ztp_coap_rxtx_common(tx_buf, tx_len, rx_buf, rx_len, header, sizeof(header));
}

/**
 * @brief CoAP transmit and receive function for signing operations.
 *
 * This function constructs and sends a CoAP message to perform signing operations
 * with the BlueCherry cloud server. It uses a predefined CoAP header for the
 * signing request and handles the transmission and reception of the message.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_sign(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                           uint16_t* rx_len)
{
  const uint8_t header[] = { 0x40,
                             0x01,
                             _bluecherry_opdata.cur_message_id >> 8,
                             _bluecherry_opdata.cur_message_id & 0xFF,
                             0xB2,
                             0x76,
                             0x31,
                             0x04,
                             0x73,
                             0x69,
                             0x67,
                             0x6E };

  return _bluecherry_ztp_coap_rxtx_common(tx_buf, tx_len, rx_buf, rx_len, header, sizeof(header));
}

#pragma endregion
#pragma region ZTP

/**
 * @brief Initializes the CBOR context.
 *
 * @param cbor CBOR context to initialize.
 * @param buffer Output buffer to use.
 * @param capacity Maximum size of the buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_init(_ztp_cbor_t* cbor, uint8_t* buffer, size_t capacity)
{
  if(buffer == NULL || capacity == 0) {
    return -1;
  }

  cbor->buffer = buffer;
  cbor->capacity = capacity;
  cbor->position = 0;

  return 0;
}

/**
 * @brief Returns the size of encoded data.
 *
 * @param cbor CBOR context.
 *
 * @return Size of encoded data.
 */
static size_t _ztp_cbor_size(const _ztp_cbor_t* cbor)
{
  return cbor->position;
}

/**
 * @brief Writes a single byte to the CBOR buffer.
 *
 * @param cbor CBOR context.
 * @param byte Byte to write.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_write_byte(_ztp_cbor_t* cbor, uint8_t byte)
{
  if(cbor->position < cbor->capacity) {
    cbor->buffer[cbor->position++] = byte;
    return 0; // Success
  }
  return -1; // Buffer overflow
}

/**
 * @brief Writes a byte array to the CBOR buffer.
 *
 * @param cbor CBOR context.
 * @param data Data to write.
 * @param length Length of data to write.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_write_bytes(_ztp_cbor_t* cbor, const uint8_t* data, size_t length)
{
  if(cbor->position + length <= cbor->capacity) {
    memcpy(&cbor->buffer[cbor->position], data, length);
    cbor->position += length;
    return 0; // Success
  }
  return -1; // Buffer overflow
}

/**
 * @brief Encodes the type and value into CBOR format.
 *
 * @param cbor CBOR context.
 * @param majorType Major type of the CBOR data.
 * @param value Value to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_type_and_value(_ztp_cbor_t* cbor, uint8_t majorType, size_t value)
{
  if(value < 24) {
    return _ztp_cbor_write_byte(cbor, (majorType << 5) | value);
  } else if(value < 256) {
    if(_ztp_cbor_write_byte(cbor, (majorType << 5) | 0x18) < 0) {
      return -1;
    }
    return _ztp_cbor_write_byte(cbor, (uint8_t) value);
  } else if(value < 65536) {
    if(_ztp_cbor_write_byte(cbor, (majorType << 5) | 0x19) < 0) {
      return -1;
    }
    uint8_t bytes[] = { (uint8_t) (value >> 8), (uint8_t) value };
    return _ztp_cbor_write_bytes(cbor, bytes, 2);
  }
  return -1; // Larger values not supported
}

/**
 * @brief Encodes a byte string into CBOR format.
 *
 * @param cbor CBOR context.
 * @param data Data to encode.
 * @param length Length of data to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_bytes(_ztp_cbor_t* cbor, const uint8_t* data, size_t length)
{
  if(_ztp_cbor_encode_type_and_value(cbor, 2, length) < 0) {
    return -1;                                      // Major type 2 (byte string)
  }
  return _ztp_cbor_write_bytes(cbor, data, length); // Write byte array to buffer
}

/**
 * @brief Encodes a string into CBOR format.
 *
 * @param cbor CBOR context.
 * @param str String to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_string(_ztp_cbor_t* cbor, const char* str)
{
  size_t len = strlen(str);
  if(_ztp_cbor_encode_type_and_value(cbor, 3, len) < 0) {
    return -1; // Major type 3 (text string)
  }
  return _ztp_cbor_write_bytes(cbor, (const uint8_t*) str, len);
}

/**
 * @brief Encodes a 64-bit unsigned integer into CBOR format.
 *
 * @param cbor CBOR context.
 * @param value Value to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_uint64(_ztp_cbor_t* cbor, uint64_t value)
{
  if(_ztp_cbor_encode_type_and_value(cbor, 2, 8) < 0) {
    return -1;
  }

  uint8_t bytes[] = { (uint8_t) (value >> 56), (uint8_t) (value >> 48), (uint8_t) (value >> 40),
                      (uint8_t) (value >> 32), (uint8_t) (value >> 24), (uint8_t) (value >> 16),
                      (uint8_t) (value >> 8),  (uint8_t) value };

  return _ztp_cbor_write_bytes(cbor, bytes, 8);
}

/**
 * @brief Encodes a signed integer into CBOR format.
 *
 * @param cbor @brief CBOR context.
 * @param value @brief Value to encode.
 *
 * @return @brief 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_int(_ztp_cbor_t* cbor, int value)
{
  if(value >= 0) {
    return _ztp_cbor_encode_type_and_value(cbor, 0,
                                           (size_t) value); // Major type 0
  } else {
    return _ztp_cbor_encode_type_and_value(cbor, 1,
                                           (size_t) (-value - 1)); // Major type 1
  }
}

/**
 * @brief Starts encoding an array into CBOR format.
 *
 * @param cbor @brief CBOR context.
 * @param size @brief Expected size of the array.
 *
 * @return @brief 0 on success, non-zero on failure.
 */
static int _ztp_cbor_start_array(_ztp_cbor_t* cbor, size_t size)
{
  return _ztp_cbor_encode_type_and_value(cbor, 4, size); // Major type 4 (array)
}

/**
 * @brief Starts encoding a map into CBOR format.
 *
 * @param cbor @brief CBOR context.
 * @param size @brief Expected size of the map.
 *
 * @return @brief 0 on success, non-zero on failure.
 */
static int _ztp_cbor_start_map(_ztp_cbor_t* cbor, size_t size)
{
  return _ztp_cbor_encode_type_and_value(cbor, 5, size); // Major type 5 (map)
}

/**
 * @brief Decodes a device ID from CBOR data.
 *
 * @param cbor_data @brief CBOR data to decode.
 * @param cbor_size @brief Size of CBOR data.
 * @param decoded_str @brief Buffer to store decoded device ID.
 * @param decoded_size @brief Size of decoded device ID buffer.
 *
 * @return @brief 0 on success, non-zero on failure.
 */
static int _ztp_cbor_decode_device_id(const uint8_t* cbor_data, size_t cbor_size, char* decoded_str,
                                      size_t decoded_size)
{
  if(cbor_size < 1 || !cbor_data) {
    return -1; // CBOR data is invalid
  }

  // Ensure initial byte is a text string (major type 3)
  uint8_t initial_byte = cbor_data[0];
  if((initial_byte >> 5) != 3) {
    return -2; // CBOR data is not a text string
  }

  // Extract the length of the string
  size_t length = 0;
  uint8_t additional_info = initial_byte & 0x1F;

  if(additional_info > 23) {
    return -3; // String length unsupported
  }

  length = additional_info;
  cbor_data++;
  cbor_size--;

  // Validate the length against the remaining CBOR data
  if(length > cbor_size) {
    return -4; // Incomplete CBOR data for string length
  }

  // Validate the length against the output buffer size
  if(length >= decoded_size) {
    return -5; // Decoded string buffer too small
  }

  // Copy the string into the output buffer and null-terminate it
  memcpy(decoded_str, cbor_data, length);
  decoded_str[length] = '\0';

  return 0;
}

/**
 * @brief Decodes a signed certificate from CBOR data.
 *
 * @param cbor_data @brief CBOR data to decode.
 * @param cbor_size @brief Size of CBOR data.
 * @param decoded_data @brief Buffer to store decoded certificate.
 * @param decoded_len @brief Pointer to store size of decoded certificate.
 *
 * @return @brief 0 on success, non-zero on failure.
 */
static int _ztp_cbor_decode_certificate(const uint8_t* cbor_data, size_t cbor_size,
                                        unsigned char* decoded_data, size_t* decoded_len)
{
  if(cbor_size < 1 || !cbor_data) {
    return -1; // CBOR data is invalid
  }

  // Ensure initial byte is a byte string (major type 2)
  uint8_t initial_byte = cbor_data[0];
  if((initial_byte >> 5) != 2) {
    return -2; // CBOR data is not a byte string
  }

  // Extract the length of the string
  size_t length = 0;
  size_t offset = 1;
  uint8_t additional_info = initial_byte & 0x1F;

  if(additional_info < 24) {
    length = additional_info;
  } else if(additional_info == 24) {
    length = cbor_data[offset++];
  } else if(additional_info == 25) {
    length = (cbor_data[offset] << 8) | cbor_data[offset + 1];
    offset += 2;
  } else if(additional_info == 26) {
    length = (cbor_data[offset] << 24) | (cbor_data[offset + 1] << 16) |
             (cbor_data[offset + 2] << 8) | cbor_data[offset + 3];
    offset += 4;
  } else {
    return -3; // Length not supported
  }

  if(offset + length > cbor_size) {
    return -4; // Length exceeds buffer size
  }

  memcpy(decoded_data, cbor_data + offset, length);
  *decoded_len = length;

  return 0;
}

/**
 * @brief Add a device ID parameter of blob type.
 *
 * This function adds a device ID parameter of blob type to the ZTP device ID parameters list
 * (e.g., MAC address).
 *
 * @param type The type of the device ID parameter.
 * @param blob The blob value of the device ID parameter.
 *
 * @return true if the parameter was added successfully, false otherwise.
 */
static bool _ztp_add_device_id_parameter_blob(bluecherry_ztp_device_id_type type,
                                              const unsigned char* blob)
{
  if(blob == NULL ||
     _bluecherry_opdata.ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC:
    _bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count].type =
        BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC;
    memcpy(_bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count]
               .value.mac,
           blob, BLUECHERRY_ZTP_MAC_LEN);
    _bluecherry_opdata.ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

/**
 * @brief Request the device ID from the BlueCherry ZTP server.
 *
 * This function constructs a CBOR-encoded request containing the device type ID and
 * device ID parameters, sends it to the BlueCherry ZTP server via CoAP,
 * and decodes the received device ID.
 *
 * @return true if the device ID was successfully requested and decoded, false otherwise.
 */
static bool _ztp_request_device_id()
{
  int ret;
  uint8_t cborBuf[256];
  _ztp_cbor_t cbor;

  if(_ztp_cbor_init(&cbor, cborBuf, sizeof(cborBuf)) < 0) {
    BC_LOGE("Failed to init CBOR buffer");
    return false;
  };

  // Start the CBOR array
  if(_ztp_cbor_start_array(&cbor, 2) < 0) {
    BC_LOGE("Failed to start CBOR array");
    return false;
  }

  // Encode type ID value
  if(_ztp_cbor_encode_string(&cbor, bcTypeId) < 0) {
    BC_LOGE("Failed to encode typeId value");
    return false;
  }

  // Start the CBOR map (key-value pairs)
  if(_ztp_cbor_start_map(&cbor, _bluecherry_opdata.ztp_devIdParams.count) < 0) {
    BC_LOGE("Failed to start CBOR map");
    return false;
  }

  for(int i = 0; i < _bluecherry_opdata.ztp_devIdParams.count; i++) {

    int type = (int) _bluecherry_opdata.ztp_devIdParams.param[i].type;
    if(_ztp_cbor_encode_int(&cbor, type) < 0) {
      BC_LOGE("Failed to encode param type (%u)", type);
      return false;
    }

    switch(_bluecherry_opdata.ztp_devIdParams.param[i].type) {
    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI: {
      // Encode IMEI number (15 characters)
      uint64_t imei = strtoull(_bluecherry_opdata.ztp_devIdParams.param[i].value.imei, NULL, 10);
      if(_ztp_cbor_encode_uint64(&cbor, imei) < 0) {
        BC_LOGE("Failed to encode IMEI number");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC: {
      // Encode MAC address (6 bytes)
      if(_ztp_cbor_encode_bytes(
             &cbor, (uint8_t*) _bluecherry_opdata.ztp_devIdParams.param[i].value.mac, 6) < 0) {
        BC_LOGE("Failed to encode MAC address");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE: {
      // Encode OOB challenge (64 bit unsigned int)
      uint64_t oobChallenge = _bluecherry_opdata.ztp_devIdParams.param[0].value.oobChallenge;
      if(_ztp_cbor_encode_uint64(&cbor, oobChallenge) < 0) {
        BC_LOGE("Failed to encode OOB challenge");
        return false;
      }
    } break;

    default:
      break;
    }
  }

  uint8_t in_buf[16];
  uint16_t in_len = 0;
  if(!_bluecherry_ztp_coap_rxtx_devid(cborBuf, _ztp_cbor_size(&cbor), in_buf, &in_len)) {
    BC_LOGE("Failed to sync with ZTP COAP server");
    return false;
  }

  ret = _ztp_cbor_decode_device_id(in_buf, in_len, ztp_bcDevId, sizeof(ztp_bcDevId));
  if(ret < 0) {
    BC_LOGE("Failed to decode device id: %d", ret);
    return false;
  }

  return true;
}

/**
 * @brief Generate a P-256 key pair and CSR for ZTP.
 *
 * Generates an EC P-256 key pair, serialises the private key to PEM in
 * ztp_pkeyBuf, builds a CSR with subject C=BE,CN=<typeId>.<devId>, signs it,
 * and stores the DER-encoded CSR in _bluecherry_opdata.ztp_csr.
 *
 * @return true if the key pair and CSR were generated successfully, false otherwise.
 */
static bool _ztp_generate_key_and_csr(void)
{
  if(bcTypeId == NULL || strlen(bcTypeId) != BLUECHERRY_ZTP_ID_LEN ||
     strlen(ztp_bcDevId) != BLUECHERRY_ZTP_ID_LEN) {
    return false;
  }

  _bluecherry_opdata.devkey = EVP_EC_gen("P-256");
  if(!_bluecherry_opdata.devkey) {
    BC_LOGE("Failed to generate EC P-256 key pair");
    return _ztp_finish_csr_gen(false);
  }

  {
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio) {
      return _ztp_finish_csr_gen(false);
    }

    int ok = PEM_write_bio_PrivateKey(bio, _bluecherry_opdata.devkey, NULL, NULL, 0, NULL, NULL);
    BUF_MEM* bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);

    if(!ok || !bptr || bptr->length >= BLUECHERRY_ZTP_PKEY_BUF_SIZE) {
      BIO_free(bio);
      return _ztp_finish_csr_gen(false);
    }
    memcpy(ztp_pkeyBuf, bptr->data, bptr->length);
    ztp_pkeyBuf[bptr->length] = '\0';
    BIO_free(bio);
  }

  _bluecherry_opdata.ztp_csr_req = X509_REQ_new();
  if(!_bluecherry_opdata.ztp_csr_req) {
    return _ztp_finish_csr_gen(false);
  }

  X509_NAME* name = X509_REQ_get_subject_name(_bluecherry_opdata.ztp_csr_req);
  snprintf(ztp_subjBuf, BLUECHERRY_ZTP_SUBJ_BUF_SIZE, "%s.%s", bcTypeId, ztp_bcDevId);
  if(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"BE", -1, -1, 0) !=
         1 ||
     X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)ztp_subjBuf, -1,
                                -1, 0) != 1) {
    return _ztp_finish_csr_gen(false);
  }

  if(X509_REQ_set_pubkey(_bluecherry_opdata.ztp_csr_req, _bluecherry_opdata.devkey) != 1) {
    return _ztp_finish_csr_gen(false);
  }

  if(X509_REQ_sign(_bluecherry_opdata.ztp_csr_req, _bluecherry_opdata.devkey, EVP_sha256()) <= 0) {
    BC_LOGE("Failed to sign CSR");
    return _ztp_finish_csr_gen(false);
  }

  {
    unsigned char* der = NULL;
    int der_len = i2d_X509_REQ(_bluecherry_opdata.ztp_csr_req, &der);
    if(der_len <= 0 || der_len > (int)BLUECHERRY_ZTP_CERT_BUF_SIZE) {
      if(der) {
        OPENSSL_free(der);
      }
      BC_LOGE("Failed to encode CSR to DER");
      return _ztp_finish_csr_gen(false);
    }
    _bluecherry_opdata.ztp_csr.length = (size_t)der_len;
    memcpy(_bluecherry_opdata.ztp_csr.buffer, der, (size_t)der_len);
    OPENSSL_free(der);
  }

  return _ztp_finish_csr_gen(true);
}

/**
 * @brief Request a signed certificate from the BlueCherry ZTP server.
 *
 * Sends the previously generated CSR to the ZTP server via CoAP, receives the
 * signed certificate in DER format, decodes it, and converts it to PEM format
 * stored in ztp_certBuf.
 *
 * @return true if the signed certificate was successfully requested and stored, false otherwise.
 */
static bool _ztp_request_signed_certificate(void)
{
  uint8_t cborBuf[BLUECHERRY_ZTP_CERT_BUF_SIZE];
  uint8_t coapData[BLUECHERRY_ZTP_CERT_BUF_SIZE];
  _ztp_cbor_t cbor;

  _ztp_cbor_init(&cbor, cborBuf, BLUECHERRY_ZTP_CERT_BUF_SIZE);

  if(_ztp_cbor_encode_bytes(&cbor, _bluecherry_opdata.ztp_csr.buffer,
                            _bluecherry_opdata.ztp_csr.length) < 0) {
    BC_LOGE("Failed to encode CSR");
    return false;
  }

  uint16_t in_len = 0;
  if(!_bluecherry_ztp_coap_rxtx_sign(cborBuf, _ztp_cbor_size(&cbor), coapData, &in_len)) {
    BC_LOGE("Failed to receive response from ZTP COAP server");
    return false;
  }

  size_t decodedSize = 0;
  int ret = _ztp_cbor_decode_certificate(coapData, in_len, cborBuf, &decodedSize);
  if(ret < 0) {
    BC_LOGE("Failed to decode certificate: %d", ret);
    return false;
  }

  const unsigned char* p = cborBuf;
  X509* cert = d2i_X509(NULL, &p, (long)decodedSize);
  if(!cert) {
    BC_LOGE("Failed to parse DER certificate");
    return false;
  }

  BIO* bio = BIO_new(BIO_s_mem());
  if(!bio || PEM_write_bio_X509(bio, cert) != 1) {
    BIO_free(bio);
    X509_free(cert);
    BC_LOGE("Failed to convert certificate to PEM");
    return false;
  }

  BUF_MEM* bptr = NULL;
  BIO_get_mem_ptr(bio, &bptr);
  if(!bptr || bptr->length >= BLUECHERRY_ZTP_CERT_BUF_SIZE) {
    BIO_free(bio);
    X509_free(cert);
    BC_LOGE("PEM certificate too large for buffer");
    return false;
  }

  memcpy(ztp_certBuf, bptr->data, bptr->length);
  ztp_certBuf[bptr->length] = '\0';

  BIO_free(bio);
  X509_free(cert);
  return true;
}

#pragma endregion
#pragma region PUBLIC

#define BLUECHERRY_AUTO_SYNC_SEC 30

static bool _get_mac(uint8_t mac[6])
{
  struct ifaddrs* ifap;
  if(getifaddrs(&ifap) != 0) {
    return false;
  }
  bool found = false;
  for(struct ifaddrs* ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if(ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET &&
       !(ifa->ifa_flags & IFF_LOOPBACK)) {
      memcpy(mac, ((struct sockaddr_ll*)ifa->ifa_addr)->sll_addr, 6);
      found = true;
      break;
    }
  }
  freeifaddrs(ifap);
  return found;
}

bool bluecherry_init(const char* device_cert, const char* device_key,
                     bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                     bool auto_sync)
{
  if(_bluecherry_opdata.state != BLUECHERRY_STATE_UNINITIALIZED) {
    return true;
  }

  _bluecherry_opdata.msg_handler = msg_handler;
  _bluecherry_opdata.msg_handler_args = msg_handler_args;

  _bluecherry_opdata.out_queue.head = NULL;
  _bluecherry_opdata.out_queue.tail = NULL;
  _bluecherry_opdata.out_queue.count = 0;
  if(pthread_mutex_init(&_bluecherry_opdata.out_queue.lock, NULL) != 0 ||
     pthread_cond_init(&_bluecherry_opdata.out_queue.cond, NULL) != 0) {
    BC_LOGE("Unable to create outgoing message queue");
    return false;
  }

  if(!_bluecherry_setup_ssl()) {
    BC_LOGE("Could not setup OpenSSL context");
    goto fail;
  }
  if(!_bluecherry_configure_credentials(BLUECHERRY_CA, device_cert, device_key)) {
    BC_LOGE("Could not configure credentials");
    goto fail;
  }

  if(auto_sync) {
    pthread_t thread;
    if(pthread_create(&thread, NULL, _bluecherry_sync_task, NULL) != 0) {
      BC_LOGE("Could not create auto-sync thread");
      goto fail;
    }
    pthread_detach(thread);
  }

  _bluecherry_opdata.state = BLUECHERRY_STATE_AWAIT_CONNECTION;
  return true;

fail:
  _bluecherry_cleanup_network();
  _bluecherry_cleanup_ssl();
  return false;
}

bool bluecherry_init_ztp(bluecherry_ztp_bio_handler_t ztp_bio_handler,
                         void* ztp_bio_handler_args, const char* bc_device_type,
                         bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                         bool auto_sync)
{
  (void) ztp_bio_handler_args;

  if(_bluecherry_opdata.state != BLUECHERRY_STATE_UNINITIALIZED) {
    return true;
  }

  bcTypeId = bc_device_type;

  const char* device_cert = ztp_bio_handler(true, false, NULL);
  const char* device_key = ztp_bio_handler(true, true, NULL);

  if(device_cert == NULL || device_key == NULL) {
    BC_LOGW("Device is not provisioned for BlueCherry communication, starting ZTP...");

    uint8_t mac[8] = { 0 };
    if(!_get_mac(mac)) {
      BC_LOGE("(ZTP) Could not read MAC address");
      return false;
    }

    if(!_bluecherry_setup_ssl()) {
      BC_LOGE("(ZTP) Could not setup OpenSSL context");
      goto fail;
    }
    if(!_bluecherry_configure_credentials(BLUECHERRY_CA, NULL, NULL)) {
      BC_LOGE("(ZTP) Could not configure credentials");
      goto fail;
    }
    if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_ZTP_PORT)) {
      BC_LOGE("(ZTP) Could not connect to BlueCherry server");
      goto fail;
    }

    BC_LOGI("Connected to ZTP server");

    if(!_ztp_add_device_id_parameter_blob(BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC, mac)) {
      BC_LOGE("(ZTP) Could not add MAC address as ZTP device ID parameter");
      goto fail;
    }
    if(!_ztp_request_device_id()) {
      BC_LOGE("(ZTP) Could not request device ID");
      goto fail;
    }
    if(!_ztp_generate_key_and_csr()) {
      BC_LOGE("(ZTP) Could not generate private key");
      goto fail;
    }

    nanosleep(&(struct timespec){ .tv_sec = 1, .tv_nsec = 0 }, NULL);

    if(!_ztp_request_signed_certificate()) {
      BC_LOGE("(ZTP) Could not request signed certificate");
      goto fail;
    }

    ztp_bio_handler(false, false, (void*)ztp_certBuf);
    ztp_bio_handler(false, true, (void*)ztp_pkeyBuf);

    device_cert = ztp_certBuf;
    device_key = ztp_pkeyBuf;
  }

  return bluecherry_init(device_cert, device_key, msg_handler, msg_handler_args, auto_sync);

fail:
  _bluecherry_cleanup_network();
  _bluecherry_cleanup_ssl();
  _bluecherry_opdata.ztp_devIdParams.count = 0;
  return false;
}

bool bluecherry_sync(bool blocking)
{
  static int64_t last_retry_time_us = 0;
  static uint32_t retry_interval_ms = 100;

  if(_bluecherry_opdata.state == BLUECHERRY_STATE_AWAIT_CONNECTION) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_us = (int64_t)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
    int64_t elapsed_ms = (now_us - last_retry_time_us) / 1000LL;
    if(elapsed_ms >= retry_interval_ms) {
      last_retry_time_us = now_us;
      if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_PORT)) {
        BC_LOGE("Could not connect to BlueCherry server");
        retry_interval_ms = (retry_interval_ms < 30000) ? retry_interval_ms * 2 : 30000;
        return false;
      }
      _bluecherry_opdata.cur_message_id = 0;
      _bluecherry_opdata.last_acked_message_id = 0;
      _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_IDLE;
      retry_interval_ms = 100;
    } else {
      return false;
    }
  }

  if(_bluecherry_opdata.state == BLUECHERRY_STATE_UNINITIALIZED ||
     _bluecherry_opdata.state == BLUECHERRY_STATE_CONNECTED_AWAITING_RESPONSE) {
    BC_LOGE("Cannot sync in the current state");
    return false;
  }

  const int64_t now = time(NULL);
  _bluecherry_msg_t out_msg;
  bool has_msg = false;

  pthread_mutex_lock(&_bluecherry_opdata.out_queue.lock);
  if(blocking && _bluecherry_opdata.out_queue.count == 0) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 200000000LL;
    if(deadline.tv_nsec >= 1000000000LL) {
      deadline.tv_sec++;
      deadline.tv_nsec -= 1000000000LL;
    }
    pthread_cond_timedwait(&_bluecherry_opdata.out_queue.cond,
                           &_bluecherry_opdata.out_queue.lock, &deadline);
  }
  if(_bluecherry_opdata.out_queue.head != NULL) {
    out_msg = _bluecherry_opdata.out_queue.head->msg;
    has_msg = true;
  }
  pthread_mutex_unlock(&_bluecherry_opdata.out_queue.lock);

  if(has_msg) {
    if(_bluecherry_coap_rxtx(&out_msg)) {
      pthread_mutex_lock(&_bluecherry_opdata.out_queue.lock);
      _bluecherry_msg_queue_entry_t* node = _bluecherry_opdata.out_queue.head;
      if(node != NULL) {
        _bluecherry_opdata.out_queue.head = node->next;
        if(_bluecherry_opdata.out_queue.head == NULL) {
          _bluecherry_opdata.out_queue.tail = NULL;
        }
        _bluecherry_opdata.out_queue.count--;
        free(node->msg.data);
        free(node);
      }
      pthread_mutex_unlock(&_bluecherry_opdata.out_queue.lock);
    } else {
      BC_LOGE("Could not sync payload with cloud");
      _bluecherry_opdata.state = BLUECHERRY_STATE_AWAIT_CONNECTION;
      return false;
    }
  } else {
    if(!blocking || ((now - _bluecherry_opdata.last_tx_time) >= BLUECHERRY_AUTO_SYNC_SEC)) {
      if(!_bluecherry_coap_rxtx(NULL)) {
        BC_LOGE("Could not sync with cloud");
        _bluecherry_opdata.state = BLUECHERRY_STATE_AWAIT_CONNECTION;
        return false;
      }
    } else {
      return true;
    }
  }

  if(_bluecherry_opdata.in_buf_len < BLUECHERRY_COAP_HEADER_SIZE) {
    BC_LOGE("Received CoAP packet too small: %u", (unsigned)_bluecherry_opdata.in_buf_len);
    return false;
  }

  uint16_t offset = 0;

  uint8_t header = _bluecherry_opdata.in_buf[offset++];
  uint8_t version = (header >> 6) & 0x03;
  if(version != 1) {
    BC_LOGE("Received CoAP packet with version %d, expected 1", version);
    return false;
  }

  uint8_t type = (header >> 4) & 0x03;
  uint8_t token_len = header & 0x0F;

  size_t min_header_len = (size_t)(1 + token_len + 1 + 2 + 1);
  if(_bluecherry_opdata.in_buf_len < min_header_len) {
    BC_LOGE("Received CoAP packet with invalid length %u for token length %u",
            (unsigned)_bluecherry_opdata.in_buf_len, token_len);
    return false;
  }

  offset += token_len;
  uint8_t code = _bluecherry_opdata.in_buf[offset++];
  uint16_t msg_id = _bluecherry_opdata.in_buf[offset++];
  msg_id <<= 8;
  msg_id |= _bluecherry_opdata.in_buf[offset++];
  if(_bluecherry_opdata.in_buf[offset++] != 0xFF) {
    BC_LOGE("Received CoAP packet without payload marker");
    return false;
  }

  if(type == BLUECHERRY_COAP_TYPE_ACK) {
    if(msg_id != _bluecherry_opdata.cur_message_id) {
      BC_LOGE("Received ACK for %" PRIu16 " instead of %" PRIu16, msg_id,
              _bluecherry_opdata.cur_message_id);
      return false;
    }
    _bluecherry_opdata.last_acked_message_id = msg_id;
  }

  bool want_resync = false;

  switch(code) {
  case BLUECHERRY_COAP_RSP_VALID:
    want_resync = false;
    break;
  case BLUECHERRY_COAP_RSP_CONTINUE:
    want_resync = true;
    break;
  default:
    BC_LOGE("Received invalid CoAP code %02X", code);
    return false;
  }

  while(offset < _bluecherry_opdata.in_buf_len) {
    uint8_t topic = _bluecherry_opdata.in_buf[offset++];
    uint8_t data_len = _bluecherry_opdata.in_buf[offset++];

    if(offset + data_len > _bluecherry_opdata.in_buf_len) {
      BC_LOGE("Received malformed payload length");
      return false;
    }

    if(topic == 0x00) {
      want_resync = true;
    } else if(_bluecherry_opdata.msg_handler != NULL) {
      _bluecherry_opdata.msg_handler(topic, data_len, _bluecherry_opdata.in_buf + offset,
                                     _bluecherry_opdata.msg_handler_args);
    }

    offset += data_len;
  }

  if(want_resync) {
    BC_LOGD("Synchronized messages with cloud, more pending");
    _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_PENDING_MESSAGES;
    return true;
  }

  BC_LOGD("Synchronized messages with cloud");
  _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_IDLE;
  return true;
}

bool bluecherry_publish(uint8_t topic, uint16_t len, const uint8_t* data)
{
  BC_LOGD("Scheduling publish on topic 0x%02X with %dB of data", topic, len);

  if(len > (BLUECHERRY_MAX_MESSAGE_LEN - (BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE))) {
    BC_LOGE("The message exceeds the maximum allowed size");
    return false;
  }

  size_t total_len = BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE + len;

  uint8_t* data_cpy = malloc(total_len);
  if(data_cpy == NULL) {
    BC_LOGE("Could not allocate publish buffer: %s", strerror(errno));
    return false;
  }

  (data_cpy + BLUECHERRY_COAP_HEADER_SIZE)[0] = topic;
  (data_cpy + BLUECHERRY_COAP_HEADER_SIZE)[1] = len & 0xFF;
  memcpy(data_cpy + BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE, data, len);

  _bluecherry_msg_queue_entry_t* node = malloc(sizeof(_bluecherry_msg_queue_entry_t));
  if(node == NULL) {
    BC_LOGE("Could not allocate queue node");
    free(data_cpy);
    return false;
  }
  node->msg.len = total_len;
  node->msg.data = data_cpy;
  node->next = NULL;

  pthread_mutex_lock(&_bluecherry_opdata.out_queue.lock);
  if(_bluecherry_opdata.out_queue.tail != NULL) {
    _bluecherry_opdata.out_queue.tail->next = node;
  } else {
    _bluecherry_opdata.out_queue.head = node;
  }
  _bluecherry_opdata.out_queue.tail = node;
  _bluecherry_opdata.out_queue.count++;
  pthread_cond_signal(&_bluecherry_opdata.out_queue.cond);
  pthread_mutex_unlock(&_bluecherry_opdata.out_queue.lock);

  return true;
}

#pragma endregion
