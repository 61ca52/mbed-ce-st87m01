/*
 * Copyright (c) 2026 Jan Gerrit Gers
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ST87M01_TLSPROVISIONING_H_
#define ST87M01_TLSPROVISIONING_H_

#include "mbed.h"
#include "ATHandler.h"

#if defined(MBEDTLS_PEM_PARSE_C) && !defined(MBEDTLS_BASE64_C)
#error "MBEDTLS_PEM_PARSE_C defined, but not all prerequisites"
#endif

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

/** TLS key and certificate provisioning for ST87M01.
 *
 *  Wraps the modem AT sequences (TLSKEYADD, TLSCERTADD, ...). */
class ST87M01_TlsProvisioning {
public:
    /** AT#TLSKEYADD <type>. Low nibble selects algorithm; KEY_HEX_FORMAT
     *  (0x80) flags ASCII-hex output for the generated public key. */
    enum KeyType {
        KEY_ASYMMETRIC_PRIVATE = 0x00,
        KEY_SYMMETRIC          = 0x01,
        KEY_PUBLIC             = 0x02,
        KEY_ECC_BRAINPOOL      = 0x04,
        KEY_HEX_FORMAT         = 0x80
    };

    /** AT#TLSKEYADD storage backends. */
    enum KeyStorage {
        STORAGE_OTP      = 1,
        STORAGE_FLASH    = 2,
        STORAGE_RET_RAM  = 3,
        STORAGE_RAM      = 4
    };

    /** AT#TLSCERTADD cert types. */
    enum CertType {
        CERT_DEVICE   = 0,
        CERT_CA_ROOT  = 1,
        CERT_PSK_ID   = 2
    };

    explicit ST87M01_TlsProvisioning(ATHandler &at);
    ~ST87M01_TlsProvisioning() = default;

    /** Generate a fresh ECC private key on the modem.
     *  @param profile_id   Profile id (0..15).
     *  @param key_size     Bytes (32=P-256, 48=P-384).
     *  @param storage      FLASH persists across reboot.
     *  @param pub_key_out  Optional buffer for the public key; null discards it.
     *  @param pub_key_len  In: capacity. Out: bytes written.
     *  @return NSAPI_ERROR_OK on success. */
    nsapi_error_t generate_key(int profile_id, int key_size = 32,
                               KeyStorage storage = STORAGE_FLASH,
                               uint8_t *pub_key_out = nullptr,
                               size_t *pub_key_len = nullptr);

    /** Store a private key. Accepts DER, hex-ASCII, or PEM (when built with
     *  MBED_CONF_ST87M01_TLS_SUPPORT_PEM); converted to DER before upload. */
    nsapi_error_t add_key(int profile_id, const uint8_t *key_data, size_t key_len,
                          KeyStorage storage = STORAGE_FLASH);

    nsapi_error_t delete_key(int profile_id);
    void list_keys(int profile_id = -1);

    /** Store a CA root certificate. Accepts DER, hex-ASCII, or PEM. */
    nsapi_error_t add_ca_certificate(int profile_id, const uint8_t *cert_data, size_t cert_len,
                                     bool volatile_storage = false);

    /** Store a device certificate. Accepts DER, hex-ASCII, or PEM. */
    nsapi_error_t add_device_certificate(int profile_id, const uint8_t *cert_data, size_t cert_len,
                                         bool volatile_storage = false);

    nsapi_error_t delete_certificate(int profile_id, CertType type);
    nsapi_error_t delete_all_certificates(int profile_id);
    void list_certificates(int profile_id = -1);

    /** Flush provisioned credentials to NVM. Triggers a modem reboot. */
    nsapi_error_t save_to_nvm();

    /** Report whether a profile holds a key and/or certificate.
     *  @param profile_id Profile id (0..15).
     *  @param has_key    Optional out: true if any key present.
     *  @param has_cert   Optional out: true if any cert present. */
    nsapi_error_t check_profile(int profile_id, bool *has_key, bool *has_cert);

    bool is_profile_ready(int profile_id);
    bool has_certificate(int profile_id, CertType type);

private:
    nsapi_error_t add_certificate_impl(int profile_id, CertType type,
                                       const uint8_t *cert_data, size_t cert_len,
                                       bool volatile_storage);

    size_t convert_hex_to_bin(const char *hex, size_t hex_len, uint8_t *out, size_t out_max);
    bool is_hex_string(const uint8_t *data, size_t len);

    ATHandler &_at;
};

/** @}*/

} // namespace mbed

#endif // ST87M01_TLSPROVISIONING_H_
