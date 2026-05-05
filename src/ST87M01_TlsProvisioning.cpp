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

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "rtos/ThisThread.h"

#include "mbedtls/base64.h"
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
#include "mbedtls/pem.h"
#endif

#include "CellularLog.h"

#include "ST87M01_TlsProvisioning.h"

using namespace mbed;
using namespace std::chrono;
using namespace std::chrono_literals;

namespace {

    // AT#TLSKEYADD / AT#TLSCERTADD reject payloads larger than 4 KiB.
    constexpr size_t OP_MAX_PEM_SIZE = 4096;

#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
    bool looks_like_pem(const uint8_t *data, size_t len)
    {
        if (!data || len < 16)
        {
            return false;
        }
        const char marker[] = "-----BEGIN";
        const size_t marker_len = sizeof(marker) - 1;
        for (size_t i = 0; i + marker_len <= len; i++)
        {
            if (memcmp(data + i, marker, marker_len) == 0)
            {
                return true;
            }
        }
        return false;
    }
#endif

    bool read_der_len(const uint8_t *&p, const uint8_t *end, size_t *out)
    {
        if (p >= end)
        {
            return false;
        }

        uint8_t b = *p++;
        if ((b & 0x80) == 0)
        {
            *out = b;
            return true;
        }

        size_t nbytes = b & 0x7F;
        if (nbytes == 0 || nbytes > sizeof(size_t) || (p + nbytes) > end)
        {
            return false;
        }

        *out = 0;
        for (size_t i = 0; i < nbytes; i++)
        {
            *out = (*out << 8) | *p++;
        }
        return true;
    }

    // ST87M01 caps RSA at 2048-bit moduli; check before upload.
    bool parse_rsa_modulus_bits(const uint8_t *der, size_t der_len, size_t *mod_bits)
    {
        static const uint8_t oid_rsa[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
        const uint8_t *p = der;
        const uint8_t *end = der + der_len;

        while (p && p < end)
        {
            const void *found = memchr(p, oid_rsa[0], end - p);
            if (!found)
            {
                return false;
            }

            p = static_cast<const uint8_t *>(found);
            if (static_cast<size_t>(end - p) < sizeof(oid_rsa))
            {
                return false;
            }

            if (memcmp(p, oid_rsa, sizeof(oid_rsa)) != 0)
            {
                p++;
                continue;
            }

            p += sizeof(oid_rsa);
            if ((end - p) >= 2 && p[0] == 0x05 && p[1] == 0x00)
            {
                p += 2;
            }

            while (p < end && *p != 0x03)
            {
                p++;
            }
            if (p >= end || *p != 0x03)
            {
                return false;
            }
            p++;

            size_t bitlen = 0;
            if (!read_der_len(p, end, &bitlen))
            {
                return false;
            }

            if (p >= end)
            {
                return false;
            }
            p++;

            if (p >= end || *p != 0x30)
            {
                return false;
            }
            p++;

            size_t seq_len = 0;
            if (!read_der_len(p, end, &seq_len))
            {
                return false;
            }

            if (p >= end || *p != 0x02)
            {
                return false;
            }
            p++;

            size_t mlen = 0;
            if (!read_der_len(p, end, &mlen))
            {
                return false;
            }

            if (mlen > 0 && *p == 0x00)
            {
                mlen--;
            }

            *mod_bits = mlen * 8;
            return true;
        }
        return false;
    }

} // namespace

namespace mbed
{

    ST87M01_TlsProvisioning::ST87M01_TlsProvisioning(ATHandler &at)
        : _at(at)
    {
    }

    size_t ST87M01_TlsProvisioning::convert_hex_to_bin(const char *hex, size_t hex_len, uint8_t *out, size_t out_max)
    {
        if (!hex || !out || out_max == 0)
        {
            return 0;
        }

        size_t valid_count = 0;
        for (size_t i = 0; i < hex_len; i++)
        {
            char c = hex[i];
            if (c == '\r' || c == '\n' || c == '.' || c == ' ')
            {
                continue;
            }
            if (!isxdigit(static_cast<unsigned char>(c)))
            {
                return 0;
            }
            valid_count++;
        }

        if (valid_count % 2 != 0 || valid_count / 2 > out_max)
        {
            return 0;
        }

        size_t out_len = 0;
        bool high_nibble = true;
        uint8_t byte_val = 0;

        for (size_t i = 0; i < hex_len; i++)
        {
            char c = hex[i];
            if (c == '\r' || c == '\n' || c == '.' || c == ' ')
            {
                continue;
            }

            uint8_t val = 0;
            if (c >= '0' && c <= '9')
            {
                val = static_cast<uint8_t>(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                val = static_cast<uint8_t>(c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F')
            {
                val = static_cast<uint8_t>(c - 'A' + 10);
            }

            if (high_nibble)
            {
                byte_val = static_cast<uint8_t>(val << 4);
                high_nibble = false;
            }
            else
            {
                byte_val |= val;
                out[out_len++] = byte_val;
                high_nibble = true;
            }
        }

        return out_len;
    }

    bool ST87M01_TlsProvisioning::is_hex_string(const uint8_t *data, size_t len)
    {
        if (!data || len < 2)
        {
            return false;
        }

        // DER starts with 0x30 (SEQUENCE tag)
        if (data[0] == 0x30)
        {
            return false;
        }

        // PEM starts with "-----"
        if (len >= 5 && memcmp(data, "-----", 5) == 0)
        {
            return false;
        }

        size_t hex_char_count = 0;
        for (size_t i = 0; i < len; i++)
        {
            char c = static_cast<char>(data[i]);
            if (c == '\r' || c == '\n' || c == '.' || c == ' ')
            {
                continue;
            }
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            {
                hex_char_count++;
            }
            else
            {
                return false;
            }
        }

        return (hex_char_count >= 2) && (hex_char_count % 2 == 0);
    }

    nsapi_error_t ST87M01_TlsProvisioning::generate_key(int profile_id, int key_size,
                                                        KeyStorage storage,
                                                        uint8_t *pub_key_out,
                                                        size_t *pub_key_len)
    {
        if (profile_id < 0 || profile_id > 15)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        if (storage == STORAGE_RAM || storage == STORAGE_RET_RAM)
        {
            tr_warn("ST87M01 TLS: key gen requires FLASH storage");
            storage = STORAGE_FLASH;
        }

        // Drop any existing key; it may be in an invalid state.
        delete_key(profile_id);

        int type = KEY_ASYMMETRIC_PRIVATE;
        if (pub_key_out)
        {
            type |= KEY_HEX_FORMAT;
        }

        // data_flag bit0=1 generate internally; bit1=1 return public key.
        int data_flag = 0x01;
        if (pub_key_out && pub_key_len && *pub_key_len > 0)
        {
            data_flag |= 0x02;
        }

        tr_info("ST87M01 TLS: gen key profile=%d type=0x%02x storage=%d size=%d",
                profile_id, type, storage, key_size);

        _at.lock();
        _at.cmd_start("AT#TLSKEYADD=");
        _at.write_int(profile_id);
        _at.write_int(type);
        _at.write_int(storage);
        _at.write_int(key_size);
        _at.write_int(data_flag);
        _at.cmd_stop();

        if (pub_key_out && pub_key_len && *pub_key_len > 0)
        {
            _at.resp_start();
            char hex_buf[512] = {0};
            _at.read_string(hex_buf, sizeof(hex_buf) - 1);
            _at.resp_stop();

            size_t bin_len = convert_hex_to_bin(hex_buf, strlen(hex_buf), pub_key_out, *pub_key_len);
            *pub_key_len = bin_len;
        }
        else
        {
            _at.resp_start();
            _at.resp_stop();
        }

        nsapi_error_t err = _at.unlock_return_error();

        if (err == NSAPI_ERROR_OK)
        {
            tr_info("ST87M01 TLS: key gen ok profile=%d", profile_id);
        }
        else
        {
            device_err_t dev_err = _at.get_last_device_error();
            tr_error("ST87M01 TLS: key gen failed err=%d CME=%d", err, dev_err.errCode);
        }

        return err;
    }

    nsapi_error_t ST87M01_TlsProvisioning::add_key(int profile_id, const uint8_t *key_data,
                                                   size_t key_len, KeyStorage storage)
    {
        if (profile_id < 0 || profile_id > 15 || !key_data || key_len == 0)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        if (key_len > OP_MAX_PEM_SIZE)
        {
            tr_error("ST87M01 TLS: key %u too large", static_cast<unsigned>(key_len));
            return NSAPI_ERROR_PARAMETER;
        }

        const uint8_t *final_data = key_data;
        size_t final_len = key_len;

        uint8_t *converted_buf = nullptr;
        mbedtls_pem_context pem_ctx;
        bool pem_ctx_initialized = false;

        if (is_hex_string(key_data, key_len))
        {
            tr_debug("ST87M01 TLS: hex key -> bin");
            size_t max_bin_len = key_len / 2 + 1;
            converted_buf = static_cast<uint8_t *>(malloc(max_bin_len));
            if (!converted_buf)
            {
                return NSAPI_ERROR_NO_MEMORY;
            }

            size_t bin_len = convert_hex_to_bin(reinterpret_cast<const char *>(key_data),
                                                key_len, converted_buf, max_bin_len);
            if (bin_len == 0)
            {
                free(converted_buf);
                return NSAPI_ERROR_PARAMETER;
            }

            final_data = converted_buf;
            final_len = bin_len;
        }
        else if (looks_like_pem(key_data, key_len))
        {
            tr_debug("ST87M01 TLS: PEM key -> DER");

            uint8_t *pem_terminated = static_cast<uint8_t *>(malloc(key_len + 1));
            if (!pem_terminated)
            {
                return NSAPI_ERROR_NO_MEMORY;
            }
            memcpy(pem_terminated, key_data, key_len);
            pem_terminated[key_len] = '\0';

            mbedtls_pem_init(&pem_ctx);
            pem_ctx_initialized = true;

            static const struct
            {
                const char *header;
                const char *footer;
            } key_formats[] = {
                {"-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"},
                {"-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"},
                {"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"},
            };

            int ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
            size_t use_len = 0;

            for (size_t i = 0; i < sizeof(key_formats) / sizeof(key_formats[0]); i++)
            {
                ret = mbedtls_pem_read_buffer(&pem_ctx,
                                              key_formats[i].header,
                                              key_formats[i].footer,
                                              pem_terminated,
                                              nullptr, 0,
                                              &use_len);
                if (ret == 0)
                {
                    break;
                }
            }

            free(pem_terminated);

            if (ret != 0)
            {
                mbedtls_pem_free(&pem_ctx);
                pem_ctx_initialized = false;
            }
            else
            {
                final_data = pem_ctx.buf;
                final_len = pem_ctx.buflen;
            }
        }

        // Drop any existing key first.
        delete_key(profile_id);

        tr_info("ST87M01 TLS: add key profile=%d size=%u", profile_id, static_cast<unsigned>(final_len));

        _at.lock();
        _at.cmd_start("AT#TLSKEYADD=");
        _at.write_int(profile_id);
        _at.write_int(KEY_ASYMMETRIC_PRIVATE);
        _at.write_int(storage);
        _at.write_int(static_cast<int>(final_len));
        _at.write_int(0);
        _at.cmd_stop();

        _at.resp_start();
        _at.resp_stop();

        nsapi_error_t err = _at.get_last_error();
        if (err == NSAPI_ERROR_OK)
        {
            _at.write_bytes(final_data, final_len);
            _at.resp_start();
            _at.resp_stop();
            err = _at.get_last_error();
        }

        _at.unlock();

        if (pem_ctx_initialized)
        {
            mbedtls_pem_free(&pem_ctx);
        }
        if (converted_buf)
        {
            free(converted_buf);
        }

        if (err == NSAPI_ERROR_OK)
        {
            tr_info("ST87M01 TLS: key added profile=%d size=%u", profile_id, static_cast<unsigned>(final_len));
        }
        else
        {
            device_err_t dev_err = _at.get_last_device_error();
            tr_error("ST87M01 TLS: add key failed CME=%d", dev_err.errCode);
        }

        return err;
    }

    nsapi_error_t ST87M01_TlsProvisioning::delete_key(int profile_id)
    {
        if (profile_id < 0 || profile_id > 15)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        _at.lock();
        nsapi_error_t err = _at.at_cmd_discard("#TLSKEYDEL", "=", "%d", profile_id);
        _at.unlock();
        return err;
    }

    void ST87M01_TlsProvisioning::list_keys(int profile_id)
    {
        _at.lock();
        if (profile_id >= 0)
        {
            _at.at_cmd_discard("#TLSKEYLIST", "=", "%d", profile_id);
        }
        else
        {
            _at.at_cmd_discard("#TLSKEYLIST", "");
        }
        _at.unlock();
    }

    // =========================================================================
    // Certificate Management
    // =========================================================================

    nsapi_error_t ST87M01_TlsProvisioning::add_ca_certificate(int profile_id,
                                                              const uint8_t *cert_data,
                                                              size_t cert_len,
                                                              bool volatile_storage)
    {
        return add_certificate_impl(profile_id, CERT_CA_ROOT, cert_data, cert_len, volatile_storage);
    }

    nsapi_error_t ST87M01_TlsProvisioning::add_device_certificate(int profile_id,
                                                                  const uint8_t *cert_data,
                                                                  size_t cert_len,
                                                                  bool volatile_storage)
    {
        return add_certificate_impl(profile_id, CERT_DEVICE, cert_data, cert_len, volatile_storage);
    }

    nsapi_error_t ST87M01_TlsProvisioning::add_certificate_impl(int profile_id, CertType type,
                                                                const uint8_t *cert_data, size_t cert_len,
                                                                bool volatile_storage)
    {
        if (profile_id < 0 || profile_id > 15 || !cert_data || cert_len == 0)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        if (cert_len > OP_MAX_PEM_SIZE)
        {
            tr_error("ST87M01 TLS: cert %u too large", static_cast<unsigned>(cert_len));
            return NSAPI_ERROR_PARAMETER;
        }

        // Convert PEM/hex inputs to DER.
        const uint8_t *final_data = cert_data;
        size_t final_len = cert_len;
        uint8_t *converted_buf = nullptr;
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
        mbedtls_pem_context pem_ctx;
        bool pem_ctx_initialized = false;
#endif

        if (is_hex_string(cert_data, cert_len))
        {
            size_t max_bin_len = cert_len / 2 + 1;
            converted_buf = static_cast<uint8_t *>(malloc(max_bin_len));
            if (!converted_buf)
            {
                return NSAPI_ERROR_NO_MEMORY;
            }

            size_t bin_len = convert_hex_to_bin(reinterpret_cast<const char *>(cert_data),
                                                cert_len, converted_buf, max_bin_len);
            if (bin_len == 0)
            {
                free(converted_buf);
                return NSAPI_ERROR_PARAMETER;
            }

            final_data = converted_buf;
            final_len = bin_len;
        }
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
        else if (looks_like_pem(cert_data, cert_len))
        {
            uint8_t *pem_terminated = static_cast<uint8_t *>(malloc(cert_len + 1));
            if (!pem_terminated)
            {
                return NSAPI_ERROR_NO_MEMORY;
            }
            memcpy(pem_terminated, cert_data, cert_len);
            pem_terminated[cert_len] = '\0';

            mbedtls_pem_init(&pem_ctx);
            pem_ctx_initialized = true;

            size_t use_len = 0;
            int ret = mbedtls_pem_read_buffer(&pem_ctx,
                                              "-----BEGIN CERTIFICATE-----",
                                              "-----END CERTIFICATE-----",
                                              pem_terminated,
                                              nullptr, 0,
                                              &use_len);

            free(pem_terminated);

            if (ret != 0)
            {
                tr_error("ST87M01 TLS: PEM parse -0x%04x", -ret);
                mbedtls_pem_free(&pem_ctx);
                return NSAPI_ERROR_PARAMETER;
            }

            final_data = pem_ctx.buf;
            final_len = pem_ctx.buflen;
        }
#endif

        // RSA modulus cap: 2048 bits.
        size_t rsa_bits = 0;
        if (parse_rsa_modulus_bits(final_data, final_len, &rsa_bits))
        {
            if (rsa_bits > 2048)
            {
                tr_error("ST87M01 TLS: RSA %u bits > 2048", static_cast<unsigned>(rsa_bits));
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
                if (pem_ctx_initialized) mbedtls_pem_free(&pem_ctx);
#endif
                free(converted_buf);
                return NSAPI_ERROR_PARAMETER;
            }
        }

        /* A key must exist before TLSCERTADD.
         * CA_ROOT: auto-generate a placeholder (not used for TLS validation).
         * DEVICE:  caller must have provisioned the matching key. */
        if (type == CERT_CA_ROOT)
        {
            tr_info("ST87M01 TLS: gen placeholder key for CA cert profile=%d", profile_id);
            KeyStorage key_storage = volatile_storage ? STORAGE_RAM : STORAGE_FLASH;
            nsapi_error_t gen_err = generate_key(profile_id, 32, key_storage);
            if (gen_err != NSAPI_ERROR_OK)
            {
                tr_error("ST87M01 TLS: key gen err=%d, cert add aborted", gen_err);
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
                if (pem_ctx_initialized) mbedtls_pem_free(&pem_ctx);
#endif
                free(converted_buf);
                return gen_err;
            }
        }
        else
        {
            // Device cert needs a matching key; verify with TLSKEYLIST.
            nsapi_error_t key_err = _at.at_cmd_discard("#TLSKEYLIST", "=", "%d", profile_id);
            if (key_err != NSAPI_ERROR_OK)
            {
                tr_error("ST87M01 TLS: profile=%d no key; call add_key() first", profile_id);
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
                if (pem_ctx_initialized) mbedtls_pem_free(&pem_ctx);
#endif
                free(converted_buf);
                return NSAPI_ERROR_PARAMETER;
            }
        }

        // Drop existing cert of same type to avoid CME 1301.
        delete_certificate(profile_id, type);

        tr_info("ST87M01 TLS: add cert type=%d profile=%d size=%u",
                type, profile_id, static_cast<unsigned>(final_len));

        // ASCII transfer: DER -> hex string.
        static const char hex_chars[] = "0123456789ABCDEF";
        const size_t hex_len = final_len * 2;
        char *hex_data = static_cast<char *>(malloc(hex_len + 1));
        if (!hex_data)
        {
#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
            if (pem_ctx_initialized) mbedtls_pem_free(&pem_ctx);
#endif
            free(converted_buf);
            return NSAPI_ERROR_NO_MEMORY;
        }

        for (size_t i = 0; i < final_len; i++)
        {
            hex_data[i * 2]     = hex_chars[(final_data[i] >> 4) & 0x0F];
            hex_data[i * 2 + 1] = hex_chars[final_data[i] & 0x0F];
        }
        hex_data[hex_len] = '\0';

        _at.lock();
        _at.cmd_start("AT#TLSCERTADD=");
        _at.write_int(profile_id);
        _at.write_int(type);
        _at.write_int(static_cast<int>(final_len));
        _at.write_bytes(reinterpret_cast<const uint8_t *>(","), 1);
        _at.write_bytes(reinterpret_cast<const uint8_t *>(hex_data), hex_len);
        _at.cmd_stop();

        _at.resp_start();
        _at.resp_stop();

        nsapi_error_t err = _at.get_last_error();

        free(hex_data);
        _at.unlock();

#if MBED_CONF_ST87M01_TLS_SUPPORT_PEM
        if (pem_ctx_initialized)
        {
            mbedtls_pem_free(&pem_ctx);
        }
#endif
        free(converted_buf);

        if (err == NSAPI_ERROR_OK)
        {
            tr_info("ST87M01 TLS: cert added type=%d profile=%d size=%u",
                    type, profile_id, static_cast<unsigned>(final_len));
        }
        else
        {
            device_err_t dev_err = _at.get_last_device_error();
            tr_error("ST87M01 TLS: cert add failed CME=%d", dev_err.errCode);
            if (dev_err.errCode == 1300)
            {
                tr_error("ST87M01 TLS: CME 1300 = invalid PSA, cert may need TLSCERTSIGN");
            }
        }

        return err;
    }

    nsapi_error_t ST87M01_TlsProvisioning::delete_certificate(int profile_id, CertType type)
    {
        if (profile_id < 0 || profile_id > 15)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        _at.lock();
        nsapi_error_t err = _at.at_cmd_discard("#TLSCERTDEL", "=", "%d,%d", profile_id, type);
        _at.unlock();
        return err;
    }

    nsapi_error_t ST87M01_TlsProvisioning::delete_all_certificates(int profile_id)
    {
        if (profile_id < 0 || profile_id > 15)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        _at.lock();
        nsapi_error_t err = _at.at_cmd_discard("#TLSCERTDEL", "=", "%d", profile_id);
        _at.unlock();
        return err;
    }

    void ST87M01_TlsProvisioning::list_certificates(int profile_id)
    {
        _at.lock();
        if (profile_id >= 0)
        {
            _at.at_cmd_discard("#TLSCERTLIST", "=", "%d", profile_id);
        }
        else
        {
            _at.at_cmd_discard("#TLSCERTLIST", "");
        }
        _at.unlock();
    }

    // =========================================================================
    // Utility
    // =========================================================================

    nsapi_error_t ST87M01_TlsProvisioning::save_to_nvm()
    {
        tr_info("ST87M01 TLS: saving NVM (reboot)");
        _at.lock();
        nsapi_error_t err = _at.at_cmd_discard("#RESET", "=1");
        _at.unlock();

        if (err == NSAPI_ERROR_OK)
        {
            rtos::ThisThread::sleep_for(2s);
        }
        return err;
    }

    nsapi_error_t ST87M01_TlsProvisioning::check_profile(int profile_id, bool *has_key, bool *has_cert)
    {
        if (profile_id < 0 || profile_id > 15)
        {
            return NSAPI_ERROR_PARAMETER;
        }

        if (has_key)
        {
            *has_key = false;
        }
        if (has_cert)
        {
            *has_cert = false;
        }

        nsapi_error_t err = _at.at_cmd_discard("#TLSKEYLIST", "=", "%d", profile_id);
        if (err == NSAPI_ERROR_OK && has_key)
        {
            *has_key = true;
        }

        err = _at.at_cmd_discard("#TLSCERTLIST", "=", "%d", profile_id);
        if (err == NSAPI_ERROR_OK && has_cert)
        {
            *has_cert = true;
        }

        return NSAPI_ERROR_OK;
    }

    bool ST87M01_TlsProvisioning::is_profile_ready(int profile_id)
    {
        bool has_key = false;
        bool has_cert = false;
        check_profile(profile_id, &has_key, &has_cert);
        return has_key || has_cert;
    }

    bool ST87M01_TlsProvisioning::has_certificate(int profile_id, CertType type)
    {
        bool has_key = false;
        bool has_cert = false;
        check_profile(profile_id, &has_key, &has_cert);
        return has_cert;
    }

} // namespace mbed
