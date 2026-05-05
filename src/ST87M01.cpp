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

#include <cstdio>
#include <cstring>

#include "rtos/ThisThread.h"

#include "CellularLog.h"

#include "ST87M01.h"
#include "ST87M01_CellularContext.h"
#include "ST87M01_CellularInformation.h"
#include "ST87M01_CellularNetwork.h"
#include "ST87M01_TlsProvisioning.h"

using namespace events;
using namespace mbed;
using namespace std::chrono_literals;

static const uint16_t RETRY_TIMEOUT_ARRAY[] = {2, 4, 8, 16, 32};
static const intptr_t CELLULAR_PROPERTIES[AT_CellularDevice::PROPERTY_MAX] = {
    5,                                           // C_EREG
    AT_CellularNetwork::RegistrationModeDisable, // C_GREG
    AT_CellularNetwork::RegistrationModeDisable, // C_REG
    1,                                           // AT_CGSN_WITH_TYPE
    1,                                           // AT_CGDATA
    0,                                           // AT_CGAUTH
    1,                                           // AT_CNMI
    1,                                           // AT_CSMP
    1,                                           // AT_CMGF
    1,                                           // AT_CSDH
    1,                                           // PROPERTY_IPV4_STACK
    1,                                           // PROPERTY_IPV6_STACK
    1,                                           // PROPERTY_IPV4V6_STACK
    0,                                           // PROPERTY_NON_IP_PDP_TYPE
    0,                                           // PROPERTY_AT_CGEREP
    0,                                           // PROPERTY_AT_COPS_FALLBACK_AUTO
    6,                                           // PROPERTY_SOCKET_COUNT (0 to 6)
    1,                                           // PROPERTY_IP_TCP
    1,                                           // PROPERTY_IP_UDP
    0,                                           // PROPERTY_AT_SEND_DELAY
};

/// Decode hex string to binary. Returns number of bytes written, 0 on error.
static size_t hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_max)
{
    size_t bin_len = hex_len / 2;
    if (hex_len % 2 != 0 || bin_len > out_max)
    {
        return 0;
    }
    for (size_t i = 0; i < bin_len; i++)
    {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        out[i] = (uint8_t)strtol(byte_str, nullptr, 16);
    }
    return bin_len;
}

ST87M01::ST87M01(FileHandle *fh, PinName rst, PinName wakeup)
    : AT_CellularDevice(fh),
      _rst(rst, 1),
      _wakeup(wakeup, 0),
      _tls_provisioning(nullptr)
#if MBED_CONF_ST87M01_CONFIGURE
      , _configured(false)
#endif
{
    fh->set_blocking(true);
    set_cellular_properties(CELLULAR_PROPERTIES);
#ifdef MBED_CONF_NSAPI_DEFAULT_CELLULAR_PLMN
    tr_debug("ST87M01: set_plmn=%s", MBED_CONF_NSAPI_DEFAULT_CELLULAR_PLMN);
    set_plmn(MBED_CONF_NSAPI_DEFAULT_CELLULAR_PLMN);
#endif
    set_retry_timeout_array(RETRY_TIMEOUT_ARRAY, sizeof(RETRY_TIMEOUT_ARRAY) / sizeof(RETRY_TIMEOUT_ARRAY[0]));
}

ST87M01::~ST87M01()
{
    delete _tls_provisioning;
    _tls_provisioning = nullptr;
}

nsapi_error_t ST87M01::init()
{
    setup_at_handler();

    // ATE0 is mandatory; ATHandler's parser assumes echo off.
    // The rest are diagnostic/power-management and must not abort init.
    _at.lock();
    drain_rx(80ms);
    _at.sync(500);

    nsapi_error_t err = _at.at_cmd_discard("", "");
    if (err != NSAPI_ERROR_OK) {
        _at.unlock();
        tr_error("ST87M01: AT sync failed (err=%d)", err);
        return err;
    }

    err = _at.at_cmd_discard("E", "0");
    if (err != NSAPI_ERROR_OK) {
        _at.unlock();
        tr_error("ST87M01: ATE0 failed (err=%d)", err);
        return err;
    }

    _at.at_cmd_discard("+CMEE", "=1");
    _at.clear_error();
    _at.at_cmd_discard("#WDGMODE", "=0");
    _at.clear_error();
    _at.at_cmd_discard("+CSCON", "=1");
    _at.clear_error();
    _at.at_cmd_discard("#SLEEPIND", "=1");
    _at.clear_error();
    _at.at_cmd_discard("#SLEEPMODE", "=0");
    _at.clear_error();
    _at.at_cmd_discard("#WAKEUPEVENT", "=", "%d,%d", 15, 3);
    _at.clear_error();

    // configure() runs under the held AT lock.
#if MBED_CONF_ST87M01_CONFIGURE
    if (!_configured) {
        err = configure();
        if (err != NSAPI_ERROR_OK) {
            _at.unlock();
            tr_error("ST87M01: configure() failed (err=%d)", err);
            return err;
        }
        _configured = true;
    }
#endif

    _at.unlock();

    err = ensure_cfun1();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: CFUN=1 failed (err=%d)", err);
        return err;
    }

    if (is_tls_enabled()) {
        err = init_tls();
        if (err != NSAPI_ERROR_OK) {
            tr_error("ST87M01: TLS init failed (err=%d)", err);
            return err;
        }
    }

    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01::wait_for_app_ready(int attempts)
{
    // CME 1120 = APP MCU still booting. Drop lock between probes for URC drain.
    nsapi_error_t err = NSAPI_ERROR_DEVICE_ERROR;
    for (int attempt = 0; attempt < attempts; attempt++) {
        _at.clear_error();
        int sim_status = -1;
        err = _at.at_cmd_int("#SIMST", "?", sim_status);
        if (err == NSAPI_ERROR_OK) {
            return NSAPI_ERROR_OK;
        }

        device_err_t dev_err = _at.get_last_device_error();
        if (dev_err.errType != DeviceErrorTypeErrorCME || dev_err.errCode != 1120) {
            return err;
        }

        if (attempt == 0) {
            tr_info("ST87M01: APP not ready (CME 1120), waiting...");
        }
        _at.unlock();
        rtos::ThisThread::sleep_for(1000ms);
        _at.lock();
    }
    return err;
}

nsapi_error_t ST87M01::configure()
{
    // Caller holds _at.lock() across the band/IPPARAMS reconfig.
    nsapi_error_t err = wait_for_app_ready();
    if (err != NSAPI_ERROR_OK) {
        tr_warn("ST87M01: APP processor not ready (err=%d)", err);
        return err;
    }

    // ---- Query current state ------------------------------------------------

    bool bands_match = true;
#ifdef MBED_CONF_ST87M01_BANDS
    char current_bands[64] = {0};
    _at.cmd_start_stop("#BANDSEL", "?");
    _at.resp_start("#BANDSEL:");
    _at.set_delimiter(';');
    _at.read_string(current_bands, sizeof(current_bands));
    _at.set_default_delimiter();
    _at.resp_stop();
    err = _at.get_last_error();
    if (err != NSAPI_ERROR_OK) {
        tr_warn("ST87M01: #BANDSEL query failed (err=%d)", err);
        return err;
    }
    bands_match = (strcmp(current_bands, MBED_CONF_ST87M01_BANDS) == 0);
#else
    tr_info("ST87M01: bands not configured, leaving #BANDSEL unchanged");
#endif

    const int expected_ip_pref = (strcmp(MBED_CONF_ST87M01_DEFAULT_PDP_TYPE, "IPV6") == 0) ? 1 : 0;
    bool ipparams_match = false;
    {
        char ipparams_buf[128] = {0};
        _at.clear_error();
        _at.cmd_start_stop("#IPPARAMS", "?");
        _at.resp_start("#IPPARAMS:");
        _at.set_delimiter(';');
        _at.read_string(ipparams_buf, sizeof(ipparams_buf));
        _at.set_default_delimiter();
        _at.resp_stop();

        if (_at.get_last_error() == NSAPI_ERROR_OK && ipparams_buf[0] != '\0') {
            int auto_ip = -1;
            int preferred_ip = -1;
            sscanf(ipparams_buf, "%d,%d", &auto_ip, &preferred_ip);
            ipparams_match = (auto_ip == 1 && preferred_ip == expected_ip_pref);
        }
        _at.clear_error();
    }

    if (bands_match && ipparams_match) {
#ifdef MBED_CONF_ST87M01_BANDS
        tr_info("ST87M01: bands=%s and IPPARAMS already set, skipping cold-init", current_bands);
#else
        tr_info("ST87M01: IPPARAMS already set, skipping cold-init");
#endif
        return NSAPI_ERROR_OK;
    }

#ifdef MBED_CONF_ST87M01_BANDS
    if (bands_match) {
        tr_info("ST87M01: bands=%s ok, applying IPPARAMS", current_bands);
    } else {
        tr_info("ST87M01: bands cold-init: %s -> %s", current_bands, MBED_CONF_ST87M01_BANDS);
    }
#else
    tr_info("ST87M01: IPPARAMS cold-init");
#endif

    // #BANDSEL and #IPPARAMS are only writable while CFUN=0.
    _at.set_at_timeout(16000, false);
    err = _at.at_cmd_discard("+CFUN", "=", "%d", 0);
    _at.restore_at_timeout();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: CFUN=0 failed (err=%d)", err);
        return err;
    }
    ThisThread::sleep_for(500ms);

#ifdef MBED_CONF_ST87M01_BANDS
    if (!bands_match) {
        _at.cmd_start("AT#BANDSEL=");
        _at.write_string(MBED_CONF_ST87M01_BANDS, false);
        _at.cmd_stop_read_resp();
        err = _at.get_last_error();
        if (err != NSAPI_ERROR_OK) {
            tr_error("ST87M01: #BANDSEL write failed (err=%d)", err);
            return err;
        }

#ifdef MBED_CONF_ST87M01_BANDCFG
        if (_at.at_cmd_discard("#BANDCFG", "=", "%s", MBED_CONF_ST87M01_BANDCFG) != NSAPI_ERROR_OK) {
            tr_warn("ST87M01: #BANDCFG primary failed, continuing");
        } else {
            tr_info("ST87M01: #BANDCFG primary configured: %s", MBED_CONF_ST87M01_BANDCFG);
        }
#endif
#ifdef MBED_CONF_ST87M01_BANDCFG_NMO1
        if (_at.at_cmd_discard("#BANDCFG", "=", "%s", MBED_CONF_ST87M01_BANDCFG_NMO1) != NSAPI_ERROR_OK) {
            tr_warn("ST87M01: #BANDCFG NMO1 failed, continuing");
        }
#endif
#ifdef MBED_CONF_ST87M01_BANDCFG_NMO2
        if (_at.at_cmd_discard("#BANDCFG", "=", "%s", MBED_CONF_ST87M01_BANDCFG_NMO2) != NSAPI_ERROR_OK) {
            tr_warn("ST87M01: #BANDCFG NMO2 failed, continuing");
        }
#endif
#ifdef MBED_CONF_ST87M01_BANDCFG_NMO3
        if (_at.at_cmd_discard("#BANDCFG", "=", "%s", MBED_CONF_ST87M01_BANDCFG_NMO3) != NSAPI_ERROR_OK) {
            tr_warn("ST87M01: #BANDCFG NMO3 failed, continuing");
        }
#endif
    }
#endif // MBED_CONF_ST87M01_BANDS

    // EC (Extended Coverage) OOS timers; best-effort.
    if (_at.at_cmd_discard("#SCAN", "=", "%d,%d,%d,%d,%d,%d", 1, -110, 1, 360, 1, 360) != NSAPI_ERROR_OK) {
        tr_warn("ST87M01: #SCAN failed, continuing");
        _at.clear_error();
    }

    /* AT#IPPARAMS=<auto_ip>,<preferred_ip>,<max_periodicity>,<timeout>,<nbsent>,
     *             <dns4>,<dns6>,<backup_dns>,<dns_select> */
    _at.cmd_start("AT#IPPARAMS=");
    _at.write_int(1);
    _at.write_int(expected_ip_pref);
    _at.write_int(65535);
    _at.write_int(60);
    _at.write_int(0);
#ifdef MBED_CONF_CELLULAR_OFFLOAD_DNS_QUERIES
    _at.write_string(MBED_CONF_ST87M01_DNSV4, false);
    _at.write_string(MBED_CONF_ST87M01_DNSV6, false);
    _at.write_string("", false);
    _at.write_int(MBED_CONF_ST87M01_DNS_TO_USE);
#else
    _at.write_string("", false);
    _at.write_string("", false);
    _at.write_string("", false);
    _at.write_int(1);
#endif
    _at.cmd_stop_read_resp();
    err = _at.get_last_error();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: #IPPARAMS configuration failed (err=%d)", err);
        return err;
    }
    tr_info("ST87M01: #IPPARAMS configured");

    err = soft_reset();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: soft_reset failed (err=%d)", err);
        return err;
    }
    drain_rx(80ms);
    err = _at.at_cmd_discard("", "");
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: AT sync after reboot failed (err=%d)", err);
    }
    return err;
}

nsapi_error_t ST87M01::init_tls()
{
    const int sslctxID = MBED_CONF_ST87M01_TLS_DEFAULT_SSLCTXID;
    tr_info("ST87M01: checking TLS profile %d", sslctxID);

    ST87M01_TlsProvisioning *tls = get_tls_provisioning();
    if (!tls) {
        return NSAPI_ERROR_NO_MEMORY;
    }

    bool has_key = false;
    bool has_cert = false;

    nsapi_error_t err = tls->check_profile(sslctxID, &has_key, &has_cert);
    if (err != NSAPI_ERROR_OK) {
        tr_warn("ST87M01: TLS profile %d check failed (err=%d)", sslctxID, err);
        return err;
    }

    tr_info("ST87M01: TLS profile %d key=%d cert=%d", sslctxID, has_key, has_cert);

    bool need_save = false;

    if (!has_key) {
        if (MBED_CONF_ST87M01_TLS_GENERATE_KEY) {
            tr_info("ST87M01: generating key for profile %d", sslctxID);
            err = tls->generate_key(
                sslctxID,
                MBED_CONF_ST87M01_TLS_KEY_SIZE,
                static_cast<ST87M01_TlsProvisioning::KeyStorage>(MBED_CONF_ST87M01_TLS_KEY_STORAGE));
            if (err != NSAPI_ERROR_OK) {
                tr_error("ST87M01: key generation failed for profile %d (err=%d)", sslctxID, err);
                return err;
            }
            need_save = true;
        } else {
            tr_warn("ST87M01: TLS profile %d has no key and tls_generate_key=false", sslctxID);
        }
    }

    if (!has_cert && MBED_CONF_ST87M01_TLS_CA_CERT != nullptr) {
        const char *ca_cert_hex = MBED_CONF_ST87M01_TLS_CA_CERT;
        if (ca_cert_hex && ca_cert_hex[0] != '\0') {
            tr_info("ST87M01: provisioning CA cert for profile %d", sslctxID);

            size_t hex_len = strlen(ca_cert_hex);
            size_t bin_len = hex_len / 2;
            uint8_t *cert_der = new uint8_t[bin_len];

            size_t decoded = hex_decode(ca_cert_hex, hex_len, cert_der, bin_len);
            if (decoded == 0) {
                delete[] cert_der;
                tr_error("ST87M01: CA cert hex decode failed for profile %d", sslctxID);
                return NSAPI_ERROR_PARAMETER;
            }

            err = tls->add_ca_certificate(sslctxID, cert_der, decoded, false);
            delete[] cert_der;

            if (err != NSAPI_ERROR_OK) {
                tr_error("ST87M01: CA cert add failed for profile %d (err=%d)", sslctxID, err);
                return err;
            }
            need_save = true;
        }
    }

    if (MBED_CONF_ST87M01_TLS_DEVICE_CERT != nullptr) {
        const char *dev_cert_hex = MBED_CONF_ST87M01_TLS_DEVICE_CERT;
        if (dev_cert_hex && dev_cert_hex[0] != '\0') {
            tr_info("ST87M01: provisioning device cert for profile %d", sslctxID);

            size_t hex_len = strlen(dev_cert_hex);
            size_t bin_len = hex_len / 2;
            uint8_t *cert_der = new uint8_t[bin_len];

            size_t decoded = hex_decode(dev_cert_hex, hex_len, cert_der, bin_len);
            if (decoded == 0) {
                delete[] cert_der;
                tr_error("ST87M01: device cert hex decode failed for profile %d", sslctxID);
                return NSAPI_ERROR_PARAMETER;
            }

            err = tls->add_device_certificate(sslctxID, cert_der, decoded, false);
            delete[] cert_der;

            if (err != NSAPI_ERROR_OK) {
                tr_error("ST87M01: device cert add failed for profile %d (err=%d)", sslctxID, err);
                return err;
            }
            need_save = true;
        }
    }

    if (need_save) {
        tr_info("ST87M01: saving TLS to NVM (modem reboot)");
        err = tls->save_to_nvm();
        if (err != NSAPI_ERROR_OK) {
            tr_error("ST87M01: TLS NVM save failed (err=%d)", err);
            return err;
        }

        drain_rx(2000ms);
        _at.lock();
        _at.sync(500);
        _at.unlock();
    } else {
        tr_info("ST87M01: TLS profile %d already provisioned", sslctxID);
    }

    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01::ensure_cfun1()
{
    // Re-sending +CFUN=1 in CFUN=1 trips CME 98 and drops the IP stack. Query first.
    int cfun_mode = -1;
    _at.lock();
    _at.clear_error();
    nsapi_error_t err = _at.at_cmd_int("+CFUN", "?", cfun_mode);
    _at.unlock();

    if (err) {
        tr_error("ST87M01: +CFUN query failed (err=%d)", err);
        return err;
    }

    if (cfun_mode == 1) {
        tr_info("ST87M01: already in CFUN=1");
        return NSAPI_ERROR_OK;
    }

    tr_info("ST87M01: +CFUN=1 (previous mode=%d)", cfun_mode);
    _at.lock();
    _at.set_at_timeout(16000, false);
    err = _at.at_cmd_discard("+CFUN", "=", "%d", 1);
    _at.restore_at_timeout();
    _at.unlock();

    return err;
}

nsapi_error_t ST87M01::get_sim_state(SimState &state)
{
    _at.lock();
    _at.flush();

    int sim_status = -1;
    nsapi_error_t err = NSAPI_ERROR_OK;

    // CME 1120 = APP MCU still booting; retry up to 5s.
    for (int attempt = 0; attempt < 10; attempt++) {
        err = _at.at_cmd_int("#SIMST", "?", sim_status);
        if (!err) {
            break;
        }

        device_err_t dev_err = _at.get_last_device_error();
        if (dev_err.errType != DeviceErrorTypeErrorCME && dev_err.errCode != 1120) {
            break;
        }

        rtos::ThisThread::sleep_for(500ms);
    }
    _at.unlock();

    if (err == NSAPI_ERROR_OK) {
        if (sim_status == 1) {
            state = SimStateReady;
        } else {
            state = SimStateUnknown;
            err = NSAPI_ERROR_DEVICE_ERROR;
        }
    } else {
        tr_warn("ST87M01: SIM status query failed (err=%d)", err);
        state = SimStateUnknown;
    }

    return err;
}

bool ST87M01::reset()
{
    tr_info("ST87M01: hardware reset");
    if (!press_button(_rst, false, 15ms)) {
        return false;
    }

    drain_rx(2000ms);
    return true;
}

void ST87M01::drain_rx(std::chrono::duration<uint32_t, milli> dwell)
{
    _at.flush();
    ThisThread::sleep_for(dwell);
    _at.flush();
    _at.clear_error();
}

void ST87M01::dump_network_status()
{
    char buf[128];
    _at.lock();

    _at.cmd_start_stop("+CEREG", "?");
    _at.resp_start("+CEREG:");
    _at.read_string(buf, sizeof(buf));
    _at.resp_stop();
    tr_info("ST87M01: CEREG: %s", buf);

    _at.cmd_start_stop("+CGATT", "?");
    _at.resp_start("+CGATT:");
    int attached = _at.read_int();
    _at.resp_stop();
    tr_info("ST87M01: CGATT: %d", attached);

    for (int cid = 1; cid <= 7; cid++) {
        _at.cmd_start_stop("+CGACT", "?");
        _at.resp_start("+CGACT:");
        int cid_resp = _at.read_int();
        int state = _at.read_int();
        _at.resp_stop();
        if (_at.get_last_error() == NSAPI_ERROR_OK && cid_resp == cid && state != 0) {
            tr_info("ST87M01: CGACT cid=%d active=%d", cid, state);
        }
    }

    _at.cmd_start("AT+CGPADDR=");
    _at.write_int(1);
    _at.cmd_stop();
    _at.resp_start("+CGPADDR:");
    _at.skip_param();
    _at.read_string(buf, sizeof(buf));
    _at.resp_stop();
    if (_at.get_last_error() == NSAPI_ERROR_OK && buf[0] != '\0') {
        tr_info("ST87M01: CGPADDR: %s", buf);
    }

    _at.unlock();
}

ST87M01_TlsProvisioning *ST87M01::get_tls_provisioning()
{
    if (!_tls_provisioning) {
        _tls_provisioning = new ST87M01_TlsProvisioning(_at);
    }
    return _tls_provisioning;
}

AT_CellularNetwork *ST87M01::open_network_impl(ATHandler &at)
{
    return new ST87M01_CellularNetwork(at, *this);
}

AT_CellularContext *ST87M01::create_context_impl(ATHandler &at, const char *apn, bool cp_req, bool nonip_req)
{
#ifdef MBED_CONF_NSAPI_DEFAULT_CELLULAR_APN
    if (!apn || apn[0] == '\0') {
        apn = MBED_CONF_NSAPI_DEFAULT_CELLULAR_APN;
    }
#endif
    return new ST87M01_CellularContext(at, this, apn, cp_req, nonip_req);
}

AT_CellularInformation *ST87M01::open_information_impl(ATHandler &at)
{
    return new ST87M01_CellularInformation(at, *this);
}

nsapi_error_t ST87M01::set_baud_rate(int baud_rate)
{
    nsapi_error_t err;

#if (DEVICE_SERIAL && DEVICE_INTERRUPTIN)
    err = set_baud_rate_impl(baud_rate);
    if (err) {
        tr_warn("ST87M01: baud rate change to %d rejected (err=%d)", baud_rate, err);
        return err;
    }

    _at.set_baud(baud_rate);
    rtos::ThisThread::sleep_for(3s);
    drain_rx(80ms);
    err = soft_reset();
#else
    tr_warn("ST87M01: set_baud_rate needs DEVICE_SERIAL+DEVICE_INTERRUPTIN");
    err = NSAPI_ERROR_UNSUPPORTED;
#endif

    return err;
}

nsapi_error_t ST87M01::set_baud_rate_impl(int baud_rate)
{
    return _at.at_cmd_discard("+IPR", "=", "%d", baud_rate);
}

nsapi_error_t ST87M01::soft_reset()
{
    tr_info("ST87M01: saving NVM and rebooting");
    nsapi_error_t err = _at.at_cmd_discard("#RESET", "=1");
    rtos::ThisThread::sleep_for(3s);
    drain_rx(5000ms);
    if (!_at.sync(1000)) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    // CME 1120 = APP MCU still booting; retry up to 30s.
    for (int attempt = 0; attempt < 30; attempt++) {
        _at.clear_error();
        int sim_status = -1;
        nsapi_error_t sim_err = _at.at_cmd_int("#SIMST", "?", sim_status);
        if (sim_err == NSAPI_ERROR_OK) {
            tr_info("ST87M01: APP ready (attempts=%d)", attempt);
            return err;
        }

        device_err_t dev_err = _at.get_last_device_error();
        if (dev_err.errType == DeviceErrorTypeErrorCME && dev_err.errCode == 1120) {
            rtos::ThisThread::sleep_for(1000ms);
            continue;
        }

        return err;
    }

    tr_warn("ST87M01: APP readiness 30s timeout, proceeding");
    return err;
}

bool ST87M01::press_button(DigitalOut &button, bool active_high, std::chrono::duration<uint32_t, milli> duration)
{
    if (!button.is_connected()) {
        return false;
    }
    button = active_high;
    ThisThread::sleep_for(duration);
    button = !active_high;
    return true;
}

#if MBED_CONF_ST87M01_PROVIDE_DEFAULT
#include "drivers/BufferedSerial.h"
CellularDevice *CellularDevice::get_default_instance()
{
    static BufferedSerial serial(MBED_CONF_ST87M01_TX, MBED_CONF_ST87M01_RX, MBED_CONF_ST87M01_BAUDRATE);
#if defined(MBED_CONF_ST87M01_RTS) && defined(MBED_CONF_ST87M01_CTS)
    tr_debug("ST87M01 flow control: RTS %d CTS %d", MBED_CONF_ST87M01_RTS, MBED_CONF_ST87M01_CTS);
    serial.set_flow_control(SerialBase::RTSCTS, MBED_CONF_ST87M01_RTS, MBED_CONF_ST87M01_CTS);
#endif
    static ST87M01 device(&serial, MBED_CONF_ST87M01_RESETN, MBED_CONF_ST87M01_WAKEUP);
    return &device;
}
#endif
