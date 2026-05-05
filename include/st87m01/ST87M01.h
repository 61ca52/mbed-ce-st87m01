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

#ifndef ST87M01_H_
#define ST87M01_H_

#ifdef TARGET_FF_ARDUINO
#ifndef MBED_CONF_ST87M01_TX
#define MBED_CONF_ST87M01_TX D1
#endif
#ifndef MBED_CONF_ST87M01_RX
#define MBED_CONF_ST87M01_RX D0
#endif
#ifndef MBED_CONF_ST87M01_RESETN
#define MBED_CONF_ST87M01_RESETN D9
#endif
#ifndef MBED_CONF_ST87M01_WAKEUP
#define MBED_CONF_ST87M01_WAKEUP D8
#endif
#endif /* TARGET_FF_ARDUINO */

#ifndef MBED_CONF_ST87M01_CONFIGURE
#define MBED_CONF_ST87M01_CONFIGURE 1
#endif
#ifndef MBED_CONF_ST87M01_DEFAULT_PDP_TYPE
#define MBED_CONF_ST87M01_DEFAULT_PDP_TYPE "IP"
#endif

#ifndef MBED_CONF_ST87M01_DNSV4
#define MBED_CONF_ST87M01_DNSV4 ""
#endif
#ifndef MBED_CONF_ST87M01_DNSV6
#define MBED_CONF_ST87M01_DNSV6 ""
#endif
#ifndef MBED_CONF_ST87M01_DNS_TO_USE
#define MBED_CONF_ST87M01_DNS_TO_USE 1
#endif

#ifndef MBED_CONF_ST87M01_TLS_ENABLE
#define MBED_CONF_ST87M01_TLS_ENABLE false
#endif
#ifndef MBED_CONF_ST87M01_TLS_DEFAULT_SSLCTXID
#define MBED_CONF_ST87M01_TLS_DEFAULT_SSLCTXID 0
#endif
#ifndef MBED_CONF_ST87M01_TLS_CA_CERT
#define MBED_CONF_ST87M01_TLS_CA_CERT nullptr
#endif
#ifndef MBED_CONF_ST87M01_TLS_DEVICE_CERT
#define MBED_CONF_ST87M01_TLS_DEVICE_CERT nullptr
#endif
#ifndef MBED_CONF_ST87M01_TLS_GENERATE_KEY
#define MBED_CONF_ST87M01_TLS_GENERATE_KEY false
#endif
#ifndef MBED_CONF_ST87M01_TLS_KEY_SIZE
#define MBED_CONF_ST87M01_TLS_KEY_SIZE 32
#endif
#ifndef MBED_CONF_ST87M01_TLS_KEY_STORAGE
#define MBED_CONF_ST87M01_TLS_KEY_STORAGE 2
#endif

#include <chrono>

#include "mbed.h"
#include "AT_CellularDevice.h"

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

class ST87M01_TlsProvisioning;

/** ST87M01 NB-IoT modem driver (AT sockets, module-IP mode). */
class ST87M01 : public AT_CellularDevice {
public:
    ST87M01(FileHandle *fh, PinName rst, PinName wakeup);
    virtual ~ST87M01();

    virtual nsapi_error_t get_sim_state(SimState &state) override;
    virtual nsapi_error_t init() override;

    /** Apply RF bands, IP stack params, cold-init. Caller holds _at.lock(). */
    virtual nsapi_error_t configure();

    /** Provision TLS credentials to the default profile per mbed_app.json. */
    virtual nsapi_error_t init_tls();

    /** Promote radio to CFUN=1 only when not already there. Re-issuing
     *  AT+CFUN=1 in CFUN=1 trips CME 98 and drops the IP stack. */
    nsapi_error_t ensure_cfun1();

    /** Pulse the hardware reset line and drain the UART. */
    bool reset();

    /** Flush UART, wait, flush again. */
    void drain_rx(std::chrono::duration<uint32_t, milli> dwell = std::chrono::milliseconds(50));

    /** Dump registration, attach and PDP status to trace. */
    void dump_network_status();

    /** TLS provisioning interface (lazy, one per device). */
    ST87M01_TlsProvisioning *get_tls_provisioning();

    /** Default TLS security profile id from mbed_app.json. */
    int get_default_sslctxid() const { return MBED_CONF_ST87M01_TLS_DEFAULT_SSLCTXID; }

    /** True when TLS provisioning is enabled in config. */
    bool is_tls_enabled() const { return MBED_CONF_ST87M01_TLS_ENABLE; }

protected:
    virtual AT_CellularNetwork *open_network_impl(ATHandler &at) override;
    virtual AT_CellularContext *create_context_impl(ATHandler &at, const char *apn, bool cp_req = false, bool nonip_req = false) override;
    virtual AT_CellularInformation *open_information_impl(ATHandler &at) override;
    virtual nsapi_error_t set_baud_rate(int baud_rate) override;
    virtual nsapi_error_t set_baud_rate_impl(int baud_rate) override;

    nsapi_error_t soft_reset();

private:
    /** Poll #SIMST until APP MCU clears CME 1120. Caller holds _at.lock();
     *  the lock is briefly released between probes. */
    nsapi_error_t wait_for_app_ready(int attempts = 30);

    bool press_button(DigitalOut &button, bool active_high, std::chrono::duration<uint32_t, milli> duration);

    DigitalOut _rst;
    DigitalOut _wakeup;
    ST87M01_TlsProvisioning *_tls_provisioning;

#if MBED_CONF_ST87M01_CONFIGURE
    bool _configured;
#endif
};

/** @}*/

} // namespace mbed
#endif // ST87M01_H_
