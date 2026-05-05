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

#include <cstring>

#include "CellularLog.h"

#include "ST87M01.h"
#include "ST87M01_CellularContext.h"
#include "ST87M01_CellularStack.h"
#include "ST87M01_HTTP.h"

namespace mbed {

ST87M01_CellularContext::ST87M01_CellularContext(ATHandler &at, CellularDevice *device, const char *apn, bool cp_req, bool nonip_req)
    : AT_CellularContext(at, device, apn, cp_req, nonip_req),
      _http_client(nullptr),
      _http_socket_id(-1)
{
}

ST87M01_CellularContext::~ST87M01_CellularContext()
{
    if (_http_socket_id >= 0) {
        http_close();
    }
    delete _http_client;
    _http_client = nullptr;
}

nsapi_error_t ST87M01_CellularContext::get_ip_address(SocketAddress *address)
{
    if (!address) {
        return NSAPI_ERROR_PARAMETER;
    }
#if NSAPI_PPP_AVAILABLE
    address->set_ip_address(nsapi_ppp_get_ip_addr(_at.get_file_handle()));
    return NSAPI_ERROR_OK;
#else
    if (!_stack) {
        _stack = get_stack();
    }
    if (_stack) {
        static_cast<AT_CellularStack *>(_stack)->set_cid(_cid);
        _stack->get_ip_address(address);
        return NSAPI_ERROR_OK;
    }
    return NSAPI_ERROR_NO_CONNECTION;
#endif
}

nsapi_error_t ST87M01_CellularContext::close_all_sockets()
{
    if (_stack) {
        return static_cast<ST87M01_CellularStack *>(_stack)->close_all_sockets();
    }
    return NSAPI_ERROR_OK;
}

ST87M01_HTTP *ST87M01_CellularContext::get_http_client()
{
    if (!_http_client) {
        tr_info("ST87M01: creating HTTP client for cid=%d", _cid);
        _http_client = new ST87M01_HTTP(_at, _cid);
    }
    return _http_client;
}

ST87M01_CellularStack *ST87M01_CellularContext::get_st87_stack()
{
    if (!_stack) {
        get_stack();
    }
    return static_cast<ST87M01_CellularStack *>(_stack);
}

nsapi_error_t ST87M01_CellularContext::http_open(const char *host, uint16_t port, bool use_tls)
{
    if (_http_socket_id >= 0) {
        tr_warn("ST87M01: HTTP session already open on socket %d, closing first", _http_socket_id);
        http_close();
    }

    ST87M01_CellularStack *stack = get_st87_stack();
    if (!stack) {
        tr_error("ST87M01: HTTP open to %s:%u failed, no stack", host, port);
        return NSAPI_ERROR_NO_CONNECTION;
    }

    int socket_id = -1;
    nsapi_error_t err = stack->open_tcp_session(socket_id, host, port, use_tls);
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: HTTP open_tcp_session to %s:%u failed (err=%d)", host, port, err);
        return err;
    }

    ST87M01_HTTP *http = get_http_client();
    if (!http) {
        stack->close_tcp_session(socket_id);
        return NSAPI_ERROR_NO_MEMORY;
    }

    err = http->attach_socket(socket_id);
    if (err != NSAPI_ERROR_OK) {
        stack->close_tcp_session(socket_id);
        return err;
    }

    err = http->start();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: HTTP start on socket %d failed (err=%d)", socket_id, err);
        http->detach_socket();
        stack->close_tcp_session(socket_id);
        return err;
    }

    _http_socket_id = socket_id;
    tr_info("ST87M01: HTTP session opened to %s:%u (socket=%d tls=%d)", host, port, socket_id, use_tls);
    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01_CellularContext::http_close()
{
    if (_http_socket_id < 0) {
        return NSAPI_ERROR_OK;
    }

    nsapi_error_t err = NSAPI_ERROR_OK;

    if (_http_client) {
        _http_client->stop();
        _http_client->detach_socket();
    }

    ST87M01_CellularStack *stack = get_st87_stack();
    if (stack) {
        err = stack->close_tcp_session(_http_socket_id);
    }

    int closed_socket = _http_socket_id;
    _http_socket_id = -1;

    tr_info("ST87M01: HTTP session closed (socket=%d)", closed_socket);
    return err;
}

#if !NSAPI_PPP_AVAILABLE
NetworkStack *ST87M01_CellularContext::get_stack()
{
    if (_pdp_type == NON_IP_PDP_TYPE || _cp_in_use) {
        tr_error("ST87M01: cannot request stack for NON-IP context; use get_cp_netif() instead");
        return NULL;
    }

    if (!_stack) {
        tr_info("ST87M01: creating stack for cid=%d", _cid);
        _stack = new ST87M01_CellularStack(_at, _cid, (nsapi_ip_stack_t)_pdp_type, *get_device());
    } else {
        static_cast<AT_CellularStack *>(_stack)->set_cid(_cid);
    }
    return _stack;
}
#endif

const char *ST87M01_CellularContext::get_nonip_context_type_str()
{
    return "NONIP";
}

bool ST87M01_CellularContext::get_context()
{
    pdp_type_t selected_pdp_type = configured_pdp_type();
    char found_apn[MAX_ACCESSPOINT_NAME_LENGTH] = {0};

    _at.lock();
    int selected_cid = select_existing_cid(selected_pdp_type, found_apn, sizeof(found_apn));
    nsapi_error_t err = _at.get_last_error();
    _at.unlock();

    // Most NB-IoT networks are IPv4-only; honour the configured PDP type.
    pdp_type_t cfg_pdp = configured_pdp_type();
    if (err == NSAPI_ERROR_OK && selected_cid >= 0 && selected_pdp_type != cfg_pdp) {
        tr_info("ST87M01: cid=%d PDP modem=%d cfg=%d, using cfg",
                selected_cid, selected_pdp_type, cfg_pdp);
        selected_pdp_type = cfg_pdp;
    }

    if (err != NSAPI_ERROR_OK || selected_cid < 0) {
        // ST87M01 supports CIDs 1-6 only; CID 5 is usually auto-activated.
        // Base-class fallback (cid_max+1) would exceed the limit.
        tr_warn("ST87M01: no suitable context, reusing CID 5 or 6");
        _at.lock();

        int reuse_cid = -1;
        char existing_pdp[16] = {0};

        _at.cmd_start_stop("+CGDCONT", "?");
        _at.resp_start("+CGDCONT:");
        while (_at.info_resp()) {
            int cid = _at.read_int();
            char pdp[16] = {0};
            char apn[MAX_ACCESSPOINT_NAME_LENGTH] = {0};
            _at.read_string(pdp, sizeof(pdp));
            _at.read_string(apn, sizeof(apn));

            if ((cid == 5 || cid == 6) && reuse_cid < 0) {
                reuse_cid = cid;
                strncpy(existing_pdp, pdp, sizeof(existing_pdp) - 1);
            } else if (cid == 5 && reuse_cid == 6) {
                reuse_cid = cid;
                strncpy(existing_pdp, pdp, sizeof(existing_pdp) - 1);
            }
        }
        _at.resp_stop();

        if (reuse_cid < 0) {
            _at.unlock();
            tr_warn("ST87M01: CID 5/6 not found, falling back to base class");
            return AT_CellularContext::get_context();
        }

        tr_info("ST87M01: reusing cid=%d APN='%s'", reuse_cid, _apn ? _apn : "");

        selected_pdp_type = cfg_pdp;
        const char *apn_safe = (_apn && _apn[0]) ? _apn : "";
        nsapi_error_t reconf_err = _at.at_cmd_discard("+CGDCONT", "=", "%d,\"%s\",\"%s\"",
                                                     reuse_cid, pdp_type_to_str(selected_pdp_type), apn_safe);
        _at.unlock();

        if (reconf_err != NSAPI_ERROR_OK) {
            tr_error("ST87M01: reconf cid=%d APN='%s' (err=%d)",
                     reuse_cid, _apn ? _apn : "", reconf_err);
            return false;
        }

        selected_cid = reuse_cid;
    }

    _at.lock();
    bool is_active = _nw->is_active_context(NULL, selected_cid);
    _at.unlock();

    _pdp_type = selected_pdp_type;
    _cid = selected_cid;

    if (_stack) {
        static_cast<AT_CellularStack *>(_stack)->set_cid(_cid);
    }

    if (found_apn[0] != '\0' && !_apn) {
        memcpy(_found_apn, found_apn, sizeof(_found_apn));
    }

    tr_info("ST87M01: PDP cid=%d type=%d active=%d", selected_cid, _pdp_type, is_active);

    if ((found_apn[0] == '\0') && (!_apn || _apn[0] == '\0')) {
        tr_warn("ST87M01: cid=%d empty APN; set APN or st87m01.dnsv4", selected_cid);
    }

    const char *apn_to_check = _apn ? _apn : found_apn;
    if (apn_to_check && apn_to_check[0] != '\0') {
        if (strcasecmp(apn_to_check, "internet") == 0 || strcasecmp(apn_to_check, "web") == 0) {
            tr_warn("ST87M01: APN '%s' likely invalid; use operator NB-IoT APN", apn_to_check);
        }
    }

    if (is_active) {
        _is_context_active = true;
        _is_context_activated = true;
    }

    return true;
}

void ST87M01_CellularContext::deactivate_context()
{
    // CME 171 (last PDN disconnection not allowed) is benign; the network
    // refuses to drop the final PDP context. Treat as success.
    static constexpr int CME_LAST_PDN_NOT_ALLOWED = 171;
    _at.at_cmd_discard("+CGACT", "=0,", "%d", _cid);

    nsapi_error_t err = _at.get_last_error();
    if (err != NSAPI_ERROR_OK) {
        device_err_t dev_err = _at.get_last_device_error();
        if (dev_err.errType == DeviceErrorTypeErrorCME &&
            dev_err.errCode == CME_LAST_PDN_NOT_ALLOWED) {
            tr_info("ST87M01: disconnect ok, last PDN cid=%d preserved", _cid);
            _at.clear_error();
        } else {
            tr_warn("ST87M01: deactivate cid=%d failed CME=%d", _cid, dev_err.errCode);
        }
    } else {
        tr_info("ST87M01: deactivated cid=%d", _cid);
    }
}

int ST87M01_CellularContext::select_existing_cid(pdp_type_t &pdp_type_out, char *apn_out, size_t apn_len)
{
    // AT+CGACT?: list active contexts; ranker prefers active ones.
    bool cid_active[7] = {false};
    _at.cmd_start_stop("+CGACT", "?");
    _at.resp_start("+CGACT:");
    while (_at.info_resp()) {
        const int cid = _at.read_int();
        const int active = _at.read_int();
        if (cid >= 0 && cid < 7) {
            cid_active[cid] = (active == 1);
        }
    }
    _at.resp_stop();

    // AT+CGDCONT?: enumerate defined contexts, rank by preference.
    // Rank: active cid=5 > active cid=6 > any active > matching APN > other.
    int chosen = -1;
    char chosen_pdp[16] = {0};
    char apn_buf[MAX_ACCESSPOINT_NAME_LENGTH] = {0};

    _at.cmd_start_stop("+CGDCONT", "?");
    _at.resp_start("+CGDCONT:");
    while (_at.info_resp()) {
        const int cid = _at.read_int();
        char pdp_type[16] = {0};
        _at.read_string(pdp_type, sizeof(pdp_type));
        char apn[MAX_ACCESSPOINT_NAME_LENGTH] = {0};
        _at.read_string(apn, sizeof(apn));

        const bool is_active = (cid >= 0 && cid < 7) ? cid_active[cid] : false;
        auto prefer_rank = [&](int c, bool active) -> int {
            if (c == 5 && active) return 0;
            if (c == 6 && active) return 1;
            if (active) return 2;
            if (_apn && strlen(_apn) && strcasecmp(apn, _apn) == 0) return 3;
            return 10;
        };

        int current_rank = prefer_rank(cid, is_active);
        int chosen_rank = (chosen == -1) ? 7 : prefer_rank(chosen, (chosen >= 0 && chosen < 100) ? cid_active[chosen] : false);

        if (current_rank < chosen_rank) {
            chosen = cid;
            strncpy(chosen_pdp, pdp_type, sizeof(chosen_pdp) - 1);
            strncpy(apn_buf, apn, sizeof(apn_buf) - 1);
        }
    }
    _at.resp_stop();

    if (apn_out && apn_len) {
        strncpy(apn_out, apn_buf, apn_len - 1);
        apn_out[apn_len - 1] = '\0';
    }

    pdp_type_out = parse_pdp_type(chosen_pdp);
    return chosen;
}

ST87M01_CellularContext::pdp_type_t ST87M01_CellularContext::configured_pdp_type()
{
    if (strcmp(MBED_CONF_ST87M01_DEFAULT_PDP_TYPE, "IPV6") == 0) {
        return IPV6_PDP_TYPE;
    }
    if (strcmp(MBED_CONF_ST87M01_DEFAULT_PDP_TYPE, "IPV4V6") == 0) {
        return IPV4V6_PDP_TYPE;
    }
    return IPV4_PDP_TYPE;
}

ST87M01_CellularContext::pdp_type_t ST87M01_CellularContext::parse_pdp_type(const char *str)
{
    if (strcmp(str, "IPV4V6") == 0) {
        return IPV4V6_PDP_TYPE;
    }
    if (strcmp(str, "IPV6") == 0) {
        return IPV6_PDP_TYPE;
    }
    if (strcmp(str, "IP") == 0 || strcmp(str, "IPV4") == 0) {
        return IPV4_PDP_TYPE;
    }
    if (strcmp(str, "Non-IP") == 0 || strcmp(str, "NONIP") == 0) {
        return NON_IP_PDP_TYPE;
    }
    return IPV4V6_PDP_TYPE;
}

const char *ST87M01_CellularContext::pdp_type_to_str(pdp_type_t t)
{
    switch (t) {
        case IPV6_PDP_TYPE:
            return "IPV6";
        case IPV4V6_PDP_TYPE:
            return "IPV4V6";
        default:
            return "IP";
    }
}

} // namespace mbed
