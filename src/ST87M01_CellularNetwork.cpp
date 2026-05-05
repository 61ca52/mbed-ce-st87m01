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

#include "ST87M01_CellularNetwork.h"

using namespace mbed;

ST87M01_CellularNetwork::ST87M01_CellularNetwork(ATHandler &at, AT_CellularDevice &device)
    : AT_CellularNetwork(at, device)
{
    _op_act = RAT_NB1;
}

nsapi_error_t ST87M01_CellularNetwork::set_access_technology_impl(RadioAccessTechnology op_rat)
{
    if (op_rat != RAT_NB1) {
        _op_act = RAT_NB1;
        return NSAPI_ERROR_UNSUPPORTED;
    }
    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01_CellularNetwork::set_registration(const char *plmn)
{
    if (_op_act != RAT_NB1) {
        _op_act = RAT_NB1;
    }

    NWRegisteringMode mode = NWModeAutomatic;

    if (!plmn) {
        tr_debug("ST87M01: auto registration");
        if (get_network_registering_mode(mode) != NSAPI_ERROR_OK) {
            return NSAPI_ERROR_DEVICE_ERROR;
        }
        if (mode != NWModeAutomatic) {
            return _at.at_cmd_discard("+COPS", "=0");
        }
        return NSAPI_ERROR_OK;
    }

    tr_debug("ST87M01: manual registration to %s", plmn);

    // With auto_ip=1 the modem auto-registers; +COPS=1 on the same PLMN
    // returns CME 3 ("operation not allowed"). Check current PLMN first.
    {
        int current_mode = -1;
        char current_oper[32] = {0};

        _at.cmd_start_stop("+COPS", "?");
        _at.resp_start("+COPS:");
        current_mode = _at.read_int();
        if (_at.get_last_error() == NSAPI_ERROR_OK) {
            _at.skip_param();
            _at.read_string(current_oper, sizeof(current_oper));
        }
        _at.resp_stop();

        if (_at.get_last_error() == NSAPI_ERROR_OK &&
                current_oper[0] != '\0' &&
                strcmp(current_oper, plmn) == 0) {
            tr_info("ST87M01: already on PLMN %s mode=%d", plmn, current_mode);
            return NSAPI_ERROR_OK;
        }
        _at.clear_error();
    }

    mode = NWModeManual;
    OperatorNameFormat format = OperatorNameNumeric;

#ifdef MBED_CONF_CELLULAR_PLMN_FALLBACK_AUTO
    if (_device.get_property(AT_CellularDevice::PROPERTY_AT_COPS_FALLBACK_AUTO)) {
        mode = NWModeManualAutomatic;
    }
#endif

    // ST87M01 rejects +COPS with <act>=9 in some states; omit <act>.
    _at.set_at_timeout(180000, false);
    nsapi_error_t err = _at.at_cmd_discard("+COPS", "=", "%d,%d,%s", mode, format, plmn);
    _at.restore_at_timeout();

    if (err != NSAPI_ERROR_OK) {
        // CME 3 ("operation not allowed") usually means we are already registered;
        // confirm via +CEREG.
        device_err_t dev_err = _at.get_last_device_error();
        if (dev_err.errType == DeviceErrorTypeErrorCME && dev_err.errCode == 3) {
            tr_info("ST87M01: +COPS rejected (CME 3), probing +CEREG");
            _at.clear_error();

            int cereg_stat = -1;
            _at.cmd_start_stop("+CEREG", "?");
            _at.resp_start("+CEREG:");
            _at.skip_param();
            cereg_stat = _at.read_int();
            _at.resp_stop();

            if (_at.get_last_error() == NSAPI_ERROR_OK &&
                    (cereg_stat == 1 || cereg_stat == 5)) {
                tr_info("ST87M01: already registered CEREG=%d", cereg_stat);
                return NSAPI_ERROR_OK;
            }
            _at.clear_error();
        }
    }

    return err;
}

nsapi_error_t ST87M01_CellularNetwork::get_signal_quality_cesq(CesqInfo &info)
{
    _at.lock();
    _at.clear_error();
    _at.flush();
    _at.cmd_start_stop("+CESQ", "");
    _at.resp_start("+CESQ: ");
    info.rxlev = _at.read_int();
    info.ber   = _at.read_int();
    info.rscp  = _at.read_int();
    info.ecno  = _at.read_int();
    info.rsrq  = _at.read_int();
    info.rsrp  = _at.read_int();
    _at.resp_stop();

    tr_debug("ST87M01: CESQ rxlev=%d ber=%d rscp=%d ecno=%d rsrq=%d rsrp=%d",
             info.rxlev, info.ber, info.rscp, info.ecno, info.rsrq, info.rsrp);
    return _at.unlock_return_error();
}

nsapi_error_t ST87M01_CellularNetwork::get_signal_quality(int &rssi, int *ber)
{
    CesqInfo cesq;
    nsapi_error_t err = get_signal_quality_cesq(cesq);

    // 3GPP TS 27.007 §8.69: RSRP 0..97 maps to dBm = -140 + value; 255 = unknown.
    if (err == NSAPI_ERROR_OK && cesq.rsrp >= 0 && cesq.rsrp <= 97) {
        rssi = -140 + cesq.rsrp;
        if (ber) {
            *ber = (cesq.ber == 99) ? SignalQualityUnknown : cesq.ber;
        }
        return NSAPI_ERROR_OK;
    }

    rssi = SignalQualityUnknown;
    if (ber) {
        *ber = SignalQualityUnknown;
    }
    return err;
}

nsapi_error_t ST87M01_CellularNetwork::clear()
{
    nsapi_error_t err = AT_CellularNetwork::clear();
#if MBED_CONF_CELLULAR_CONTROL_PLANE_OPT
    if (!err) {
        err = _at.at_cmd_discard("+CGDCONT", "=", "%d", 0);
#ifdef MBED_CONF_NSAPI_DEFAULT_CELLULAR_APN
        err = _at.at_cmd_discard("+CGDCONT", "=", "%d%s%s", 1, "NONIP", MBED_CONF_NSAPI_DEFAULT_CELLULAR_APN);
#endif
        if (!err) {
            err = _at.at_cmd_discard("+CIPCA", "=", "%d%d", 3, 1);
        }
        if (!err) {
            _at.lock();
            _at.cmd_start("AT+NCONFIG=\"AUTOCONNECT\",\"TRUE\"");
            _at.cmd_stop_read_resp();
            err = _at.unlock_return_error();
        }
    }
#endif
    return err;
}

nsapi_error_t ST87M01_CellularNetwork::set_attach()
{
    nsapi_error_t err = AT_CellularNetwork::set_attach();
    if (err == NSAPI_ERROR_OK) {
        tr_info("ST87M01: PS attach ok");
    } else {
        tr_warn("ST87M01: PS attach (err=%d)", err);
    }
    return err;
}
