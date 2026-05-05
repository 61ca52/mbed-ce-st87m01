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

#ifndef ST87M01_CELLULARNETWORK_H_
#define ST87M01_CELLULARNETWORK_H_

#include "AT_CellularNetwork.h"

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

/** CellularNetwork for ST87M01; NB-IoT only (RAT_NB1). */
class ST87M01_CellularNetwork : public AT_CellularNetwork {
public:
    ST87M01_CellularNetwork(ATHandler &at, AT_CellularDevice &device);
    virtual ~ST87M01_CellularNetwork() = default;

    /** Raw +CESQ record; RSRP 255 = unknown. */
    struct CesqInfo {
        int rxlev;
        int ber;
        int rscp;
        int ecno;
        int rsrq;
        int rsrp;
    };

    /** Return the raw CESQ record in one AT transaction. */
    nsapi_error_t get_signal_quality_cesq(CesqInfo &info);

protected:
    virtual nsapi_error_t set_access_technology_impl(RadioAccessTechnology op_rat) override;
    virtual nsapi_error_t get_signal_quality(int &rssi, int *ber) override;
    virtual nsapi_error_t set_attach() override;
    virtual nsapi_error_t set_registration(const char *plmn = 0) override;
    virtual nsapi_error_t clear() override;
};

/** @}*/

} // namespace mbed
#endif // ST87M01_CELLULARNETWORK_H_
