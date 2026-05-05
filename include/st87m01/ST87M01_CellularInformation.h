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

#ifndef ST87M01_CELLULARINFORMATION_H_
#define ST87M01_CELLULARINFORMATION_H_

#include "AT_CellularInformation.h"

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

/** CellularInformation for ST87M01; uses +NCCID and ATI parsing. */
class ST87M01_CellularInformation : public AT_CellularInformation {
public:
    ST87M01_CellularInformation(ATHandler &at, AT_CellularDevice &device);
    virtual ~ST87M01_CellularInformation();

    virtual nsapi_error_t get_iccid(char *buf, size_t buf_size) override;
    virtual nsapi_error_t get_manufacturer(char *buf, size_t buf_size) override;
    virtual nsapi_error_t get_model(char *buf, size_t buf_size) override;
    virtual nsapi_error_t get_revision(char *buf, size_t buf_size) override;
};

/** @}*/

} // namespace mbed

#endif /* ST87M01_CELLULARINFORMATION_H_ */
