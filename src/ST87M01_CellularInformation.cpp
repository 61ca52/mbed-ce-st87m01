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

#include "ST87M01_CellularInformation.h"

namespace mbed {

ST87M01_CellularInformation::ST87M01_CellularInformation(ATHandler &at, AT_CellularDevice &device)
    : AT_CellularInformation(at, device)
{
}

ST87M01_CellularInformation::~ST87M01_CellularInformation()
{
}

nsapi_error_t ST87M01_CellularInformation::get_iccid(char *buf, size_t buf_size)
{
    return _at.at_cmd_str("+NCCID", "?", buf, buf_size);
}

// ATI yields three lines before OK:
//   line 1: STMICROELECTRONICS  (manufacturer)
//   line 2: ST87M01             (model)
//   line 3: <software_version>  (revision)
nsapi_error_t ST87M01_CellularInformation::get_manufacturer(char *buf, size_t buf_size)
{
    _at.lock();
    _at.flush();
    _at.cmd_start("ATI");
    _at.cmd_stop();
    _at.resp_start();
    _at.read_string(buf, buf_size);
    _at.resp_stop();

    nsapi_error_t err = _at.get_last_error();
    _at.unlock();
    return err;
}

nsapi_error_t ST87M01_CellularInformation::get_model(char *buf, size_t buf_size)
{
    _at.lock();
    _at.flush();
    _at.cmd_start("ATI");
    _at.cmd_stop();
    _at.resp_start();
    _at.skip_param();
    _at.read_string(buf, buf_size);
    _at.resp_stop();

    nsapi_error_t err = _at.get_last_error();
    _at.unlock();
    return err;
}

nsapi_error_t ST87M01_CellularInformation::get_revision(char *buf, size_t buf_size)
{
    _at.lock();
    _at.flush();
    _at.cmd_start("ATI");
    _at.cmd_stop();
    _at.resp_start();
    _at.skip_param(2);
    _at.read_string(buf, buf_size);
    _at.resp_stop();

    nsapi_error_t err = _at.get_last_error();
    _at.unlock();
    return err;
}

} // namespace mbed
