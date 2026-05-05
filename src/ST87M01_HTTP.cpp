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

#include "rtos/ThisThread.h"

#include "CellularLog.h"

#include "ST87M01_HTTP.h"

using namespace mbed;
using namespace std::chrono;
using namespace std::chrono_literals;

// Maximum HTTP socket id on ST87M01 (AT#SOCKETCREATE allocates ids 0..6).
#define OP_MAX_HTTP_SOCKET_ID  6

ST87M01_HTTP::ST87M01_HTTP(ATHandler &at, int cid)
    : _at(at), _cid(cid), _socket_id(-1), _http_started(false)
{
}

ST87M01_HTTP::~ST87M01_HTTP()
{
    if (_http_started) {
        stop();
    }
}

nsapi_error_t ST87M01_HTTP::attach_socket(int socket_id)
{
    if (socket_id < 0 || socket_id > OP_MAX_HTTP_SOCKET_ID) {
        return NSAPI_ERROR_PARAMETER;
    }

    if (_http_started) {
        tr_warn("ST87M01: HTTP attach on running stack, stopping (sock=%d)", _socket_id);
        stop();
    }

    _socket_id = socket_id;
    tr_debug("ST87M01: HTTP attached sock=%d", socket_id);
    return NSAPI_ERROR_OK;
}

void ST87M01_HTTP::detach_socket()
{
    if (_http_started) {
        stop();
    }
    _socket_id = -1;
}

nsapi_error_t ST87M01_HTTP::start()
{
    if (_socket_id < 0) {
        tr_error("ST87M01: HTTP start, no socket attached");
        return NSAPI_ERROR_NO_SOCKET;
    }

    if (_http_started) {
        return NSAPI_ERROR_OK;
    }

    _at.lock();
    nsapi_error_t err = _at.at_cmd_discard("#HTTPSTART", "");
    _at.unlock();

    if (err == NSAPI_ERROR_OK) {
        _http_started = true;
        tr_info("ST87M01: HTTP started sock=%d", _socket_id);
    } else {
        tr_error("ST87M01: HTTP start sock=%d (err=%d)", _socket_id, err);
    }

    return err;
}

nsapi_error_t ST87M01_HTTP::stop()
{
    if (!_http_started) {
        return NSAPI_ERROR_OK;
    }

    _at.lock();
    nsapi_error_t err = _at.at_cmd_discard("#HTTPSTOP", "");
    _at.unlock();

    _http_started = false;
    return err;
}

nsapi_error_t ST87M01_HTTP::get(const char *host, const char *path, ST87M01_HTTP::Response &response)
{
    if (!_http_started) {
        nsapi_error_t err = start();
        if (err != NSAPI_ERROR_OK) {
            response.error = err;
            return err;
        }
    }

    nsapi_error_t err = send_method(Method::GET, host, path, false);
    if (err != NSAPI_ERROR_OK) {
        response.error = err;
        return err;
    }

    err = send_body("", 0);
    if (err != NSAPI_ERROR_OK) {
        response.error = err;
        return err;
    }

    err = read_response(response);
    response.error = err;
    response.success = (err == NSAPI_ERROR_OK && response.status_code >= 200 && response.status_code < 300);
    return err;
}

nsapi_error_t ST87M01_HTTP::post(const char *host, const char *path, const char *content_type,
                                  const char *body, size_t body_len, ST87M01_HTTP::Response &response)
{
    if (!_http_started) {
        nsapi_error_t err = start();
        if (err != NSAPI_ERROR_OK) {
            response.error = err;
            return err;
        }
    }

    nsapi_error_t err = send_method(Method::POST, host, path, false);
    if (err != NSAPI_ERROR_OK) {
        response.error = err;
        return err;
    }

    if (content_type && content_type[0]) {
        err = send_header("Content-Type", content_type);
        if (err != NSAPI_ERROR_OK) {
            response.error = err;
            return err;
        }
    }

    err = send_body(body, body_len);
    if (err != NSAPI_ERROR_OK) {
        response.error = err;
        return err;
    }

    err = read_response(response);
    response.error = err;
    response.success = (err == NSAPI_ERROR_OK && response.status_code >= 200 && response.status_code < 300);
    return err;
}

nsapi_error_t ST87M01_HTTP::send_method(ST87M01_HTTP::Method method, const char *host, const char *path, bool keep_alive)
{
    const char *method_str = nullptr;
    switch (method) {
        case Method::GET:
            method_str = "GET";
            break;
        case Method::POST:
            method_str = "POST";
            break;
        case Method::PUT:
            method_str = "PUT";
            break;
        case Method::HEAD:
            method_str = "HEAD";
            break;
    }

    _at.lock();

    _at.cmd_start("AT#HTTPMETHOD=");
    _at.write_string(method_str, false);
    _at.write_string(host, false);
    _at.write_string(path, false);
    _at.write_int(keep_alive ? 1 : 0);
    _at.cmd_stop();

    _at.resp_start();
    _at.resp_stop();

    nsapi_error_t err = _at.unlock_return_error();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: #HTTPMETHOD %s failed (err=%d)", method_str, err);
    }
    return err;
}

nsapi_error_t ST87M01_HTTP::send_header(const char *field, const char *value)
{
    _at.lock();

    _at.cmd_start("AT#HTTPHEADER=");
    _at.write_string(field, false);
    _at.write_string(value, false);
    _at.cmd_stop();

    _at.resp_start();
    _at.resp_stop();

    nsapi_error_t err = _at.unlock_return_error();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: #HTTPHEADER %s failed (err=%d)", field, err);
    }
    return err;
}

nsapi_error_t ST87M01_HTTP::send_body(const char *body, size_t len)
{
    _at.lock();

    _at.cmd_start("AT#HTTPSEND=");
    _at.write_int(_cid);
    _at.write_int(_socket_id);

    if (len > 0 && body) {
        _at.write_string(body, true);
    } else {
        _at.write_string("", true);
    }
    _at.cmd_stop();

    _at.resp_start();
    _at.resp_stop();

    nsapi_error_t err = _at.unlock_return_error();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: #HTTPSEND cid=%d sock=%d len=%u (err=%d)", _cid, _socket_id, (unsigned)len, err);
    }
    return err;
}

nsapi_error_t ST87M01_HTTP::read_response(ST87M01_HTTP::Response &response, uint32_t timeout_ms)
{
    response.status_code = 0;
    response.content_length = 0;
    response.body[0] = '\0';
    response.body_length = 0;
    response.success = false;
    response.error = NSAPI_ERROR_OK;

    _at.lock();
    _at.set_at_timeout(timeout_ms);

    // Server response is assembled asynchronously; ~300ms minimum on NB-IoT.
    rtos::ThisThread::sleep_for(500ms);

    _at.cmd_start_stop("#HTTPREAD", "");
    _at.resp_start("#HTTPREAD:");

    int total_read = 0;
    bool got_response = false;

    if (_at.info_resp()) {
        // Firmware places the size in the 1st, 2nd or 3rd field depending on
        // which header/length params are populated; last non-zero wins.
        int param1 = _at.read_int();
        int param2 = _at.read_int();
        int param3 = _at.read_int();

        int data_size = 0;
        if (param3 > 0) {
            data_size = param3;
        } else if (param2 > 0) {
            data_size = param2;
        } else {
            data_size = param1;
        }

        if (data_size > 0) {
            const int max_read = static_cast<int>(sizeof(response.body) - 1);
            int to_read = (data_size < max_read) ? data_size : max_read;

            if (data_size > max_read) {
                tr_warn("ST87M01: HTTP %d > buf %d, truncating", data_size, max_read);
            }

            int bytes_read = _at.read_bytes((uint8_t *)response.body, to_read);
            if (bytes_read > 0) {
                response.body[bytes_read] = '\0';
                response.body_length = bytes_read;
                total_read = bytes_read;
                got_response = true;

                if (data_size > bytes_read) {
                    _at.skip_param_bytes(data_size - bytes_read, 1);
                }

                if (strncmp(response.body, "HTTP/", 5) == 0) {
                    const char *status_start = strchr(response.body, ' ');
                    if (status_start) {
                        response.status_code = atoi(status_start + 1);
                    }
                }

                const char *body_start = strstr(response.body, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    response.content_length = response.body_length - (body_start - response.body);
                }
            }
        }
    }

    _at.resp_stop();
    _at.restore_at_timeout();

    nsapi_error_t err = _at.unlock_return_error();

    if (!got_response) {
        tr_warn("ST87M01: HTTP no response on sock=%d", _socket_id);
        return NSAPI_ERROR_TIMEOUT;
    }

    tr_info("ST87M01: HTTP status=%d size=%d", response.status_code, total_read);
    return err;
}
