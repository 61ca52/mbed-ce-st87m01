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

#ifndef ST87M01_HTTP_H_
#define ST87M01_HTTP_H_

#include "mbed.h"
#include "ATHandler.h"
#include "CellularContext.h"

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

/** Modem-side HTTP/HTTPS client over AT#HTTP* commands.
 *
 *  Obtain via ST87M01_CellularContext::get_http_client(). Operates on sockets
 *  from ST87M01_CellularStack. For HTTPS, provision the default TLS profile
 *  via ST87M01::get_tls_provisioning() before connecting. */
class ST87M01_HTTP {
public:
    /** HTTP verbs supported by AT#HTTPMETHOD. */
    enum class Method {
        GET,
        POST,
        PUT,
        HEAD
    };

    /** Parsed modem response; body[] holds raw header+body from AT#HTTPREAD. */
    struct Response {
        int status_code = 0;
        int content_length = 0;
        char body[1400] = {0};
        int body_length = 0;
        bool success = false;
        nsapi_error_t error = NSAPI_ERROR_OK;
    };

    ST87M01_HTTP(ATHandler &at, int cid = 5);
    ~ST87M01_HTTP();

    /** Bind to a connected socket; ownership stays with the caller. */
    nsapi_error_t attach_socket(int socket_id);

    /** Start the modem HTTP stack; requires an attached socket. */
    nsapi_error_t start();

    /** Stop the modem HTTP stack; underlying socket stays open. */
    nsapi_error_t stop();

    bool is_started() const { return _http_started; }
    int get_socket_id() const { return _socket_id; }

    nsapi_error_t get(const char *host, const char *path, Response &response);
    nsapi_error_t post(const char *host, const char *path, const char *content_type,
                       const char *body, size_t body_len, Response &response);

    /** Detach from current socket; stops the HTTP stack if running. */
    void detach_socket();

private:
    nsapi_error_t send_method(Method method, const char *host, const char *path, bool keep_alive);
    nsapi_error_t send_header(const char *field, const char *value);
    nsapi_error_t send_body(const char *body, size_t len);
    nsapi_error_t read_response(Response &response, uint32_t timeout_ms = 30000);

    ATHandler &_at;
    int _cid;
    int _socket_id;
    bool _http_started;
};

/** @}*/

} // namespace mbed

#endif // ST87M01_HTTP_H_
