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

#ifndef ST87M01_CELLULARCONTEXT_H_
#define ST87M01_CELLULARCONTEXT_H_

#include "AT_CellularContext.h"

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

class ST87M01_HTTP;
class ST87M01_CellularStack;

/** CellularContext for ST87M01. Reuses existing PDP contexts (the modem
 *  auto-activates CID 5/6 on attach) and exposes the modem-side HTTP client
 *  attached to the active socket. */
class ST87M01_CellularContext : public AT_CellularContext {
public:
    ST87M01_CellularContext(ATHandler &at, CellularDevice *device, const char *apn, bool cp_req = false, bool nonip_req = false);
    virtual ~ST87M01_CellularContext();

    virtual nsapi_error_t get_ip_address(SocketAddress *address) override;

    /** Close all sockets tracked by the underlying stack. */
    nsapi_error_t close_all_sockets();

    /** HTTP client bound to this context's CID (lazy). */
    ST87M01_HTTP *get_http_client();

    /** Return the ST87M01 stack for advanced socket operations. */
    ST87M01_CellularStack *get_st87_stack();

    /** Open an HTTP/HTTPS session: create TCP socket, connect, start the
     *  modem HTTP stack. HTTPS uses the default TLS profile. */
    nsapi_error_t http_open(const char *host, uint16_t port, bool use_tls = false);

    /** Stop the HTTP stack and close the underlying socket. */
    nsapi_error_t http_close();

    bool http_is_open() const { return _http_socket_id >= 0; }

protected:
#if !NSAPI_PPP_AVAILABLE
    virtual NetworkStack *get_stack() override;
#endif
    virtual const char *get_nonip_context_type_str() override;
    virtual bool get_context() override;
    virtual void deactivate_context() override;

private:
    static pdp_type_t configured_pdp_type();
    static pdp_type_t parse_pdp_type(const char *str);
    static const char *pdp_type_to_str(pdp_type_t t);
    int select_existing_cid(pdp_type_t &pdp_type_out, char *apn_out, size_t apn_len);

    ST87M01_HTTP *_http_client;
    int _http_socket_id;
};

/** @}*/

} // namespace mbed

#endif // ST87M01_CELLULARCONTEXT_H_
