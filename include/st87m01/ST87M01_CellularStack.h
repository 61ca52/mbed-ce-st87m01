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

#ifndef ST87M01_CELLULARSTACK_H_
#define ST87M01_CELLULARSTACK_H_

#include "AT_CellularStack.h"
#include "rtos/MemoryPool.h"

#ifndef MBED_CONF_ST87M01_SOCKET_RX_BUFFER_SIZE
#define MBED_CONF_ST87M01_SOCKET_RX_BUFFER_SIZE 2048
#endif

namespace mbed {

/** @addtogroup at-hayes
 *  @ingroup Cellular
 *  @{
 */

/** ST87M01 stack: offloaded TLS, modem-side DNS, per-socket RX buffering.
 *
 *  TLS credentials may come from:
 *    1. mbed_app.json, applied by ST87M01::init_tls().
 *    2. TLSSocket setsockopt(), stored in volatile RAM. */
class ST87M01_CellularStack : public AT_CellularStack {
public:
    /** Hard upper bound on concurrent sockets (PROPERTY_SOCKET_COUNT + 1 for orphan-sweep). */
    static const int OP_MAX_SOCKETS = 7;

    ST87M01_CellularStack(ATHandler &at, int cid, nsapi_ip_stack_t stack_type, AT_CellularDevice &device);
    virtual ~ST87M01_CellularStack();

    virtual nsapi_error_t get_ip_address(SocketAddress *address) override;

    /** Close all sockets tracked by this stack plus orphans on this CID. */
    nsapi_error_t close_all_sockets();

    virtual nsapi_error_t gethostbyname(const char *host, SocketAddress *address, nsapi_version_t version, const char *interface_name) override;

    /** Routes NSAPI_TLSSOCKET_LEVEL options to ST87M01_TlsProvisioning. */
    virtual nsapi_error_t setsockopt(nsapi_socket_t handle, int level, int optname,
                                     const void *optval, unsigned optlen) override;

    /** Select TLS profile (0..15) for the next socket; -1 disables TLS. */
    void set_sslctxid(int sslctxID);

    /** Create a socket with the given TLS profile. */
    nsapi_error_t create_tls_socket(CellularSocket *socket, int sslctxID = -1);

    /** Resolve, open a TCP socket, connect; returns socket id via socket_id_out. */
    nsapi_error_t open_tcp_session(int &socket_id_out, const char *host, uint16_t port, bool use_tls = false);

    /** Close a TCP session by socket id. */
    nsapi_error_t close_tcp_session(int socket_id);

protected:
    virtual nsapi_error_t socket_listen(nsapi_socket_t handle, int backlog) override;
    virtual nsapi_error_t socket_accept(nsapi_socket_t server, nsapi_socket_t *handle, SocketAddress *address = 0) override;
    virtual nsapi_error_t socket_connect(nsapi_socket_t handle, const SocketAddress &address) override;
    virtual nsapi_error_t socket_close_impl(int sock_id) override;
    virtual nsapi_error_t create_socket_impl(CellularSocket *socket) override;
    virtual nsapi_size_or_error_t socket_sendto_impl(CellularSocket *socket, const SocketAddress &address,
                                                     const void *data, nsapi_size_t size) override;
    virtual nsapi_size_or_error_t socket_recvfrom_impl(CellularSocket *socket, SocketAddress *address,
                                                       void *buffer, nsapi_size_t size) override;

    /** TLS-aware variant; the public create_socket_impl() forwards here. */
    nsapi_error_t create_socket_impl(CellularSocket *socket, int sslctxID);

private:
    /** Per-socket RX scratch. Modem delivers one AT response per segment;
     *  TLSSocket reads header then payload, so leftover bytes must be buffered. */
    struct SocketRxBuffer {
        uint8_t data[MBED_CONF_ST87M01_SOCKET_RX_BUFFER_SIZE];
        size_t head;
        size_t tail;

        void reset() { head = tail = 0; }
        size_t available() const { return tail - head; }
        bool empty() const { return head >= tail; }
    };

    void urc_iprecv();
    void urc_nb_sent();
    void urc_socketclosed();
    void txfull_event_timeout();

    /** Activate the modem IP stack for our CID when not already active. */
    nsapi_error_t ensure_ip_configured();

    /** Close any sockets the modem still holds on our CID; empty on
     *  a clean reboot. Locks _at internally. */
    void reap_orphan_sockets();

    /** Return AT#TCPCONNECT? <status> for sock_id (UM §9.11: 3 not-connected,
     *  4 connecting, 5 connected, 6 closing); -1 if not found.
     *  Caller holds _at.lock(). */
    int query_tcp_status(int sock_id);

    bool allocate_rx_buffer(int socket_id);
    void free_rx_buffer(int socket_id);

    events::EventQueue *_event_queue;
    int _txfull_event_id;
    int _sslctxID;
    int _socket_sslctxID[OP_MAX_SOCKETS];
    rtos::MemoryPool<SocketRxBuffer, OP_MAX_SOCKETS> _rx_buf_pool;
    SocketRxBuffer *_rx_buf[OP_MAX_SOCKETS];
    bool _ip_configured;
};

/** @}*/

} // namespace mbed
#endif /* ST87M01_CELLULARSTACK_H_ */
