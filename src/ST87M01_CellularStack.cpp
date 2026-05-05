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
#include "events/EventQueue.h"
#include "events/mbed_shared_queues.h"
#include "platform/mbed_atomic.h"

#include "mbed_assert.h"
#include "mbed_error.h"
#include "netsocket/nsapi_types.h"

#include "CellularLog.h"
#include "CellularUtil.h"

#include "ST87M01.h"
#include "ST87M01_CellularStack.h"
#include "ST87M01_TlsProvisioning.h"

// Per ST UM #IPSENDUDP/#IPSENDTCP max fragment is 1400 bytes over PPP-less path.
#define OP_PACKET_SIZE_MAX     1400
#define OP_TXFULL_RETRY_DELAY  1s

// AT#TCPCONNECT= may CME-2152 on warm MCU restart when RRC setup exceeds the
// modem's internal 10 s timer; a second attempt completes quickly once RRC is up.
#define OP_TCP_CONNECT_ATTEMPTS  2
#define OP_TCP_RETRY_BACKOFF     500ms
#define OP_TCP_POLL_INTERVAL     500ms

// Vendor CME error codes, from ST87M01 UM section "Socket error reporting".
#define OP_CME_UPLINK_BUSY        159
#define OP_CME_UART_BUFFER_ERROR  536
#define OP_CME_BACK_OFF_TIMER     537

using namespace std::chrono;
using namespace mbed;
using namespace mbed_cellular_util;

ST87M01_CellularStack::ST87M01_CellularStack(ATHandler &at, int cid, nsapi_ip_stack_t stack_type, AT_CellularDevice &device)
    : AT_CellularStack(at, cid, stack_type, device),
      _event_queue(mbed_event_queue()),
      _txfull_event_id(0),
      _sslctxID(MBED_CONF_ST87M01_TLS_DEFAULT_SSLCTXID),
      _ip_configured(false)
{
    MBED_ASSERT(_sslctxID > -1 && _sslctxID < 16);

    for (int i = 0; i < OP_MAX_SOCKETS; i++) {
        _socket_sslctxID[i] = -1;
        _rx_buf[i] = nullptr;
    }

    _at.set_urc_handler("#IPRECV:", mbed::Callback<void()>(this, &ST87M01_CellularStack::urc_iprecv));
    _at.set_urc_handler("NB_SENT", mbed::Callback<void()>(this, &ST87M01_CellularStack::urc_nb_sent));
    _at.set_urc_handler("#SOCKETCLOSED:", mbed::Callback<void()>(this, &ST87M01_CellularStack::urc_socketclosed));

    // Modelled on ST ECLIB (st87ec_sequence_nbiot.c:1698): on a crashed prior session
    // a socket may still be assigned on this CID. Enumerate and close them so we start
    // with a clean slot allocation. Skipped silently when the list is empty (clean reboot).
    reap_orphan_sockets();
}

ST87M01_CellularStack::~ST87M01_CellularStack()
{
    if (_txfull_event_id) {
        _event_queue->cancel(_txfull_event_id);
    }

    for (int i = 0; i < OP_MAX_SOCKETS; i++) {
        free_rx_buffer(i);
    }

    _at.set_urc_handler("#IPRECV:", nullptr);
    _at.set_urc_handler("NB_SENT", nullptr);
    _at.set_urc_handler("#SOCKETCLOSED:", nullptr);
}

nsapi_error_t ST87M01_CellularStack::get_ip_address(SocketAddress *address)
{
    if (!address) {
        return NSAPI_ERROR_PARAMETER;
    }

    if (_cid < 0) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    _at.lock();

    char ip[NSAPI_IP_SIZE + 1] = {0};
    _at.cmd_start_stop("+CGPADDR", "=", "%d", _cid);
    _at.resp_start("+CGPADDR:");
    if (_at.info_resp()) {
        _at.skip_param();
        _at.read_string(ip, sizeof(ip));
    }
    _at.resp_stop();

    nsapi_error_t err = _at.get_last_error();

    // +CGPADDR sometimes returns empty on dual-stack contexts; fall back to
    // +CGCONTRDP, which carries the same address plus the netmask.
    if (err != NSAPI_ERROR_OK || ip[0] == '\0') {
        _at.clear_error();

        _at.cmd_start_stop("+CGCONTRDP", "=", "%d", _cid);
        _at.resp_start("+CGCONTRDP:");
        if (_at.info_resp()) {
            _at.skip_param(2);
            char apn[MAX_ACCESSPOINT_NAME_LENGTH] = {0};
            _at.read_string(apn, sizeof(apn));

            char ipv6_and_mask[128] = {0};
            _at.read_string(ipv6_and_mask, sizeof(ipv6_and_mask));

            char *sep = strpbrk(ipv6_and_mask, ",/");
            if (sep) {
                *sep = '\0';
            }

            if (ipv6_and_mask[0]) {
                strncpy(ip, ipv6_and_mask, sizeof(ip) - 1);
            }
        }
        _at.resp_stop();
        err = _at.get_last_error();
    }

    _at.unlock();

    if (err != NSAPI_ERROR_OK || ip[0] == '\0') {
        tr_error("ST87M01: no IP for cid=%d (err=%d)", _cid, err);
        return NSAPI_ERROR_NO_CONNECTION;
    }

    address->set_ip_address(ip);
    tr_info("ST87M01: cid=%d ip=%s", _cid, ip);
    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01_CellularStack::close_all_sockets()
{
    tr_info("ST87M01: closing all sockets on cid=%d", _cid);
    nsapi_error_t last_err = NSAPI_ERROR_OK;

    _at.lock();

    for (int sock_id = 0; sock_id < OP_MAX_SOCKETS; sock_id++) {
        CellularSocket *driver_sock = find_socket(sock_id);

        if (driver_sock) {
            if (!driver_sock->closed && driver_sock->id >= 0) {
                nsapi_error_t err = _at.at_cmd_discard("#SOCKETCLOSE", "=", "%d,%d", _cid, sock_id);
                if (err != NSAPI_ERROR_OK) {
                    tr_warn("ST87M01: close socket %d failed (err=%d)", sock_id, err);
                    last_err = err;
                } else {
                    driver_sock->closed = true;
                }
            }
        } else {
            // Sweep slots from a prior session; CME on never-opened slots is fine.
            nsapi_error_t err = _at.at_cmd_discard("#SOCKETCLOSE", "=", "%d,%d", _cid, sock_id);
            if (err != NSAPI_ERROR_OK) {
                device_err_t dev_err = _at.get_last_device_error();
                if (dev_err.errType != DeviceErrorTypeErrorCME) {
                    tr_warn("ST87M01: close untracked sock=%d failed (err=%d)", sock_id, err);
                    last_err = err;
                }
                _at.clear_error();
            }
        }
    }

    _at.unlock();
    return last_err;
}

nsapi_error_t ST87M01_CellularStack::gethostbyname(const char *host, SocketAddress *address, nsapi_version_t version, const char *interface_name)
{
    if (!host || !address) {
        return NSAPI_ERROR_PARAMETER;
    }

    _at.lock();
    _at.clear_error();

    const int ip_mode = (version == NSAPI_IPv6) ? 1 : 0;
    char ipbuf[NSAPI_IP_SIZE + 1] = {0};
    int ttl = 0;
    bool got_dns = false;

    // AT#DNS expects an unquoted host. Worst-case resolution 60s on NB-IoT.
    _at.set_at_timeout(60000, false);

    _at.cmd_start("AT#DNS=");
    _at.write_int(_cid);
    _at.write_int(ip_mode);
    _at.write_string(host, false);
    _at.cmd_stop();

    _at.resp_start("#DNS:");
    if (_at.info_resp()) {
        _at.read_string(ipbuf, sizeof(ipbuf));
        ttl = _at.read_int();
        got_dns = (ipbuf[0] != '\0');
    }
    _at.restore_at_timeout();
    _at.resp_stop();

    nsapi_error_t err = _at.get_last_error();
    if (got_dns && err != NSAPI_ERROR_OK) {
        // Some firmware raises a spurious error after a valid #DNS result.
        _at.clear_error();
        err = NSAPI_ERROR_OK;
    }

    _at.unlock();

    if (err != NSAPI_ERROR_OK || !got_dns) {
        tr_error("ST87M01: DNS lookup %s failed (err=%d)", host, err);
        return NSAPI_ERROR_DNS_FAILURE;
    }

    address->set_ip_address(ipbuf);
    tr_info("ST87M01: DNS %s -> %s ttl=%d", host, ipbuf, ttl);
    return NSAPI_ERROR_OK;
}

void ST87M01_CellularStack::set_sslctxid(int sslctxID)
{
    if (sslctxID >= -1 && sslctxID <= 15) {
        _sslctxID = sslctxID;
    } else {
        _sslctxID = MBED_CONF_ST87M01_TLS_DEFAULT_SSLCTXID;
    }
    tr_debug("ST87M01: sslctxID for next socket=%d", sslctxID);
}

nsapi_error_t ST87M01_CellularStack::create_tls_socket(CellularSocket *socket, int sslctxID)
{
    if (sslctxID < 0 || sslctxID > 16) {
        sslctxID = _sslctxID;
    }
    return create_socket_impl(socket, sslctxID);
}

nsapi_error_t ST87M01_CellularStack::open_tcp_session(int &socket_id_out, const char *host, uint16_t port, bool use_tls)
{
    socket_id_out = -1;

    if (!host || host[0] == '\0') {
        return NSAPI_ERROR_PARAMETER;
    }

    SocketAddress addr;
    nsapi_error_t err = gethostbyname(host, &addr, NSAPI_IPv4, nullptr);
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: DNS %s failed (err=%d)", host, err);
        return err;
    }
    addr.set_port(port);

    nsapi_socket_t sock = nullptr;
    err = socket_open(&sock, NSAPI_TCP);
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: socket_open failed (err=%d)", err);
        return err;
    }

    CellularSocket *cell_sock = static_cast<CellularSocket *>(sock);
    if (use_tls) {
        cell_sock->tls_socket = true;
    }

    err = socket_connect(sock, addr);
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: connect %s:%u failed (err=%d)", addr.get_ip_address(), port, err);
        socket_close(sock);
        return err;
    }

    socket_id_out = cell_sock->id;
    tr_info("ST87M01: TCP session sock=%d %s:%u tls=%d", socket_id_out, host, port, use_tls);
    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01_CellularStack::close_tcp_session(int socket_id)
{
    if (socket_id < 0 || socket_id >= OP_MAX_SOCKETS) {
        return NSAPI_ERROR_PARAMETER;
    }

    CellularSocket *sock = find_socket(socket_id);
    if (!sock) {
        _at.lock();
        nsapi_error_t err = _at.at_cmd_discard("#SOCKETCLOSE", "=", "%d,%d", _cid, socket_id);
        _at.unlock();
        return err;
    }

    _at.lock();
    nsapi_error_t err = socket_close_impl(socket_id);
    _at.unlock();
    return err;
}

nsapi_error_t ST87M01_CellularStack::socket_listen(nsapi_socket_t handle, int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

nsapi_error_t ST87M01_CellularStack::socket_accept(nsapi_socket_t server, nsapi_socket_t *handle, SocketAddress *address)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

nsapi_error_t ST87M01_CellularStack::socket_connect(nsapi_socket_t handle, const SocketAddress &address)
{
    CellularSocket *socket = (CellularSocket *)handle;
    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    _at.lock();

    if (socket->id == -1) {
        int sslctxID = socket->tls_socket ? _sslctxID : -1;
        const nsapi_error_t error_create = create_socket_impl(socket, sslctxID);
        if (error_create != NSAPI_ERROR_OK) {
            _at.unlock();
            return error_create;
        }
    }

    if (socket->proto == NSAPI_TCP) {
        /* AT#TCPCONNECT? <status> per UM §9.11:
         *   3 not-connected, 4 connecting, 5 connected, 6 closing.
         * Warm restart in RRC IDLE: connect can CME-2152 because the modem's
         * 10 s timer fires before RACH + RRC + SYN. The attempt itself wakes
         * RRC, so a second attempt usually succeeds in ~2 s. */
        const int connect_timeout_ms = socket->tls_socket ? 65000 : 15000;
        int status = query_tcp_status(socket->id);
        bool connected = (status == 5);
        nsapi_error_t last_conn_err = NSAPI_ERROR_OK;

        for (int attempt = 0; !connected && attempt < OP_TCP_CONNECT_ATTEMPTS; attempt++) {
            if (status == 6) {
                tr_warn("ST87M01: TCP socket=%d in closing state", socket->id);
                break;
            }

            if (status == 4) {
                // Already in flight; poll instead of duplicating.
                auto deadline = rtos::Kernel::Clock::now() + milliseconds(connect_timeout_ms);
                while (status == 4 && rtos::Kernel::Clock::now() < deadline) {
                    rtos::ThisThread::sleep_for(OP_TCP_POLL_INTERVAL);
                    status = query_tcp_status(socket->id);
                }
                connected = (status == 5);
                continue;
            }

            // status 3 or unknown: issue the connect.
            _at.set_at_timeout(connect_timeout_ms, false);
            _at.cmd_start("AT#TCPCONNECT=");
            _at.write_int(_cid);
            _at.write_int(socket->id);
            _at.write_string(address.get_ip_address(), false);
            _at.write_int(address.get_port());
            _at.cmd_stop();
            _at.resp_start();
            _at.resp_stop();
            _at.restore_at_timeout();

            last_conn_err = _at.get_last_error();
            if (last_conn_err != NSAPI_ERROR_OK) {
                _at.clear_error();
            }

            // Status is authoritative regardless of OK/CME from AT#TCPCONNECT=.
            status = query_tcp_status(socket->id);
            connected = (status == 5);

            if (!connected && attempt + 1 < OP_TCP_CONNECT_ATTEMPTS) {
                tr_warn("ST87M01: TCP connect attempt %d (err=%d status=%d), retrying",
                        attempt + 1, last_conn_err, status);
                // Back-off so +CSCON:1 settles before the next attempt.
                rtos::ThisThread::sleep_for(OP_TCP_RETRY_BACKOFF);
            }
        }

        if (!connected) {
            tr_error("ST87M01: TCP connect failed socket=%d dst=%s:%u status=%d err=%d",
                     socket->id, address.get_ip_address(), address.get_port(), status, last_conn_err);
            _at.unlock();
            return NSAPI_ERROR_NO_CONNECTION;
        }

        tr_info("ST87M01: TCP socket=%d connected %s:%u status=%d",
                socket->id, address.get_ip_address(), address.get_port(), status);
    }

    _at.unlock();

    socket->remoteAddress = address;
    socket->connected = true;
    return NSAPI_ERROR_OK;
}

nsapi_error_t ST87M01_CellularStack::socket_close_impl(int sock_id)
{
    CellularSocket *sock = find_socket(sock_id);

    if (sock && sock->closed) {
        return NSAPI_ERROR_OK;
    }

    if (sock) {
        sock->txfull_event = false;
    }

    nsapi_error_t err = _at.at_cmd_discard("#SOCKETCLOSE", "=", "%d,%d", _cid, sock_id);

    if (sock_id >= 0 && sock_id < OP_MAX_SOCKETS) {
        _socket_sslctxID[sock_id] = -1;
        free_rx_buffer(sock_id);
    }

    tr_info("ST87M01: socket %d closed (err=%d)", sock_id, err);
    return err;
}

nsapi_error_t ST87M01_CellularStack::create_socket_impl(CellularSocket *socket)
{
    int sslctxID = socket->tls_socket ? _sslctxID : -1;
    return create_socket_impl(socket, sslctxID);
}

nsapi_error_t ST87M01_CellularStack::create_socket_impl(CellularSocket *socket, int sslctxID)
{
    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    // When cold-init is skipped, the IP stack may not be auto-active.
    nsapi_error_t ip_err = ensure_ip_configured();
    if (ip_err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: IP stack not configured (err=%d)", ip_err);
        return ip_err;
    }

    int sock_id = -1;
    const char *socket_type = nullptr;

    if (socket->proto == NSAPI_UDP) {
        socket_type = "UDP";
    } else if (socket->proto == NSAPI_TCP) {
        socket_type = "TCP";
    } else {
        return NSAPI_ERROR_PARAMETER;
    }

    int ip_version = (_ip_ver_sendto == NSAPI_IPv6) ? 1 : 0;

    uint16_t local_port = socket->localAddress.get_port();
    if (local_port > 49407) {
        local_port = 0;
    }

    // 60s covers worst-case NB-IoT TLS handshake; 10s is fine for cleartext.
    int send_timeout = (sslctxID >= 0) ? 60 : 10;
    int receive_timeout = (sslctxID >= 0) ? 60 : 10;

    // AT#SOCKETCREATE=<cid>,<ip_ver>,<type>,<local_port>,<send_to>,<recv_to>,<urc>[,<sslctxID>]
    _at.cmd_start("AT#SOCKETCREATE=");
    _at.write_int(_cid);
    _at.write_int(ip_version);
    _at.write_string(socket_type, false);
    if (local_port == 0) {
        _at.write_string("", false);
    } else {
        _at.write_int(local_port);
    }
    _at.write_int(send_timeout);
    _at.write_int(receive_timeout);
    _at.write_int(1);

    if (sslctxID >= 0) {
        _at.write_int(sslctxID);
    }
    _at.cmd_stop();

    _at.resp_start("#SOCKETCREATE:");
    if (_at.info_resp()) {
        sock_id = _at.read_int();
    }
    _at.resp_stop();

    bool ok = (_at.get_last_error() == NSAPI_ERROR_OK);

    if (!ok || (sock_id == -1)) {
        tr_error("ST87M01: socket create failed id=%d proto=%s sslctxID=%d", sock_id, socket_type, sslctxID);
        return NSAPI_ERROR_NO_SOCKET;
    }

    if (sock_id >= 0 && sock_id < OP_MAX_SOCKETS) {
        _socket_sslctxID[sock_id] = sslctxID;
        if (!allocate_rx_buffer(sock_id)) {
            tr_error("ST87M01: rx-buffer alloc failed for socket %d", sock_id);
            _at.at_cmd_discard("#SOCKETCLOSE", "=", "%d,%d", _cid, sock_id);
            return NSAPI_ERROR_NO_MEMORY;
        }
    }

    socket->id = sock_id;
    socket->started = true;

    tr_info("ST87M01: socket created id=%d proto=%s sslctxID=%d", sock_id, socket_type, sslctxID);
    return NSAPI_ERROR_OK;
}

nsapi_size_or_error_t ST87M01_CellularStack::socket_sendto_impl(CellularSocket *socket, const SocketAddress &address,
                                                                const void *data, nsapi_size_t size)
{
    MBED_ASSERT(socket->id != -1);

    if (socket->closed) {
        tr_warn("ST87M01: send on sock=%d, closed by remote", socket->id);
        return NSAPI_ERROR_CONNECTION_LOST;
    }

    // UDP connect() does not populate remoteAddress; capture for recvfrom_impl.
    if (socket->proto == NSAPI_UDP) {
        socket->remoteAddress = address;
        socket->connected = true;
    }

    // IP-version change drops a TCP connection; reopen UDP only.
    if (socket->proto == NSAPI_UDP && _ip_ver_sendto != address.get_ip_version()) {
        _ip_ver_sendto = address.get_ip_version();
        socket_close_impl(socket->id);
        create_socket_impl(socket, _socket_sslctxID[socket->id]);
    }

    if (size > OP_PACKET_SIZE_MAX) {
        tr_warn("ST87M01: payload %u > max %d, truncating", size, OP_PACKET_SIZE_MAX);
        size = OP_PACKET_SIZE_MAX;
    }

    int retry = 0;
    static const char HEX_CHARS[] = "0123456789ABCDEF";

retry_send:
    _at.set_at_timeout(15000, false);

    if (socket->proto == NSAPI_UDP) {
        // AT#IPSENDUDP=<cid>,<sock>,<ip>,<port>,<rai>,<data_type>,[<len>,]<data>
        // data_type=2 = hex-encoded payload, keeps binary intact over AT.
        _at.cmd_start("AT#IPSENDUDP=");
        _at.write_int(_cid);
        _at.write_int(socket->id);
        _at.write_string(address.get_ip_address(), false);
        _at.write_int(address.get_port());
        _at.write_int(0);
        _at.write_int(2);
    } else if (socket->proto == NSAPI_TCP) {
        // AT#IPSENDTCP=<cid>,<sock>,<data_type>,[<len>,]<data>
        _at.cmd_start("AT#IPSENDTCP=");
        _at.write_int(_cid);
        _at.write_int(socket->id);
        _at.write_int(2);
    } else {
        return NSAPI_ERROR_PARAMETER;
    }

    _at.write_bytes((const uint8_t *)",", 1);

    const uint8_t *src = (const uint8_t *)data;
    for (nsapi_size_t i = 0; i < size; i++) {
        char hex_byte[2];
        hex_byte[0] = HEX_CHARS[(src[i] >> 4) & 0x0F];
        hex_byte[1] = HEX_CHARS[src[i] & 0x0F];
        _at.write_bytes((const uint8_t *)hex_byte, 2);
    }

    _at.cmd_stop();
    _at.resp_start();
    _at.resp_stop();
    _at.restore_at_timeout();

    if (_at.get_last_error() == NSAPI_ERROR_OK) {
        return size;
    }

    // Transient congestion: UART buffer full, back-off active, uplink busy.
    // Burst-retry for UDP; raise WOULD_BLOCK for TCP and let the socket layer wake.
    device_err_t err = _at.get_last_device_error();
    if ((err.errType == DeviceErrorTypeErrorCME && (err.errCode == OP_CME_UART_BUFFER_ERROR || err.errCode == OP_CME_BACK_OFF_TIMER)) ||
        err.errCode == OP_CME_UPLINK_BUSY) {
        if (socket->proto == NSAPI_UDP) {
            if (retry < 3) {
                retry++;
                tr_warn("ST87M01: sock=%d sendto EAGAIN, retry %d", socket->id, retry);
                rtos::ThisThread::sleep_for(30ms);
                _at.clear_error();
                goto retry_send;
            }
            return NSAPI_ERROR_NO_MEMORY;
        }

        _socket_mutex.lock();
        if (!socket->txfull_event && !_txfull_event_id) {
            tr_warn("ST87M01: sock=%d TX full", socket->id);
            socket->txfull_event = true;
            _txfull_event_id = _event_queue->call_in(OP_TXFULL_RETRY_DELAY, callback(this, &ST87M01_CellularStack::txfull_event_timeout));
            if (!_txfull_event_id) {
                MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_DRIVER, MBED_ERROR_CODE_ENOMEM),
                           "ST87M01_CellularStack::socket_sendto_impl(): unable to add event to queue.\n");
                _socket_mutex.unlock();
                return NSAPI_ERROR_NO_MEMORY;
            }
        }
        _socket_mutex.unlock();
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    return _at.get_last_error();
}

nsapi_size_or_error_t ST87M01_CellularStack::socket_recvfrom_impl(CellularSocket *socket, SocketAddress *address,
                                                                  void *buffer, nsapi_size_t size)
{
    MBED_ASSERT(socket->id != -1);

    const int sock_id = socket->id;
    if (sock_id < 0 || sock_id >= OP_MAX_SOCKETS) {
        return NSAPI_ERROR_PARAMETER;
    }

    if (socket->closed) {
        return NSAPI_ERROR_CONNECTION_LOST;
    }

    const bool is_udp = (socket->proto == NSAPI_UDP);
    SocketRxBuffer *rxbuf = _rx_buf[sock_id];

    // TCP: drain leftover from prior #IPREAD before issuing a new one.
    // UDP: leftover is stale; reset.
    if (rxbuf != nullptr && !rxbuf->empty()) {
        if (is_udp) {
            rxbuf->reset();
        } else {
            size_t avail = rxbuf->available();
            size_t to_copy = (avail < size) ? avail : size;
            memcpy(buffer, rxbuf->data + rxbuf->head, to_copy);
            rxbuf->head += to_copy;

            if (rxbuf->empty()) {
                rxbuf->reset();
            }

            tr_debug("ST87M01: sock=%d recv %u from buf (%u left)", sock_id, to_copy, rxbuf->available());
            return static_cast<nsapi_size_or_error_t>(to_copy);
        }
    }

    if (socket->pending_bytes == 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    int data_len = 0;

    _at.cmd_start_stop("#IPREAD", "=", "%d,%d", _cid, sock_id);
    _at.resp_start("#IPREAD:");
    if (_at.info_resp()) {
        _at.skip_param();
        _at.skip_param();
        data_len = _at.read_int();
    }

    if (data_len <= 0 || _at.get_last_error() != NSAPI_ERROR_OK) {
        _at.resp_stop();
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    nsapi_size_or_error_t returned = 0;

    if (is_udp) {
        // RFC 768: one datagram per call; truncate to caller buffer.
        const nsapi_size_t copy_len = (static_cast<nsapi_size_t>(data_len) < size)
                                          ? static_cast<nsapi_size_t>(data_len) : size;
        nsapi_size_or_error_t read_ret = _at.read_bytes(static_cast<uint8_t *>(buffer), copy_len);

        if (read_ret > 0 && _at.get_last_error() == NSAPI_ERROR_OK) {
            const int overflow = data_len - read_ret;
            if (overflow > 0) {
                tr_warn("ST87M01: sock=%d UDP %d > buf %u, truncating", sock_id, data_len, (unsigned)size);
                _at.skip_param_bytes(overflow, 1);
            }
            _at.skip_param_bytes(2, 1);
            returned = read_ret;

            // #IPREAD omits the source. Sockets here are connected, so the peer
            // is the remoteAddress captured in socket_sendto_impl.
            if (address) {
                *address = socket->remoteAddress;
            }
        }
    } else {
        // TCP: buffer the segment, hand back up to `size`, retain the rest.
        if (rxbuf == nullptr) {
            tr_error("ST87M01: sock=%d no rx buffer", sock_id);
            _at.resp_stop();
            _socket_mutex.lock();
            socket->pending_bytes = 0;
            _socket_mutex.unlock();
            return NSAPI_ERROR_NO_MEMORY;
        }

        nsapi_size_or_error_t read_ret = 0;
        if ((size_t)data_len <= sizeof(rxbuf->data)) {
            rxbuf->reset();
            read_ret = _at.read_bytes(rxbuf->data, data_len);
            if (read_ret > 0 && _at.get_last_error() == NSAPI_ERROR_OK) {
                rxbuf->tail = read_ret;
                _at.skip_param_bytes(2, 1);
            }
        } else {
            tr_warn("ST87M01: sock=%d data %d > buf %u, truncating", sock_id, data_len, (unsigned)sizeof(rxbuf->data));
            rxbuf->reset();
            read_ret = _at.read_bytes(rxbuf->data, sizeof(rxbuf->data));
            if (read_ret > 0 && _at.get_last_error() == NSAPI_ERROR_OK) {
                rxbuf->tail = read_ret;
                _at.skip_param_bytes(data_len - read_ret, 1);
                _at.skip_param_bytes(2, 1);
            }
        }

        if (read_ret > 0 && _at.get_last_error() == NSAPI_ERROR_OK) {
            size_t avail = rxbuf->available();
            size_t to_copy = (avail < size) ? avail : size;
            memcpy(buffer, rxbuf->data + rxbuf->head, to_copy);
            rxbuf->head += to_copy;

            if (rxbuf->empty()) {
                rxbuf->reset();
            }
            returned = static_cast<nsapi_size_or_error_t>(to_copy);
        }
    }

    _at.resp_stop();

    if (_at.get_last_error() != NSAPI_ERROR_OK || returned <= 0) {
        if (!is_udp && rxbuf != nullptr) {
            rxbuf->reset();
        }
        _socket_mutex.lock();
        socket->pending_bytes = 0;
        _socket_mutex.unlock();
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    _socket_mutex.lock();
    if (socket->pending_bytes > 0) {
        socket->pending_bytes--;
    }
    _socket_mutex.unlock();

    tr_debug("ST87M01: sock=%d recv %s %d (wire=%d, pending=%u)",
             sock_id, is_udp ? "UDP" : "TCP", returned, data_len, (unsigned)socket->pending_bytes);
    return returned;
}

#if defined(MBED_CONF_NSAPI_OFFLOAD_TLSSOCKET) && (MBED_CONF_NSAPI_OFFLOAD_TLSSOCKET)

nsapi_error_t ST87M01_CellularStack::setsockopt(nsapi_socket_t handle, int level, int optname,
                                                const void *optval, unsigned optlen)
{
    CellularSocket *socket = static_cast<CellularSocket *>(handle);
    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    if (level != NSAPI_TLSSOCKET_LEVEL) {
        return AT_CellularStack::setsockopt(handle, level, optname, optval, optlen);
    }

    if (!optval) {
        return NSAPI_ERROR_PARAMETER;
    }

    ST87M01 *st87_device = static_cast<ST87M01 *>(&_device);
    ST87M01_TlsProvisioning *tls = st87_device->get_tls_provisioning();
    if (!tls) {
        return NSAPI_ERROR_NO_MEMORY;
    }

    nsapi_error_t ret = NSAPI_ERROR_OK;

    switch (optname) {
        case NSAPI_TLSSOCKET_ENABLE: {
            if (optlen != sizeof(bool)) {
                return NSAPI_ERROR_PARAMETER;
            }
            bool enabled = *static_cast<const bool *>(optval);
            if (socket->proto != NSAPI_TCP) {
                return NSAPI_ERROR_PARAMETER;
            }
            socket->tls_socket = enabled;
            tr_info("ST87M01: TLS %s on profile %d", enabled ? "enabled" : "disabled", _sslctxID);
            break;
        }

        case NSAPI_TLSSOCKET_SET_HOSTNAME: {
            // SNI is taken from the AT#TCPCONNECT host string by the modem.
            tr_debug("ST87M01: TLS hostname set (SNI handled by modem)");
            break;
        }

        case NSAPI_TLSSOCKET_SET_CACERT: {
            if (optlen == 0) {
                return NSAPI_ERROR_PARAMETER;
            }
            ret = tls->add_ca_certificate(_sslctxID, static_cast<const uint8_t *>(optval), optlen, true);
            break;
        }

        case NSAPI_TLSSOCKET_SET_CLCERT: {
            if (optlen == 0) {
                return NSAPI_ERROR_PARAMETER;
            }
            ret = tls->add_device_certificate(_sslctxID, static_cast<const uint8_t *>(optval), optlen, true);
            break;
        }

        case NSAPI_TLSSOCKET_SET_CLKEY: {
            if (optlen == 0) {
                return NSAPI_ERROR_PARAMETER;
            }
            ret = tls->add_key(_sslctxID, static_cast<const uint8_t *>(optval), optlen, ST87M01_TlsProvisioning::STORAGE_RAM);
            break;
        }

        default:
            tr_warn("ST87M01: unsupported TLS socket option %d", optname);
            ret = NSAPI_ERROR_UNSUPPORTED;
            break;
    }

    return ret;
}

#else

nsapi_error_t ST87M01_CellularStack::setsockopt(nsapi_socket_t handle, int level, int optname,
                                                const void *optval, unsigned optlen)
{
    if (level == NSAPI_TLSSOCKET_LEVEL) {
        tr_warn("ST87M01: offload TLSSocket disabled in config");
        return NSAPI_ERROR_UNSUPPORTED;
    }
    return AT_CellularStack::setsockopt(handle, level, optname, optval, optlen);
}

#endif

bool ST87M01_CellularStack::allocate_rx_buffer(int socket_id)
{
    if (socket_id < 0 || socket_id >= OP_MAX_SOCKETS) {
        return false;
    }

    if (_rx_buf[socket_id] != nullptr) {
        _rx_buf[socket_id]->reset();
        return true;
    }

    _rx_buf[socket_id] = _rx_buf_pool.try_alloc();
    if (_rx_buf[socket_id] == nullptr) {
        tr_error("ST87M01: rx-buffer pool exhausted for sock=%d", socket_id);
        return false;
    }

    _rx_buf[socket_id]->reset();
    return true;
}

void ST87M01_CellularStack::free_rx_buffer(int socket_id)
{
    if (socket_id < 0 || socket_id >= OP_MAX_SOCKETS) {
        return;
    }

    if (_rx_buf[socket_id] != nullptr) {
        _rx_buf_pool.free(_rx_buf[socket_id]);
        _rx_buf[socket_id] = nullptr;
    }
}

void ST87M01_CellularStack::reap_orphan_sockets()
{
    _at.lock();

    // Close only slots actually held on our CID; UM §9.10 <socket_status>=0 = unassigned.
    bool live[OP_MAX_SOCKETS] = {false};

    _at.cmd_start_stop("#SOCKETCREATE", "?");
    _at.resp_start("#SOCKETCREATE:");
    while (_at.info_resp()) {
        int ctx = _at.read_int();
        int sid = _at.read_int();
        int status = _at.read_int();
        if (ctx == _cid && status != 0 &&
                sid >= 0 && sid < OP_MAX_SOCKETS) {
            live[sid] = true;
        }
    }
    _at.resp_stop();
    _at.clear_error();

    for (int i = 0; i < OP_MAX_SOCKETS; i++) {
        if (live[i]) {
            tr_info("ST87M01: closing orphan sock=%d on cid=%d", i, _cid);
            _at.at_cmd_discard("#SOCKETCLOSE", "=", "%d,%d", _cid, i);
        }
    }
    _at.clear_error();

    _at.unlock();
}

int ST87M01_CellularStack::query_tcp_status(int sock_id)
{
    /* AT#TCPCONNECT?  (UM §9.11), one line per TCP link:
     *   #TCPCONNECT: <cid>,<sid>,<status>
     * status: 3 not-connected, 4 connecting, 5 connected, 6 closing. */
    int found = -1;

    _at.cmd_start_stop("#TCPCONNECT", "?");
    _at.resp_start("#TCPCONNECT:");
    while (_at.info_resp()) {
        int ctx = _at.read_int();
        int sid = _at.read_int();
        int st = _at.read_int();
        if (ctx == _cid && sid == sock_id) {
            found = st;
        }
    }
    _at.resp_stop();

    if (_at.get_last_error() != NSAPI_ERROR_OK) {
        _at.clear_error();
    }
    return found;
}

nsapi_error_t ST87M01_CellularStack::ensure_ip_configured()
{
    if (_ip_configured) {
        return NSAPI_ERROR_OK;
    }

    if (_cid < 0) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    // AT#IPCFG? returns current IP stack status per CID.
    bool ipv4_active = false;

    _at.cmd_start_stop("#IPCFG", "?");
    _at.resp_start("#IPCFG:");
    while (_at.info_resp()) {
        int ctx = _at.read_int();
        if (ctx != _cid) {
            continue;
        }
        int v4_status = _at.read_int();
        if (v4_status == 1) {
            ipv4_active = true;
        }
    }
    _at.resp_stop();

    if (_at.get_last_error() != NSAPI_ERROR_OK) {
        tr_warn("ST87M01: #IPCFG query failed, configuring anyway");
        _at.clear_error();
    }

    if (ipv4_active) {
        tr_info("ST87M01: IP stack active cid=%d", _cid);
        _ip_configured = true;
        return NSAPI_ERROR_OK;
    }

    tr_info("ST87M01: configuring IP stack cid=%d", _cid);

    char ip[NSAPI_IP_SIZE + 1] = {0};
    _at.clear_error();
    _at.cmd_start_stop("+CGPADDR", "=", "%d", _cid);
    _at.resp_start("+CGPADDR:");
    if (_at.info_resp()) {
        _at.skip_param();
        _at.read_string(ip, sizeof(ip));
    }
    _at.resp_stop();

    if (_at.get_last_error() != NSAPI_ERROR_OK || ip[0] == '\0') {
        tr_error("ST87M01: no IP for cid=%d, cannot configure IPCFG", _cid);
        _at.clear_error();
        return NSAPI_ERROR_NO_CONNECTION;
    }

    // AT#IPCFG=<cid>,<ip_mode>,<ip_address> ; ip_mode=0 = static/manual.
    _at.clear_error();
    _at.cmd_start("AT#IPCFG=");
    _at.write_int(_cid);
    _at.write_int(0);
    _at.write_string(ip, false);
    _at.cmd_stop();
    _at.resp_start();
    _at.resp_stop();

    nsapi_error_t err = _at.get_last_error();
    if (err != NSAPI_ERROR_OK) {
        tr_error("ST87M01: #IPCFG cid=%d ip=%s failed (err=%d)", _cid, ip, err);
        return err;
    }

    tr_info("ST87M01: IP stack ready cid=%d ip=%s", _cid, ip);
    _ip_configured = true;
    return NSAPI_ERROR_OK;
}

void ST87M01_CellularStack::urc_iprecv()
{
    // #IPRECV:<ctx>,<sock> = one URC per UDP datagram or per buffered TCP
    // segment. Consumers decrement pending_bytes after each #IPREAD.
    int context_id = _at.read_int();
    int socket_id = _at.read_int();

    _socket_mutex.lock();
    CellularSocket *sock = find_socket(socket_id);
    if (sock) {
        sock->pending_bytes++;
        tr_debug("ST87M01: URC #IPRECV ctx=%d sock=%d queued=%u",
                 context_id, socket_id, (unsigned)sock->pending_bytes);
        if (sock->_cb) {
            sock->_cb(sock->_data);
        }
    }
    _socket_mutex.unlock();
}

void ST87M01_CellularStack::urc_nb_sent()
{
    tr_debug("ST87M01: URC NB_SENT received");
}

void ST87M01_CellularStack::urc_socketclosed()
{
    // #SOCKETCLOSED:<ctx>,<sock>
    int context_id = _at.read_int();
    int socket_id = _at.read_int();

    tr_info("ST87M01: URC #SOCKETCLOSED ctx=%d sock=%d", context_id, socket_id);

    _socket_mutex.lock();
    CellularSocket *sock = find_socket(socket_id);
    if (sock) {
        sock->closed = true;
        sock->connected = false;

        if (socket_id >= 0 && socket_id < OP_MAX_SOCKETS && _rx_buf[socket_id] != nullptr) {
            _rx_buf[socket_id]->reset();
        }

        if (sock->_cb) {
            sock->_cb(sock->_data);
        }
    }
    _socket_mutex.unlock();
}

void ST87M01_CellularStack::txfull_event_timeout()
{
    _socket_mutex.lock();
    _txfull_event_id = 0;
    for (int i = 0; i < _device.get_property(AT_CellularDevice::PROPERTY_SOCKET_COUNT); i++) {
        CellularSocket *sock = _socket[i];
        if (sock && sock->_cb && sock->txfull_event) {
            sock->txfull_event = false;
            sock->_cb(sock->_data);
        }
    }
    _socket_mutex.unlock();
}
