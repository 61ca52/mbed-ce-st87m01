# ST87M01 NB-IoT Modem Driver for Mbed CE

*Community driver. Not affiliated with or endorsed by STMicroelectronics.*

Mbed CE cellular driver for the **ST87M01** NB-IoT modem, targeting the
**EVKITST87M01** shield on STM32 Nucleo boards.

## Overview

Runs in AT-sockets (module-IP) mode, the PPP is not used. Only `RAT_NB1` is
accepted by `ST87M01_CellularNetwork`; other RATs return
`NSAPI_ERROR_UNSUPPORTED`.

Extends the Mbed CE cellular framework with ST87M01 specifics:

- Module-IP sockets (`UDPSocket`, `TCPSocket`) via `AT#SOCKET*` / `AT#TCP*`
- Modem-offloaded DNS (`AT#DNS`) or network-provided servers
- Modem-offloaded TLS through the standard `TLSSocket` API
- Modem-internal HTTP/HTTPS client (`AT#HTTP*`)
- PDP context reuse (modem auto-activates CID 5/6 on attach)
- Band / `#BANDCFG` configuration

```text
AT_CellularDevice
 └── ST87M01
      ├── ST87M01_TlsProvisioning     key/cert management (AT#TLS*)
      ├── ST87M01_CellularContext     PDP context + HTTP entry points
      │    └── ST87M01_CellularStack  sockets, DNS, TLS offload, RX buffers
      ├── ST87M01_CellularNetwork     registration, +CESQ, NB-IoT RAT lock
      ├── ST87M01_CellularInformation IMEI / ICCID / ATI parsing
      └── ST87M01_HTTP                modem-side HTTP/HTTPS client
```

### Pin connections (Arduino form factor defaults)

| Shield pin | Nucleo pin | Function           |
|------------|------------|--------------------|
| D0         | PA3        | UART RX (modem TX) |
| D1         | PA2        | UART TX (modem RX) |
| D8         | PA9        | WAKEUP             |
| D9         | PC7        | RESETN             |

Jumper settings (VANT_LDO for GNSS antenna power, JP1–JP4 for power source):
see the EVKITST87M01-1 user manual.

## Integration

Add the library:

```cmake
add_subdirectory(st87m01)
target_link_libraries(your_app st87m01)
```

Configure `mbed_app.json5`:

```json
{
    "target_overrides": {
        "NUCLEO_L4A6ZG": {
            "st87m01.provide-default": true,
            "st87m01.bands": "\"8,20\"",
            "nsapi.default-cellular-apn": "\"your.operator.apn\""
        }
    }
}
```

Basic usage:

```cpp
#include "mbed.h"
#include "CellularDevice.h"

int main() {
    CellularDevice *device = CellularDevice::get_default_instance();
    device->init();

    CellularContext *context = device->create_context();
    context->connect();

    UDPSocket socket;
    socket.open(context);
    // ... send/receive ...

    context->disconnect();
}
```

## Configuration

All driver options live in `mbed_app.json5` under the `st87m01` namespace.
The complete, authoritative list is in [`mbed_lib.json`](./mbed_lib.json);
the tables below highlight the keys most commonly overridden.

### Serial and control pins

| Option     | Default          | Notes                                    |
|------------|------------------|------------------------------------------|
| `tx`       | `ARDUINO_UNO_D1` | UART TX                                  |
| `rx`       | `ARDUINO_UNO_D0` | UART RX                                  |
| `rts`      | `null`           | Optional flow control RTS                |
| `cts`      | `null`           | Optional flow control CTS                |
| `baudrate` | `115200`         | Serial baud rate                         |
| `resetn`   | `ARDUINO_UNO_D9` | RESETN (active low, pulsed by `reset()`) |
| `wakeup`   | `ARDUINO_UNO_D8` | WAKEUP                                   |

### Radio and IP stack

| Option             | Default     | Notes                                                                    |
|--------------------|-------------|--------------------------------------------------------------------------|
| `provide-default`  | `false`     | Register as `CellularDevice::get_default_instance()`                     |
| `configure`        | `true`      | Run band / `#IPPARAMS` configuration in `init()`; skip when NVM is ready |
| `default-pdp-type` | `"IP"`      | `"IP"` / `"IPV6"` / `"IPV4V6"` most NB-IoT networks require `"IP"`     |
| `bands`            | `"8,20"`    | Comma-separated NB-IoT bands; null to skip                               |
| `bandcfg`          | `null`      | `AT#BANDCFG` primary band record: `"<id>,0,<band>,<option>,<start100k>"` |
| `bandcfg_nmo1..3`  | `null`      | `AT#BANDCFG` NMO1/2/3 records                                            |
| `dnsv4`            | `"8.8.8.8"` | Optional static IPv4 DNS                                                 |
| `dnsv6`            | `""`        | Optional static IPv6 DNS                                                 |
| `dns_to_use`       | `1`         | 0 = static only, 1 = prefer network (see ST UM `#IPPARAMS`)              |

If `cellular.offload-dns-queries` is set, static DNS values are ignored and
network-provided DNS from `#IPPARAMS` is used instead.

### TLS provisioning

| Option                 | Default | Notes                                                          |
|------------------------|---------|----------------------------------------------------------------|
| `tls_enable`           | `false` | Run compile-time TLS provisioning in `init()`                  |
| `tls_default_sslctxid` | `0`     | Default security profile (0–15) applied to TLS sockets         |
| `tls_ca_cert`          | `null`  | CA cert in DER-hex; accepts PEM when `tls_support_pem` is true |
| `tls_device_cert`      | `null`  | Device cert, same format as above                              |
| `tls_generate_key`     | `false` | Generate an ECC key on the modem if the profile has none       |
| `tls_key_size`         | `32`    | ECC key size in bytes (32 = P-256, 48 = P-384)                 |
| `tls_key_storage`      | `2`     | 1 = OTP, 2 = Flash, 3 = RetRAM, 4 = RAM                        |
| `tls_support_pem`      | `true`  | Enable PEM→DER conversion; disable to save code size           |

### Socket buffering

| Option                  | Default | Notes                                                                    |
|-------------------------|---------|--------------------------------------------------------------------------|
| `socket_rx_buffer_size` | `4096`  | Per-socket RX scratch. Must hold a full TLS record, increase if TLS fails. |

## Layout

```text
st87m01/
├── CMakeLists.txt
├── mbed_lib.json
├── README.md
├── include/st87m01/
│   ├── ST87M01.h
│   ├── ST87M01_CellularContext.h
│   ├── ST87M01_CellularStack.h
│   ├── ST87M01_CellularNetwork.h
│   ├── ST87M01_CellularInformation.h
│   ├── ST87M01_TlsProvisioning.h
│   └── ST87M01_HTTP.h
└── src/                       # matching .cpp files
```

## TLS

The driver exposes 16 modem security profiles (0–15). Each profile can hold
one CA certificate, one device certificate, and one private key.
Certificates and keys are accepted as DER, DER-hex, or (when
`tls_support_pem` is enabled) PEM; the wrapper converts to DER before
upload.

### Compile-time provisioning (NVM)

Credentials from `mbed_app.json5` are written to NVM on first boot and
persist across resets.

```json
{
    "st87m01.tls_enable": true,
    "st87m01.tls_ca_cert": "308201A2...",
    "st87m01.tls_generate_key": true
}
```

`ST87M01::init()` calls `init_tls()`, which checks the profile, provisions
anything missing, and flushes to NVM via `save_to_nvm()` (triggers a modem
reboot).

### Runtime provisioning (TLSSocket offload)

Credentials are stored in modem RAM and cleared on reset.

```json
{ "nsapi.offload-tlssocket": true }
```

```cpp
#include "TLSSocket.h"

TLSSocket socket;
socket.open(context);
socket.set_root_ca_cert(CA_CERT_PEM);
socket.connect("secure.example.com", 443);
socket.send("GET / HTTP/1.1\r\n...", ...);
```

## Example app

EVKIT example app that wires this driver to a target board: [mbed-ce-st87m01-app](https://github.com/61ca52/mbed-ce-st87m01-app)

## License

Apache License 2.0. See `LICENSE`.
