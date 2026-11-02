# esp-32-vpn-router

Pocket ESP32-S3 travel router that gives **any** device tailnet access with **no client
software at all**. A phone or laptop joins the gadget's WiFi AP, gets DHCP, and can reach
tailnet hosts with plain `ssh user@100.x.y.z` — while keeping ordinary internet access
through the gadget's own WiFi uplink.

No Tailscale app, no WireGuard app, no drivers, nothing installed on the client.

```
client (no tailscale, no drivers)
   |  WiFi AP "esp-vpn" + DHCP 192.168.4.0/24
ESP32-S3  -- NAPT on the AP netif
   |  \-- 100.64.0.0/10 -> WireGuard netif (TailTiny tunnel)
   |  \-- default       -> WiFi STA uplink (internet keeps working)
Tailscale control plane (direct  or  DERP relay)
   |
ssh server / web app / whatever on the tailnet
```

The gadget itself is a tailnet node (set its hostname, e.g. `esp-vpn`), so the tailnet sees
every client as that one node. That means your existing ACLs apply per destination host and
port, and you do **not** need subnet router approval.

## Status

Working and tested on real hardware: AP + DHCP + DNS forwarding + NAPT, tailnet join over a
direct path, ICMP/TCP/UDP both directions, setup page served over the tailnet.

Known not working: **relayed (DERP) data traffic**. Control-plane pings succeed through DERP
and direct paths work fine, but relayed data packets do not reach lwIP in this stack. On a
symmetric-NAT uplink (typically a phone hotspot) where Tailscale is forced to DERP, clients
get tailnet control visibility but no data path. Debugged but unresolved; see
[Known limits](#known-limits).

## Requirements

- ESP32-S3 with PSRAM, 8 MB flash recommended. Developed on a Seeed XIAO ESP32-S3 (8 MB
  flash, 8 MB octal PSRAM, native USB). A generic S3 devkit works with the default profile.
- ESP-IDF v5.4.1, native install (Docker works too, just slower to set up).
- A Tailscale auth key: tagged, non-ephemeral, non-reusable.
- An uplink WiFi network with internet.

Classic ESP32 has a profile but is not recommended: no PSRAM and much less internal RAM for
WireGuard + lwIP buffers. ESP8266 cannot run this at all (no ESP-IDF, no USB, ~80 KB RAM).

## How the forwarding works

Verified against `espressif/esp-lwip@2.2.0-esp`:

- `ip4_input` only NATs when the **receiving** netif has the `napt` flag set
  (`ip_napt_forward()` returns early otherwise), so NAPT is enabled on the AP netif, not
  the uplink netif.
- The source is rewritten to the *outgoing* netif's IP, which for tailnet destinations is
  the gadget's own tailnet address. Replies therefore come back to an address the gadget
  owns, and `ip_napt_recv()` de-NATs them and forwards them out the AP again.
- TailTiny creates the WireGuard netif with netmask `/10`, MTU 1280, and
  `output = wireguardif_output`, with peer lookup by destination allowed-IP. That is what
  makes the tunnel usable as a routed interface rather than a host-only device.

### Local patch to TailTiny (required)

`third_party/tailtiny/components/tailtiny/components/wireguard_lwip/src/wireguardif.c`
contains a patch marked `LOCAL PATCH`. Upstream ties `NETIF_FLAG_LINK_UP` to "at least one
peer session exists". lwIP's `ip4_route()` skips interfaces whose link is down, so
tailnet-bound traffic fell through to the WiFi uplink and was lost, while the tunnel could
never come up because nothing was being routed into it. The patch keeps the tunnel interface
link-up and routable. Without it the router does not work.

## Build

```bash
git clone https://github.com/<you>/esp-32-vpn-router.git
cd esp-32-vpn-router

# point at your ESP-IDF if it is not in the default location
export IDF_PATH=$HOME/esp/esp-idf
export IDF_TOOLS_PATH=$HOME/.espressif
export IDF_PYTHON_ENV_PATH=$HOME/.espressif/python_env/idf5.4_py3.11_env

./build.sh esp32s3 xiao-s3     # Seeed XIAO ESP32-S3: 8 MB flash, octal PSRAM
./build.sh esp32s3             # generic S3 devkit, 16 MB flash
./build.sh esp32               # classic ESP32, no PSRAM
```

## Credentials

Keep secrets out of git. Copy the example and fill it in:

```bash
cp sdkconfig.credentials.example sdkconfig.credentials
$EDITOR sdkconfig.credentials     # AP name/password, tailnet hostname, auth key
```

`sdkconfig`, `sdkconfig.credentials` and `build/` are all gitignored. Do not commit them:
`sdkconfig` is generated and contains the same secrets in plain text.

## Flash

```bash
./flash.sh /dev/ttyACM0        # XIAO over its native USB port
./flash.sh /dev/ttyUSB0        # devkit with a UART bridge
```

`sudo` is only needed because the serial device is usually root-owned. Erase first for a
clean identity: `idf.py -p /dev/ttyACM0 erase-flash`.

## First run (no app, no tools)

1. Join the AP (name and password from `sdkconfig.credentials`).
2. The setup page opens by itself through the catch-all DNS + captive portal. If not, open
   `http://192.168.4.1/`.
3. Pick your uplink network from the live scan, type its password, tap Save. Leave the
   Tailscale field empty if the key is already baked into the firmware.
4. The AP follows the uplink's channel, so reconnect once. From then on clients get both
   internet and tailnet.

Values saved on the setup page live in NVS (namespace `gadget`) and override Kconfig after a
reboot. `idf.py erase-flash` resets them.

## Verify

From a laptop joined to the gadget's AP (`verify_from_client.sh` automates this):

```bash
./verify_from_client.sh 100.64.0.10        # any host on your tailnet, plus your ssh user
```

1. `ip addr` shows `192.168.4.x`; `ping 192.168.4.1` works.
2. `curl -s https://api.ipify.org` returns the uplink's public IP (internet path OK).
3. `ping <tailnet-ip>` and `ssh user@<tailnet-ip>` work (tailnet path OK).
4. `scp` a 1 MB file: expect 2 to 5 Mbps. WireGuard is software crypto on this chip.
5. Pull the uplink: the AP stays up, tailnet drops, it recovers within ~10 s of the uplink
   returning.
6. A port your ACL forbids must time out, proving the ACL is the boundary, not the gadget.

Without a second device, `CONFIG_GADGET_NAPT_TEST=y` builds a synthetic client packet and
feeds it to the AP interface's input path. Set `GADGET_NAPT_TEST_TARGET` to a host on your
own tailnet, then watch that host for the arriving packet.

## Security notes

- One dedicated node per gadget, with a tagged, non-ephemeral, non-reusable auth key.
- Restrict the tag in your ACL to just the destinations and ports the gadget may reach, so a
  lost gadget reaches nothing else.
- The AP password is part of your secret material, not a convenience.
- Anything on the AP can reach exactly what the ACL allows. Treat the AP password like a
  network password, not a device password.

## Known limits

- **DERP relay data path is broken** in this stack: control pings relay fine, data does not.
  Direct paths only, for now.
- No MagicDNS for clients: use raw `100.x.y.z` addresses.
- Software WireGuard: a few Mbps. Fine for SSH and small pages, not for video.
- Android may label the network "no internet" and prefer mobile data if its connectivity
  probe is slow. Turn mobile data off while testing.
- `int_free` internal DRAM sits around 170 KB after WiFi + tunnel + HTTP server. That is
  enough for forwarding but not for many simultaneous large transfers.

## License

MIT for this project, see [LICENSE](LICENSE). Vendored
[TailTiny](https://github.com/Asimmimx/tailtiny) is MIT as well; its own LICENSE file is kept
at `third_party/tailtiny/LICENSE`.
