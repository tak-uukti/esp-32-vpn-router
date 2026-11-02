/**
 * @file gadget_main.c
 * @brief Tailnet Gadget: a WiFi AP whose clients reach the tailnet with zero software
 *        installed on them, provisioned from a browser on first boot.
 *
 * Data path (verified against esp-lwip ip4_napt.c):
 *   client -> AP netif (napt=1) -> ip4_input -> ip4_route(100.64/10) -> WG netif
 *   -> wireguardif_output -> peer. Source is rewritten to the gadget's own tailnet
 *   IP, so Tailscale ACLs apply per destination port and no subnet route is needed.
 *   Replies arrive on the WG netif addressed to our tailnet IP, ip_napt_recv()
 *   de-NATs them, and lwIP forwards them back out the AP.
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "cJSON.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"

#include "tailtiny.h"
#include "tailtiny_internal.h"
#include "portal.h"

static const char *TAG = "gadget";

#define STA_UP_BIT BIT0
#define AP_UP_BIT  BIT1

#define STA_CONNECT_TIMEOUT_MS 30000
#define TAILNET_TIMEOUT_MS     60000

static esp_netif_t *s_sta_netif;
static esp_netif_t *s_ap_netif;
static EventGroupHandle_t s_events;
static tailtiny_t *s_ml;

/* Active upstream credentials: NVS (set from the setup page) wins over Kconfig. */
static char s_ssid[33] = CONFIG_GADGET_WIFI_SSID;
static char s_pass[65] = CONFIG_GADGET_WIFI_PASSWORD;
static char s_key[96]  = CONFIG_GADGET_TS_AUTH_KEY;

/* ------------------------------------------------------------------ helpers */

static void copy_str(char *dst, size_t dst_len, const char *src)
{
    if (dst_len == 0) {
        return;
    }
    size_t n = src ? strlen(src) : 0;
    if (n > dst_len - 1) {
        n = dst_len - 1;
    }
    if (n) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

/* Called from the portal's HTTP handler after the user submits the form. */
void gadget_apply_wifi(const char *ssid, const char *pass)
{
    copy_str(s_ssid, sizeof(s_ssid), ssid);
    copy_str(s_pass, sizeof(s_pass), pass);

    wifi_config_t sta = {0};
    copy_str((char *)sta.sta.ssid, sizeof(sta.sta.ssid), s_ssid);
    copy_str((char *)sta.sta.password, sizeof(sta.sta.password), s_pass);
    sta.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    esp_wifi_disconnect();
    esp_wifi_set_config(WIFI_IF_STA, &sta);
    esp_wifi_connect();
    ESP_LOGI(TAG, "applying uplink \"%s\"", s_ssid);
}

static void advertise_dns_to_clients(void)
{
    esp_netif_dns_info_t dns = {0};

    if (esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK ||
        dns.ip.u_addr.ip4.addr == 0) {
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        dns.ip.u_addr.ip4.addr = esp_ip4addr_aton("1.1.1.1");
    }
    esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &dns);
    portal_set_dns(dns.ip.u_addr.ip4.addr);

    /* Clients keep the AP address as their resolver (ESP-IDF's default) and the portal
     * forwards their queries. Overriding the DHCP DNS option left clients with no working
     * resolver, so the default is the correct choice here. */
}

/* NAPT on the AP netif is what lets client packets out of the box: esp-lwip only
 * forwards through ip_napt_forward() when the *receiving* netif has napt set. */
static void enable_router(void)
{
    esp_netif_ip_info_t ip = {0};

    if (esp_netif_get_ip_info(s_ap_netif, &ip) != ESP_OK || ip.ip.addr == 0) {
        ESP_LOGE(TAG, "AP netif has no IP, cannot enable NAPT");
        return;
    }

    esp_err_t err = esp_netif_napt_enable(s_ap_netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NAPT enable failed: %s", esp_err_to_name(err));
        return;
    }
    ESP_LOGI(TAG, "router up: clients on " IPSTR "/24 are NATed into the tailnet",
             IP2STR(&ip.ip));
}

/* ------------------------------------------------------------------ events */

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT) {
        switch (id) {
        case WIFI_EVENT_STA_START:
            if (s_ssid[0]) {
                esp_wifi_connect();
            }
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            if (s_ssid[0]) {
                ESP_LOGW(TAG, "uplink lost, retrying in 2s");
                portal_set_uplink(false);
                xEventGroupClearBits(s_events, STA_UP_BIT);
                vTaskDelay(pdMS_TO_TICKS(2000));
                esp_wifi_connect();
            }
            break;
        case WIFI_EVENT_AP_START:
            ESP_LOGI(TAG, "AP started: SSID \"%s\"", CONFIG_GADGET_AP_SSID);
            xEventGroupSetBits(s_events, AP_UP_BIT);
            break;
        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *e = data;
            ESP_LOGI(TAG, "client joined: " MACSTR, MAC2STR(e->mac));
        } break;
        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *e = data;
            ESP_LOGW(TAG, "client left: " MACSTR " reason=%d", MAC2STR(e->mac),
                     e->reason);
        } break;
        default:
            break;
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        ESP_LOGI(TAG, "uplink IP: " IPSTR, IP2STR(&e->ip_info.ip));
        advertise_dns_to_clients();
        portal_set_uplink(true);
        xEventGroupSetBits(s_events, STA_UP_BIT);
    }
}

static void tailnet_state_cb(tailtiny_t *ml, tailtiny_state_t state, void *user_data)
{
    static const char *names[] = {"IDLE", "WIFI_WAIT", "CONNECTING", "REGISTERING",
                                  "CONNECTED", "RECONNECTING", "ERROR"};
    const char *name = (state < sizeof(names) / sizeof(names[0])) ? names[state] : "?";
    ESP_LOGI(TAG, "tailnet state: %s", name);

    if (state == ML_STATE_CONNECTED && ml) {
        char ip[16];
        tailtiny_ip_to_str(tailtiny_get_vpn_ip(ml), ip);
        ESP_LOGI(TAG, "tailnet IP: %s", ip);
    }
}

/* ------------------------------------------------------------------ wifi */

static esp_err_t wifi_start_apsta(void)
{
    /* Default netifs are created before esp_wifi_init, matching Espressif's examples. */
    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif = esp_netif_create_default_wifi_ap();
    if (!s_sta_netif || !s_ap_netif) {
        return ESP_FAIL;
    }

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        wifi_event_handler, NULL, NULL));

    wifi_config_t sta = {0};
    copy_str((char *)sta.sta.ssid, sizeof(sta.sta.ssid), s_ssid);
    copy_str((char *)sta.sta.password, sizeof(sta.sta.password), s_pass);
    sta.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    wifi_config_t ap = {0};
    copy_str((char *)ap.ap.ssid, sizeof(ap.ap.ssid), CONFIG_GADGET_AP_SSID);
    copy_str((char *)ap.ap.password, sizeof(ap.ap.password), CONFIG_GADGET_AP_PASSWORD);
    ap.ap.ssid_len = strlen(CONFIG_GADGET_AP_SSID);
    ap.ap.channel = CONFIG_GADGET_AP_CHANNEL ? CONFIG_GADGET_AP_CHANNEL : 6;
    ap.ap.max_connection = CONFIG_GADGET_AP_MAX_CLIENTS;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    return ESP_OK;
}

/* Start TailTiny only once there is an uplink. Provisioning from the setup page makes
 * WiFi appear minutes after boot, so this must not be wired to boot order. */
static void tailnet_task(void *arg)
{
    xEventGroupWaitBits(s_events, STA_UP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    if (s_key[0] == '\0') {
        ESP_LOGW(TAG, "no Tailscale auth key: AP is an internet gateway only");
        vTaskDelete(NULL);
        return;
    }

    tailtiny_config_t cfg = {
        .auth_key = s_key,
        .device_name = CONFIG_GADGET_DEVICE_NAME,
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
        .max_peers = 0, /* library default */
    };
    s_ml = tailtiny_init(&cfg);
    if (!s_ml) {
        ESP_LOGE(TAG, "tailtiny_init failed");
        vTaskDelete(NULL);
        return;
    }
    tailtiny_set_state_callback(s_ml, tailnet_state_cb, NULL);
    tailtiny_start(s_ml);
    ESP_LOGI(TAG, "tailnet starting on uplink \"%s\"", s_ssid);

    vTaskDelete(NULL);
}

#if CONFIG_GADGET_NAPT_TEST
/* Proves the client->tailnet forwarding path without a WiFi client on the AP.
 * lwIP cannot send to itself once NAPT is on, so instead of opening a socket we build an
 * IP packet that *looks* like it arrived from a LAN client (192.168.4.50) and hand it to
 * the AP interface's input function, exactly where the WiFi driver would deliver it.
 * If NAPT and the WG route work, the peer sees the packet from the gadget's tailnet IP. */
#include "lwip/inet_chksum.h"
#include "lwip/ip4.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip4.h"

/* Feed the packet to ip4_input on the TCP/IP thread, exactly where the WiFi driver
 * delivers received frames. Going through netif->input/tcpip_input resolves the
 * interface from a cached index, which does not work for a netif that was inserted
 * into netif_list by hand. */
struct inject_call {
    struct tcpip_api_call_data call;
    struct pbuf *p;
    struct netif *netif;
    err_t result;
};

static err_t inject_on_tcpip(struct tcpip_api_call_data *c)
{
    struct inject_call *ic = (struct inject_call *)c;
    ic->result = ip4_input(ic->p, ic->netif);
    return ERR_OK;
}

static void napt_test_task(void *arg)
{
    /* wait until the tailnet netif actually exists */
    while (!s_ml || !tailtiny_is_connected(s_ml)) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGI(TAG, "napt test: tailnet up, starting injections");
#if CONFIG_LWIP_IP_DEBUG
    esp_log_level_set("lwip", ESP_LOG_DEBUG);
#endif

    /* Find the AP interface through public lwIP state (no private esp_netif headers). */
    ip4_addr_t ap_ip;
    IP4_ADDR(&ap_ip, 192, 168, 4, 1);
    struct netif *ap = NULL;
    for (struct netif *n = netif_list; n; n = n->next) {
        if (!ip4_addr_isany(netif_ip4_addr(n)) && ip4_addr_cmp(netif_ip4_addr(n), &ap_ip)) {
            ap = n;
            break;
        }
    }
    if (!ap || !ap->input) {
        ESP_LOGE(TAG, "napt test: no AP lwip netif");
        vTaskDelete(NULL);
        return;
    }
    /* Destination comes from Kconfig: point it at a host on your own tailnet. */
    ip4_addr_t probe_dst;
    if (!ip4addr_aton(CONFIG_GADGET_NAPT_TEST_TARGET, &probe_dst)) {
        ESP_LOGE(TAG, "napt test: GADGET_NAPT_TEST_TARGET=\"%s\" is not a valid IPv4 address",
                 CONFIG_GADGET_NAPT_TEST_TARGET);
        vTaskDelete(NULL);
        return;
    }
    struct netif *out = ip4_route(&probe_dst);
    if (out) {
        char oip[16], omask[16];
        ip4addr_ntoa_r(netif_ip4_addr(out), oip, sizeof(oip));
        ip4addr_ntoa_r(netif_ip4_netmask(out), omask, sizeof(omask));
        ESP_LOGI(TAG, "napt test: route -> %c%c%d ip=%s mask=%s up=%d link=%d out=%p",
                 out->name[0], out->name[1], out->num, oip, omask,
                 (int)netif_is_up(out), (int)netif_is_link_up(out), out->output);
    } else {
        ESP_LOGE(TAG, "napt test: NO ROUTE to %s", CONFIG_GADGET_NAPT_TEST_TARGET);
    }
    ESP_LOGI(TAG, "napt test: ap netif napt flag = %d (want 1)", (int)ap->napt);
    for (struct netif *n = netif_list; n; n = n->next) {
        char ipb[16] = "-", mkb[16] = "-", gwb[16] = "-";
        static const ip4_addr_t zero;
        if (!ip4_addr_isany(netif_ip4_addr(n))) {
            ip4addr_ntoa_r(netif_ip4_addr(n), ipb, sizeof(ipb));
        }
        if (n->netmask.u_addr.ip4.addr != zero.addr) {
            ip4addr_ntoa_r(netif_ip4_netmask(n), mkb, sizeof(mkb));
        }
        if (n->gw.u_addr.ip4.addr != zero.addr) {
            ip4addr_ntoa_r(netif_ip4_gw(n), gwb, sizeof(gwb));
        }
        ESP_LOGI(TAG, "napt test: if=%c%c%d ip=%s mask=%s gw=%s up=%d link=%d napt=%d out=%p",
                 n->name[0], n->name[1], n->num, ipb, mkb, gwb,
                 (int)netif_is_up(n), (int)netif_is_link_up(n), (int)n->napt, n->output);
    }
    ESP_LOGI(TAG, "napt test: default netif = %s", netif_default ? netif_default->name : "(none)");

    ip4_addr_t src, dst;
    IP4_ADDR(&src, 192, 168, 4, 50);   /* pretend LAN client */
    dst = probe_dst;                   /* test target from Kconfig */

    for (int i = 0; ; i++) {
        uint8_t pkt[60];
        memset(pkt, 0x5a, sizeof(pkt));

        struct ip_hdr *iph = (struct ip_hdr *)pkt;
        IPH_VHL_SET(iph, 4, 5);
        IPH_TOS_SET(iph, 0);
        IPH_LEN_SET(iph, htons(sizeof(pkt)));
        IPH_ID_SET(iph, htons((uint16_t)(0x2000 + i)));
        IPH_OFFSET_SET(iph, 0);
        IPH_TTL_SET(iph, 64);
        IPH_PROTO_SET(iph, IP_PROTO_TCP);
        ip4_addr_copy(iph->src, src);
        ip4_addr_copy(iph->dest, dst);
        IPH_CHKSUM_SET(iph, 0);
        IPH_CHKSUM_SET(iph, inet_chksum(iph, IP_HLEN));

        /* TCP SYN with a correct pseudo-header checksum. */
        uint8_t *l4 = pkt + IP_HLEN;
        uint16_t sport = htons(40000), dport = htons(22);
        uint32_t seq = htonl(1000);
        memcpy(l4, &sport, 2);
        memcpy(l4 + 2, &dport, 2);
        memcpy(l4 + 4, &seq, 4);
        memset(l4 + 8, 0, 4);       /* ack */
        l4[12] = 0x50;              /* data offset 5 */
        l4[13] = 0x02;              /* SYN */
        uint16_t win = htons(64240);
        memcpy(l4 + 14, &win, 2);
        l4[16] = l4[17] = 0;        /* checksum */
        l4[18] = l4[19] = 0;        /* urgent */

        /* pseudo header: src, dst, zero, proto, tcp length */
        uint32_t sum = 0;
        const uint8_t *ps[3] = {(const uint8_t *)&src.addr, (const uint8_t *)&dst.addr, NULL};
        for (int k = 0; k < 2; k++) {
            for (int b = 0; b < 4; b += 2) {
                sum += (uint16_t)((ps[k][b] << 8) | ps[k][b + 1]);
            }
        }
        sum += 6 + 20;
        for (int b = 0; b < 20; b += 2) {
            sum += (uint16_t)((l4[b] << 8) | l4[b + 1]);
        }
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        uint16_t tcp_csum = htons((uint16_t)~sum);
        memcpy(l4 + 16, &tcp_csum, 2);
        if (i == 0) {
            char sb[16], db[16];
            ip4addr_ntoa_r(&src, sb, sizeof(sb));
            ip4addr_ntoa_r(&dst, db, sizeof(db));
            ESP_LOGI(TAG, "napt test: built packet src=%s dst=%s (before NAPT)", sb, db);
        }

        struct pbuf *p = pbuf_alloc(PBUF_IP, sizeof(pkt), PBUF_RAM);
        if (!p) {
            ESP_LOGE(TAG, "napt test: pbuf alloc failed");
            break;
        }
        pbuf_take(p, pkt, sizeof(pkt));
        struct inject_call ic = {.p = p, .netif = ap};
        tcpip_api_call(inject_on_tcpip, &ic.call);
        ESP_LOGI(TAG, "napt test: injected echo #%d ip4_input returned %d", i + 1,
                 (int)ic.result);
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
#endif

/* Status for the setup page: what we are attached to and whether the tailnet is up. */
char *gadget_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) {
        return NULL;
    }

    wifi_ap_record_t ap_info = {0};
    bool sta_up = esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK;
    cJSON_AddBoolToObject(o, "uplink", sta_up);
    cJSON_AddStringToObject(o, "ssid", s_ssid);
    cJSON_AddNumberToObject(o, "rssi", sta_up ? ap_info.rssi : 0);

    esp_netif_ip_info_t ip = {0};
    if (sta_up && esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK && ip.ip.addr) {
        char buf[16];
        esp_ip4addr_ntoa(&ip.ip, buf, sizeof(buf));
        cJSON_AddStringToObject(o, "ip", buf);
    }

    bool tn = s_ml && tailtiny_is_connected(s_ml);
    cJSON_AddBoolToObject(o, "tailnet", tn);
    if (tn) {
        char buf[16];
        tailtiny_ip_to_str(tailtiny_get_vpn_ip(s_ml), buf);
        cJSON_AddStringToObject(o, "tailnet_ip", buf);
    }

    wifi_sta_list_t clients = {0};
    esp_wifi_ap_get_sta_list(&clients);
    cJSON_AddNumberToObject(o, "clients", clients.num);

    char *json = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    return json;
}

/* ------------------------------------------------------------------ selftest */

#if CONFIG_GADGET_SELFTEST
/* Only what the board can honestly check about itself: with NAPT enabled esp-lwip
 * compiles out send-to-self (ip4.c), so the HTTP page and the DNS responder have to be
 * verified from a real client on the AP. The scan path can be exercised locally. */
static void selftest_run(void)
{
    vTaskDelay(pdMS_TO_TICKS(2000));

    char *json = portal_scan_json();
    int nets = 0;
    if (json) {
        for (char *p = json; (p = strstr(p, "\"ssid\"")) != NULL; p++) {
            nets++;
        }
        ESP_LOGI(TAG, "selftest scan PASS (%d networks, %d bytes json)", nets, (int)strlen(json));
        ESP_LOGI(TAG, "selftest scan sample: %.140s", json);
        free(json);
    } else {
        ESP_LOGE(TAG, "selftest scan FAIL");
    }
    ESP_LOGI(TAG, "selftest: setup page and DNS are verified from a client on the AP");
}
#endif

/* ------------------------------------------------------------------ status */

static void netif_tag(struct netif *n, char *out, size_t sz)
{
    /* lwIP stores a 2-char name plus a numeric index; name is not NUL terminated. */
    if (!n) {
        snprintf(out, sz, "none");
        return;
    }
    snprintf(out, sz, "%c%c%d", n->name[0], n->name[1], (int)n->num);
}

static void status_task(void *arg)
{
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(CONFIG_GADGET_STATUS_INTERVAL_S * 1000));

        char vpn[16] = "none";
        if (s_ml && tailtiny_is_connected(s_ml)) {
            tailtiny_ip_to_str(tailtiny_get_vpn_ip(s_ml), vpn);
        }

        wifi_sta_list_t clients = {0};
        esp_wifi_ap_get_sta_list(&clients);

        /* Route diagnostic: shows which netif lwIP picks per destination. If the tunnel
         * owns the default route, ordinary internet traffic is blackholed while the
         * tailnet keeps working. */
        {
            ip4_addr_t p1, p2, p3, p4;
            IP4_ADDR(&p1, 8, 8, 8, 8);
            IP4_ADDR(&p2, 1, 1, 1, 1);
            IP4_ADDR(&p3, 100, 100, 100, 100);  /* any CGNAT address = tailnet probe */
            IP4_ADDR(&p4, 192, 0, 2, 1);        /* TEST-NET-1 = plain internet probe */
            struct netif *dflt = netif_default;
            struct netif *r1 = ip4_route(&p1);
            struct netif *r2 = ip4_route(&p2);
            struct netif *r3 = ip4_route(&p3);
            struct netif *r4 = ip4_route(&p4);
            char t0[8], t1[8], t2[8], t3[8], t4[8];
            netif_tag(dflt, t0, sizeof(t0));
            netif_tag(r1, t1, sizeof(t1));
            netif_tag(r2, t2, sizeof(t2));
            netif_tag(r3, t3, sizeof(t3));
            netif_tag(r4, t4, sizeof(t4));
            uint32_t fwd = 0, bad = 0;
            portal_dns_stats(&fwd, &bad);
            ESP_LOGI(TAG, "route default=%s 8.8.8.8=%s tailnet=%s | dns fwd=%u fail=%u",
                     t0, t1, t3, (unsigned)fwd, (unsigned)bad);
        }

        /* Internal DRAM is the scarce resource: lwIP pbufs, WiFi buffers and WireGuard
         * all come from it. The combined heap figure includes 8 MB of PSRAM and hides
         * exhaustion here, which is what stalls forwarding while a session is busy. */
        ESP_LOGI(TAG, "status tailnet=%s clients=%d uplink=%s int_free=%u int_min=%u "
                 "int_block=%u psram=%u",
                 vpn, clients.num, s_ssid[0] ? s_ssid : "unconfigured",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    }
}

/* ------------------------------------------------------------------ app */

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(ret);
    }

    /* Saved provisioning (setup page) wins over Kconfig. */
    portal_cfg_t saved = {0};
    if (portal_load(&saved) == ESP_OK) {
        snprintf(s_ssid, sizeof(s_ssid), "%s", saved.ssid);
        snprintf(s_pass, sizeof(s_pass), "%s", saved.pass);
        if (saved.key[0]) {
            snprintf(s_key, sizeof(s_key), "%s", saved.key);
        }
        ESP_LOGI(TAG, "provisioned uplink from NVS: \"%s\"", s_ssid);
    } else if (s_ssid[0]) {
        ESP_LOGI(TAG, "provisioned uplink from Kconfig: \"%s\"", s_ssid);
    } else {
        ESP_LOGI(TAG, "no uplink configured, setup page will be served on the AP");
    }

    s_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_LOGI(TAG, "boot: free heap %u bytes, PSRAM %u bytes",
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    ESP_ERROR_CHECK(wifi_start_apsta());

    EventBits_t bits = xEventGroupWaitBits(s_events, AP_UP_BIT, pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(5000));
    if (!(bits & AP_UP_BIT)) {
        ESP_LOGE(TAG, "AP never came up");
    }
    /* Router comes up as soon as the AP has an address; the uplink can arrive later and
     * only affects reachability, not the NAPT setup. */
    enable_router();
    portal_start();

    if (!s_ssid[0]) {
        ESP_LOGW(TAG, "unconfigured: open http://192.168.4.1/ from a device on the AP");
    } else {
        bits = xEventGroupWaitBits(s_events, STA_UP_BIT, pdFALSE, pdTRUE,
                                   pdMS_TO_TICKS(STA_CONNECT_TIMEOUT_MS));
        if (!(bits & STA_UP_BIT)) {
            ESP_LOGW(TAG, "no uplink WiFi after %ds (AP is up, tailnet unreachable until "
                          "credentials are set)", STA_CONNECT_TIMEOUT_MS / 1000);
        }
    }

    xTaskCreate(tailnet_task, "tailnet", 8192, NULL, 4, NULL);
#if CONFIG_GADGET_NAPT_TEST
    xTaskCreate(napt_test_task, "napt_test", 4096, NULL, 3, NULL);
#endif

#if CONFIG_GADGET_SELFTEST
    selftest_run();
#endif

    xTaskCreate(status_task, "status", 4096, NULL, 3, NULL);
}
