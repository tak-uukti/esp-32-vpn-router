/**
 * @file portal.c
 * @brief First-run provisioning portal: HTTP setup page on the gadget's own AP plus a
 *        catch-all DNS responder so phones and laptops pop the page up by themselves.
 *
 * Deliberately independent of TailTiny: it must work before any tailnet exists.
 */

#include "portal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"

#include "cJSON.h"

static const char *TAG = "portal";

#define NVS_NS      "gadget"
#define AP_GW_IP    "192.168.4.1"
#define AP_GW_U32   0xC0A80401u /* 192.168.4.1 */
#define SCAN_MAX_AP 24

/* False until the gadget has a working uplink. While false we act as a captive portal
 * (redirect everything, answer every DNS name) to force the setup page open. Once there
 * is real internet we must stop doing that: Android's connectivity probe expects 204, and
 * a redirect makes it mark the network as unusable and fall back to mobile data. */
static bool s_uplink_up;
static uint32_t s_upstream_dns;
static uint32_t s_dns_fwd, s_dns_fail; /* network byte order, 0 = unknown */

/* Implemented in gadget_main.c: re-point the station interface at saved credentials. */
void gadget_apply_wifi(const char *ssid, const char *pass);

/* ------------------------------------------------------------------ storage */

void portal_dns_stats(uint32_t *fwd, uint32_t *fail)
{
    *fwd = s_dns_fwd;
    *fail = s_dns_fail;
}

void portal_set_dns(uint32_t upstream_dns)
{
    s_upstream_dns = upstream_dns;
}

void portal_set_uplink(bool up)
{
    if (s_uplink_up != up) {
        ESP_LOGI(TAG, "uplink %s: %s", up ? "up" : "down",
                 up ? "normal DNS and connectivity probes" : "captive portal mode");
    }
    s_uplink_up = up;
}

esp_err_t portal_load(portal_cfg_t *cfg)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }

    memset(cfg, 0, sizeof(*cfg));
    size_t len = sizeof(cfg->ssid);
    err = nvs_get_str(h, "ssid", cfg->ssid, &len);
    len = sizeof(cfg->pass);
    nvs_get_str(h, "pass", cfg->pass, &len);
    len = sizeof(cfg->key);
    nvs_get_str(h, "key", cfg->key, &len);
    nvs_close(h);

    return (err == ESP_OK && cfg->ssid[0]) ? ESP_OK : ESP_ERR_NOT_FOUND;
}

esp_err_t portal_save(const portal_cfg_t *cfg)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    nvs_set_str(h, "ssid", cfg->ssid);
    nvs_set_str(h, "pass", cfg->pass);
    nvs_set_str(h, "key", cfg->key);
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

/* ------------------------------------------------------------------ dns */

/* Answers every A query with the AP address and everything else with NOERROR/0 answers.
 * That is what makes the captive portal popup work, and it is also where MagicDNS
 * answers will go later. */
static void dns_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "dns socket failed");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "dns bind failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    /* Separate socket for forwarding: the client-facing socket must never block on an
     * upstream reply, or one slow query stalls resolution for every client. */
    int up = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (up >= 0) {
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    ESP_LOGI(TAG, "dns resolver listening on :53 (catch-all until uplink, forward after)");

    uint8_t rx[512], tx[512];
    while (true) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&from, &from_len);
        if (n < 12) {
            continue;
        }

        int q_end = 12;
        while (q_end < n && rx[q_end] != 0) {
            q_end += (int)rx[q_end] + 1;
        }
        q_end += 1 + 4; /* root label + qtype + qclass */
        if (q_end > n) {
            continue;
        }
        uint16_t qtype = (uint16_t)((rx[q_end - 4] << 8) | rx[q_end - 3]);

        if (s_uplink_up) {
            /* With a real uplink, act as a forwarder: ESP-IDF's DHCP server advertises
             * this address as the client's resolver, so answering anything else (or
             * refusing) leaves clients with no DNS and no internet. */
            uint32_t upstream = s_upstream_dns ? s_upstream_dns : htonl(0x01010101);
            struct sockaddr_in to = {
                .sin_family = AF_INET,
                .sin_port = htons(53),
                .sin_addr.s_addr = upstream,
            };
            if (up < 0) {
                ESP_LOGW(TAG, "dns: no upstream socket");
                continue;
            }
            int sent = sendto(up, rx, (size_t)n, 0, (struct sockaddr *)&to, sizeof(to));
            if (sent <= 0) {
                ESP_LOGW(TAG, "dns: forward sendto failed for upstream %08x",
                         (unsigned)upstream);
                continue;
            }
            struct sockaddr_in reply_from;
            socklen_t rl = sizeof(reply_from);
            int rn = recvfrom(up, tx, sizeof(tx), 0, (struct sockaddr *)&reply_from, &rl);
            if (rn > 12) {
                s_dns_fwd++;
                sendto(sock, tx, (size_t)rn, 0, (struct sockaddr *)&from, from_len);
            } else {
                s_dns_fail++;
                ESP_LOGW(TAG, "dns: no upstream reply for upstream %08x (rn=%d)",
                         (unsigned)upstream, rn);
            }
            continue;
        }

        memcpy(tx, rx, (size_t)q_end);
        tx[2] = 0x81; /* QR=1, opcode 0, RD=1 */
        tx[3] = 0x80; /* RA=1, rcode 0 */
        uint8_t answers = (qtype == 1) ? 1 : 0;
        tx[6] = 0;
        tx[7] = answers;
        tx[8] = tx[9] = tx[10] = tx[11] = 0;

        int out = q_end;
        if (answers) {
            static const uint8_t ans[] = {
                0xC0, 0x0C,             /* name: pointer to question */
                0x00, 0x01,             /* type A */
                0x00, 0x01,             /* class IN */
                0x00, 0x00, 0x00, 0x3C, /* ttl 60 */
                0x00, 0x04,             /* rdlength */
                192, 168, 4, 1,         /* AP address */
            };
            memcpy(tx + q_end, ans, sizeof(ans));
            out += (int)sizeof(ans);
        }
        sendto(sock, tx, (size_t)out, 0, (struct sockaddr *)&from, from_len);
    }
}

/* ------------------------------------------------------------------ http */

static const char *SETUP_HTML =
    "<!doctype html><html><head><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Tailnet Gadget</title><style>"
    "body{font:16px system-ui,sans-serif;margin:0;background:#111;color:#eee;padding:20px}"
    "h1{font-size:20px;margin:0 0 4px}p.sub{color:#888;margin:0 0 20px;font-size:13px}"
    "label{display:block;margin:18px 0 6px;font-size:13px;color:#aaa}"
    "input{width:100%;box-sizing:border-box;padding:12px;border-radius:8px;border:1px solid #333;"
    "background:#1b1b1b;color:#eee;font-size:16px}"
    ".net{display:flex;justify-content:space-between;padding:12px;border:1px solid #333;"
    "border-radius:8px;margin-bottom:8px;cursor:pointer;background:#1b1b1b}"
    ".net.on{border-color:#4ade80;background:#14311f}"
    ".net small,.peer small{color:#888}"
    ".peer{display:flex;justify-content:space-between;padding:8px 12px;border:1px solid #333;"
    "border-radius:8px;margin-top:6px;background:#1b1b1b;font-size:13px}"
    "button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:8px;"
    "background:#2563eb;color:#fff;font-size:16px;font-weight:600}"
    "#msg{margin-top:16px;font-size:14px;color:#fbbf24;white-space:pre-wrap}"
    "</style></head><body>"
    "<h1>Tailnet Router</h1>"
    "<div id=st style='font-size:13px;color:#9ca3af;line-height:1.7;margin:0 0 18px;"
    "padding:12px;border:1px solid #262626;border-radius:8px;background:#161616'>"
    "reading status...</div>"
    "<p class=sub>Pick the WiFi this gadget should use for internet.</p>"
    "<div id=nets><small style='color:#888'>Scanning...</small></div>"
    "<button onclick=resc() style='background:#333;margin-top:0'>Rescan</button>"
    "<label>WiFi password</label><input id=pw type=password autocomplete=current-password>"
    "<label>Tailscale auth key (only needed the first time)</label>"
    "<input id=key type=password placeholder='tskey-auth-...'>"
    "<button onclick=save()>Save and connect</button><div id=msg></div>"
    "<script>let sel='';"
    "function resc(){document.getElementById('nets').innerHTML='<small style=\"color:#888\">Scanning...</small>';"
    "fetch('/scan.json').then(r=>r.json()).then(j=>{const t=j.networks||[];if(!t.length){"
    "document.getElementById('nets').innerHTML='<small style=\"color:#888\">No networks found</small>';return;}"
    "document.getElementById('nets').innerHTML=t.map(n=>"
    "`<div class=net id='n_${btoa(n.ssid)}' onclick=\"pick('${n.ssid.replace(/'/g,\"\\\\'\")}',this)\">"
    "<span>${n.ssid}</span><small>${n.rssi} dBm${n.auth?'':' open'}</small></div>`).join('');});}"
    "function pick(s,e){sel=s;document.querySelectorAll('.net').forEach(x=>x.classList.remove('on'));"
    "e.classList.add('on');}"
    "function save(){if(!sel){document.getElementById('msg').textContent='Pick a network first.';return;}"
    "document.getElementById('msg').textContent='Saving...';"
    "fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({ssid:sel,pass:document.getElementById('pw').value,"
    "key:document.getElementById('key').value})}).then(r=>r.json()).then(j=>{"
    "document.getElementById('msg').textContent=j.message||(j.ok?'Saved.':'Failed.');});}"
    "resc();"
    "function poll(){fetch('/status.json').then(r=>r.json()).then(j=>{"
    "var u=j.uplink?('connected to '+j.ssid+' ('+j.rssi+' dBm)'+(j.ip?', IP '+j.ip:''))"
    ":'NOT CONNECTED';"
    "var t=j.tailnet?('up '+j.tailnet_ip):'DOWN';"
    "var ps=j.peers||[];"
    "var rows=ps.map(function(x){return '<div class=peer><span>'+(x.host||'unknown')"
    "+'</span><small>'+x.ip+(x.online?(x.direct?' online direct':' online via DERP')"
    ":' offline')+'</small></div>';}).join('');"
    "if(!rows){rows='<div class=peer><span>no tailnet devices</span></div>';}"
    "document.getElementById('st').innerHTML='Uplink: '+u+'<br>Tailnet: '+t"
    "+'<br>Clients: '+j.clients+'<br>Tailnet devices: '+(j.peers_online||0)+' online / '"
    "+(j.peers_total||0)+' total<div style=margin-top:10px>'+rows+'</div>';"
    "}).catch(()=>{});}"
    "poll();setInterval(poll,5000);</script></body></html>";

static esp_err_t root_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, SETUP_HTML, HTTPD_RESP_USE_STRLEN);
}

char *portal_scan_json(void)
{
    wifi_scan_config_t sc = {.show_hidden = false};
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) {
        return NULL;
    }

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    if (count > SCAN_MAX_AP) {
        count = SCAN_MAX_AP;
    }

    wifi_ap_record_t *recs = calloc(count ? count : 1, sizeof(wifi_ap_record_t));
    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "networks");
    if (recs && esp_wifi_scan_get_ap_records(&count, recs) == ESP_OK) {
        for (int i = 0; i < count; i++) {
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "ssid", (const char *)recs[i].ssid);
            cJSON_AddNumberToObject(o, "rssi", recs[i].rssi);
            cJSON_AddBoolToObject(o, "auth", recs[i].authmode != WIFI_AUTH_OPEN);
            cJSON_AddItemToArray(arr, o);
        }
    }
    free(recs);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

static esp_err_t scan_get(httpd_req_t *req)
{
    char *json = portal_scan_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, json ? json : "{\"networks\":[]}");
    free(json);
    return err;
}

static void restart_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

static esp_err_t save_post(httpd_req_t *req)
{
    char body[640];
    int total = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int got = httpd_req_recv(req, body, (size_t)total);
    if (got <= 0) {
        httpd_resp_sendstr(req, "{\"ok\":false,\"message\":\"empty body\"}");
        return ESP_OK;
    }
    body[got] = '\0';

    cJSON *j = cJSON_Parse(body);
    if (!j) {
        httpd_resp_sendstr(req, "{\"ok\":false,\"message\":\"bad json\"}");
        return ESP_OK;
    }

    portal_cfg_t old, cfg = {0};
    portal_load(&old); /* may fail on first run; zeroed by the callee */

    const char *ssid = cJSON_GetStringValue(cJSON_GetObjectItem(j, "ssid"));
    const char *pass = cJSON_GetStringValue(cJSON_GetObjectItem(j, "pass"));
    const char *key = cJSON_GetStringValue(cJSON_GetObjectItem(j, "key"));
    if (!ssid || !ssid[0]) {
        cJSON_Delete(j);
        httpd_resp_sendstr(req, "{\"ok\":false,\"message\":\"no ssid\"}");
        return ESP_OK;
    }
    snprintf(cfg.ssid, sizeof(cfg.ssid), "%s", ssid);
    snprintf(cfg.pass, sizeof(cfg.pass), "%s", pass ? pass : "");
    snprintf(cfg.key, sizeof(cfg.key), "%s", (key && key[0]) ? key : old.key);
    cJSON_Delete(j);

    portal_save(&cfg);
    gadget_apply_wifi(cfg.ssid, cfg.pass);

    bool key_changed = strcmp(cfg.key, old.key) != 0;
    ESP_LOGI(TAG, "provisioned ssid=\"%s\" key=%s", cfg.ssid,
             key_changed ? "changed, restarting" : "unchanged");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, key_changed
        ? "{\"ok\":true,\"message\":\"Saved. Restarting to apply the tailnet key, "
          "reconnect in a few seconds.\"}"
        : "{\"ok\":true,\"message\":\"Saved. Connecting to that network now.\"}");

    if (key_changed) {
        xTaskCreate(restart_task, "portal_rst", 2048, NULL, 3, NULL);
    }
    return ESP_OK;
}

/* Captive portal probes: any URL the OS opens lands on the setup page. */
static esp_err_t status_json_get(httpd_req_t *req)
{
    char *json = gadget_status_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, json ? json : "{}");
    free(json);
    return err;
}

static esp_err_t probe_get(httpd_req_t *req)
{
    if (s_uplink_up) {
        /* Real internet exists: answer the OS probe honestly so the client keeps using
         * this network instead of silently routing around it over mobile data. */
        httpd_resp_set_status(req, "204 No Content");
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
        return httpd_resp_send(req, NULL, 0);
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://" AP_GW_IP "/");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t not_found(httpd_req_t *req, httpd_err_code_t err)
{
    if (s_uplink_up) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "not found");
    }
    return probe_get(req);
}

esp_err_t portal_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    static httpd_handle_t server;
    if (server) {
        return ESP_OK;
    }
    if (httpd_start(&server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "http server failed to start");
        return ESP_FAIL;
    }

    const httpd_uri_t uris[] = {
        {.uri = "/", .method = HTTP_GET, .handler = root_get},
        {.uri = "/scan.json", .method = HTTP_GET, .handler = scan_get},
        {.uri = "/status.json", .method = HTTP_GET, .handler = status_json_get},
        {.uri = "/save", .method = HTTP_POST, .handler = save_post},
        {.uri = "/generate_204", .method = HTTP_GET, .handler = probe_get},
        {.uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = probe_get},
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(server, &uris[i]);
    }
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, not_found);

    xTaskCreate(dns_task, "portal_dns", 4096, NULL, 4, NULL);
    ESP_LOGI(TAG, "setup page on http://%s/", AP_GW_IP);
    return ESP_OK;
}
