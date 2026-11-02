/**
 * @file portal.h
 * @brief First-run provisioning: SoftAP + HTTP setup page + catch-all DNS.
 *
 * Flow: board boots with no credentials -> AP "tailnet-gadget" is up -> the phone or
 * laptop that joins it gets a captive-portal popup (or opens http://192.168.4.1) ->
 * picks a network from a live scan, types the password, optionally pastes the Tailscale
 * auth key -> credentials go to NVS -> the gadget joins that network and the tailnet.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

typedef struct {
    char ssid[33];
    char pass[65];
    char key[96]; /* tskey-auth-... */
} portal_cfg_t;

/* Load saved provisioning from NVS. Returns ESP_ERR_NOT_FOUND if nothing saved. */
esp_err_t portal_load(portal_cfg_t *cfg);

/* Persist provisioning to NVS. */
esp_err_t portal_save(const portal_cfg_t *cfg);

/* Upstream resolver (network byte order) used for forwarding once an uplink exists. */
void portal_set_dns(uint32_t upstream_dns);

/* Resolver counters: queries forwarded upstream vs failed. */
void portal_dns_stats(uint32_t *fwd, uint32_t *fail);

/* Tell the portal whether a real uplink exists (drives captive-portal vs normal mode). */
void portal_set_uplink(bool up);

/* Start the HTTP setup server (port 80) and the catch-all DNS responder (port 53). */
esp_err_t portal_start(void);

/* Built by the app: uplink state, tailnet state, client count, as JSON. Caller frees. */
char *gadget_status_json(void);

/* Run a WiFi scan and return the results as a JSON object. Caller frees the string.
 * NULL on failure. Exposed so the on-device self-test can exercise the scan path. */
char *portal_scan_json(void);
