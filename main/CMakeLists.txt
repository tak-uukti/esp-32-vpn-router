idf_component_register(SRCS "gadget_main.c" "portal.c"
                       INCLUDE_DIRS "."
                       REQUIRES tailtiny esp_wifi esp_netif nvs_flash esp_event
                                esp_http_server esp_http_client json)
