#pragma once

// Wi-Fi credentials.
#define APP_WIFI_SSID "YOUR_WIFI_SSID"
#define APP_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"

// MQTT broker settings (TLS).
#define APP_MQTT_HOST "your-mqtt-host.example.com"
#define APP_MQTT_PORT 8883
#define APP_MQTT_USER ""
#define APP_MQTT_PASSWORD ""

// Device identity and topic layout.
#define APP_DEVICE_ID "esp32-fota-01"
#define APP_MQTT_TELEMETRY_TOPIC "devices/esp32-fota-01/telemetry"
#define APP_MQTT_COMMAND_TOPIC "devices/esp32-fota-01/commands"
#define APP_MQTT_STATUS_TOPIC "devices/esp32-fota-01/status"

// OTA manifest endpoint.
#define APP_MANIFEST_URL "https://example.com/firmware/manifest.json"

// Set to 0 in production and provide APP_ROOT_CA.
#define APP_USE_INSECURE_TLS 1

// Root CA for HTTPS/MQTT TLS when APP_USE_INSECURE_TLS is 0.
static const char APP_ROOT_CA[] = R"EOF(
-----BEGIN CERTIFICATE-----
REPLACE_WITH_ROOT_CA
-----END CERTIFICATE-----
)EOF";

#define APP_TELEMETRY_INTERVAL_MS 30000UL
#define APP_UPDATE_CHECK_INTERVAL_MS 300000UL
