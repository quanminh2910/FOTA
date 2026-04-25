#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <PubSubClient.h>
#include <Update.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <mbedtls/sha256.h>

#include "app_config.h"

#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "0.1.0"
#endif
// firmware info structure
struct FirmwareManifest {
  String version;
  String url;
  String sha256;
};
// MQTT client using secure Wi-Fi client for TLS support.
WiFiClientSecure mqttSecureClient;
PubSubClient mqttClient(mqttSecureClient);
// Timing variables for telemetry and update checks.
unsigned long lastTelemetryMs = 0;
unsigned long lastUpdateCheckMs = 0;

void configureTlsClient(WiFiClientSecure& client) { 
#if APP_USE_INSECURE_TLS
  client.setInsecure();
#else
  client.setCACert(APP_ROOT_CA);
#endif
  client.setTimeout(15000);
}

String bytesToHex(const uint8_t* bytes, size_t length) {
  const char* hex = "0123456789abcdef";
  String out;
  out.reserve(length * 2);

  for (size_t i = 0; i < length; ++i) {
    out += hex[(bytes[i] >> 4) & 0x0F];
    out += hex[bytes[i] & 0x0F];
  }

  return out;
}
// checks if candidate version is newer than current version
int compareSemver(const String& candidate, const String& current) {
  size_t i = 0;
  size_t j = 0;
  // Compare each segment of the version strings as integers
  while (i < candidate.length() || j < current.length()) {
    long a = 0;
    long b = 0;

    while (i < candidate.length() && candidate[i] != '.') {
      if (isDigit(candidate[i])) {
        a = (a * 10) + (candidate[i] - '0'); // convert char to int
      }
      ++i;
    }

    while (j < current.length() && current[j] != '.') {
      if (isDigit(current[j])) {
        b = (b * 10) + (current[j] - '0'); // convert char to int
      }
      ++j;
    }
    // candidate > current => 1
    // candidate < current => -1
    // candidate == current => 0 (continue to next segment)
    // Missing segments are treated as 0, so "1.2" == "1.2.0" and "1.2.1" > "1.2"
    if (a > b) {
      return 1;
    }

    if (a < b) {
      return -1;
    }

    if (i < candidate.length()) {
      ++i;
    }

    if (j < current.length()) {
      ++j;
    }
  }

  return 0;
}

void publishStatus(const char* state, const char* detail) {
  StaticJsonDocument<256> doc; // allocation on stack, no dynamic memory usage
  doc["device"] = APP_DEVICE_ID;
  doc["fw"] = FIRMWARE_VERSION;
  doc["state"] = state;
  doc["detail"] = detail;
  doc["uptime_ms"] = millis(); 

  char payload[256];
  const size_t written = serializeJson(doc, payload, sizeof(payload)); // returns the number of bytes written, not including the null terminator
  mqttClient.publish(APP_MQTT_STATUS_TOPIC, payload, written); 
}

bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(APP_WIFI_SSID, APP_WIFI_PASSWORD);

  Serial.print("Connecting to Wi-Fi");
  uint8_t attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 60) { // wait up to 30 seconds
    delay(500);
    Serial.print('.');
    ++attempts;
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) { // failed to connect
    Serial.println("Wi-Fi connection failed");
    return false;
  }

  Serial.print("Wi-Fi connected, IP: ");
  Serial.println(WiFi.localIP());
  return true;
}

bool connectMqtt() {
  if (mqttClient.connected()) {
    return true;
  }

  uint8_t attempts = 0;
  while (!mqttClient.connected() && attempts < 5) { // try up to 5 times with 1 second delay between attempts
    bool connected = false;

    if (strlen(APP_MQTT_USER) > 0) { // connect with username and password
      connected = mqttClient.connect(APP_DEVICE_ID, APP_MQTT_USER, APP_MQTT_PASSWORD); 
    } else { // connect without authentication
      connected = mqttClient.connect(APP_DEVICE_ID);
    }

    if (connected) { // subscribe to command topic and publish online status
      mqttClient.subscribe(APP_MQTT_COMMAND_TOPIC);
      publishStatus("online", "mqtt_connected");
      return true;
    }

    ++attempts;
    delay(1000);
  }

  return false;
}
// Fetches and parses the firmware manifest from the configured URL. 
// Returns true on success and false on failure. 
// The manifest is expected to be a JSON object containing at least "version" and "url" fields, and optionally a "sha256" field for integrity verification.
bool fetchManifest(FirmwareManifest& manifest) {
  WiFiClientSecure httpsClient;
  configureTlsClient(httpsClient);

  HTTPClient https;
  if (!https.begin(httpsClient, APP_MANIFEST_URL)) { // failed to initialize the connection
    Serial.println("Manifest request begin failed");
    return false;
  }

  const int httpCode = https.GET();
  if (httpCode != HTTP_CODE_OK) { // non-200 HTTP response code
    Serial.printf("Manifest request failed: HTTP %d\n", httpCode);
    https.end();
    return false;
  }

  StaticJsonDocument<1024> doc;
  const DeserializationError err = deserializeJson(doc, https.getString()); // deserialize the response body as JSON
  https.end();

  if (err) { // failed to parse JSON
    Serial.printf("Manifest parse error: %s\n", err.c_str());
    return false;
  }

  manifest.version = doc["version"] | "";
  manifest.url = doc["url"] | doc["firmware_url"] | ""; 
  manifest.sha256 = doc["sha256"] | ""; 
  manifest.sha256.toLowerCase();
  manifest.sha256.trim();

  if (manifest.version.isEmpty() || manifest.url.isEmpty()) { // if version or url is missing
    Serial.println("Manifest missing required fields");
    return false;
  }

  return true;
}

bool downloadAndInstall(const FirmwareManifest& manifest) {
  WiFiClientSecure httpsClient;
  configureTlsClient(httpsClient);

  HTTPClient https;
  if (!https.begin(httpsClient, manifest.url)) { // failed to initialize the connection
    Serial.println("Firmware request begin failed");
    return false;
  }

  int httpCode = https.GET();
  if (httpCode != HTTP_CODE_OK) { // non-200 HTTP response code
    Serial.printf("Firmware request failed: HTTP %d\n", httpCode);
    https.end();
    return false;
  }

  int remaining = https.getSize(); // content length from HTTP header, may be -1 if not provided by server
  if (!Update.begin(remaining > 0 ? static_cast<size_t>(remaining) : UPDATE_SIZE_UNKNOWN)) { // start the update process with the expected size, or unknown if not provided
    Serial.printf("Update.begin failed: %s\n", Update.errorString()); 
    https.end();
    return false;
  }

  WiFiClient* stream = https.getStreamPtr(); // get the underlying stream to read the firmware data
  // Initialize SHA256 context for integrity verification during download. 
  // This allows us to verify the firmware as it's being downloaded without needing to store it all
  mbedtls_sha256_context shaCtx; 
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts_ret(&shaCtx, 0);

  uint8_t buffer[1024];
  size_t totalWritten = 0;
  unsigned long lastDataAt = millis(); // track the last time we received data for timeout purposes

  while (https.connected() && (remaining > 0 || remaining == -1)) { // while the connection is open read data
    const size_t available = stream->available(); // check how many bytes are available to read

    if (available > 0) {
      const int toRead = available > sizeof(buffer) ? sizeof(buffer) : static_cast<int>(available); // if available data exceeds buffer size, read only up to buffer size
      const int readBytes = stream->readBytes(buffer, toRead); // read data into buffer

      if (readBytes <= 0) { // if read failed, skip this iteration and check for timeout
        continue;
      }

      if (Update.write(buffer, readBytes) != static_cast<size_t>(readBytes)) { // write the chunk to flash, if it fails abort the update
        Serial.printf("Update.write failed: %s\n", Update.errorString());
        Update.abort();
        https.end();
        mbedtls_sha256_free(&shaCtx);
        return false;
      }

      mbedtls_sha256_update_ret(&shaCtx, buffer, readBytes);// update the SHA256 hash with the new chunk
      totalWritten += static_cast<size_t>(readBytes);

      if (remaining > 0) { // decrease remaining byte count 
        remaining -= readBytes;
      }

      lastDataAt = millis(); // reset the timeout timer since we received data
    } else {
      if (millis() - lastDataAt > 15000UL) { // abort if we haven't received any data for 15 seconds
        Serial.println("Firmware download timed out");
        break;
      }
      delay(1);
    }
  }
  // Finalize the SHA256 hash and free the context
  uint8_t shaDigest[32];
  mbedtls_sha256_finish_ret(&shaCtx, shaDigest);
  mbedtls_sha256_free(&shaCtx);
  https.end(); 

  if (remaining > 0) {
    Serial.println("Firmware download incomplete");
    Update.abort();
    return false;
  }

  const String actualSha = bytesToHex(shaDigest, sizeof(shaDigest)); // verify the downloaded firmware against the expected SHA256 from the manifest
  if (!manifest.sha256.isEmpty() && actualSha != manifest.sha256) { 
    Serial.println("Firmware SHA256 mismatch");
    Update.abort();
    return false;
  }

  if (!Update.end(true)) { // update the firmware and finalize
    Serial.printf("Update.end failed: %s\n", Update.errorString());
    return false;
  }

  if (!Update.isFinished()) {
    Serial.println("Update was not fully written");
    return false;
  }

  Serial.printf("Firmware downloaded (%u bytes)\n", static_cast<unsigned>(totalWritten));
  return true;
}

bool checkForUpdates(bool force) {
  FirmwareManifest manifest;
  if (!fetchManifest(manifest)) {
    publishStatus("update_error", "manifest_fetch_failed");
    return false;
  }

  const int cmp = compareSemver(manifest.version, FIRMWARE_VERSION);
  if (!force && cmp <= 0) {
    return false;
  }

  Serial.printf("Updating from %s to %s\n", FIRMWARE_VERSION, manifest.version.c_str());
  publishStatus("updating", "download_started");

  if (!downloadAndInstall(manifest)) {
    publishStatus("update_error", "download_or_verify_failed");
    return false;
  }

  publishStatus("updated", "restarting");
  delay(500);
  ESP.restart();
  return true;
}

void publishTelemetry() {
  StaticJsonDocument<256> doc;
  doc["device"] = APP_DEVICE_ID;
  doc["fw"] = FIRMWARE_VERSION;
  doc["uptime_ms"] = millis();
  doc["rssi"] = WiFi.RSSI();
  doc["heap"] = ESP.getFreeHeap();

  char payload[256];
  const size_t written = serializeJson(doc, payload, sizeof(payload));
  mqttClient.publish(APP_MQTT_TELEMETRY_TOPIC, payload, written);
}

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String message;
  message.reserve(length);

  for (unsigned int i = 0; i < length; ++i) {
    message += static_cast<char>(payload[i]);
  }

  Serial.printf("MQTT command on %s: %s\n", topic, message.c_str());

  StaticJsonDocument<256> doc;
  const DeserializationError err = deserializeJson(doc, message);
  if (err) {
    publishStatus("command_error", "invalid_json");
    return;
  }

  const char* cmd = doc["cmd"] | "";
  if (strcmp(cmd, "check_update") == 0) {
    checkForUpdates(true);
    return;
  }

  if (strcmp(cmd, "reboot") == 0) {
    publishStatus("rebooting", "mqtt_command");
    delay(200);
    ESP.restart();
    return;
  }

  publishStatus("command_error", "unknown_command");
}

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("ESP32 cloud + FOTA runtime starting");
  Serial.printf("Firmware version: %s\n", FIRMWARE_VERSION);

  configureTlsClient(mqttSecureClient);
  mqttClient.setServer(APP_MQTT_HOST, APP_MQTT_PORT);
  mqttClient.setCallback(mqttCallback);
  mqttClient.setBufferSize(512);

  connectWiFi();
  connectMqtt();
  checkForUpdates(false);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  if (!mqttClient.connected()) {
    connectMqtt();
  }

  mqttClient.loop();

  const unsigned long now = millis();

  if (now - lastTelemetryMs >= APP_TELEMETRY_INTERVAL_MS) {
    lastTelemetryMs = now;
    publishTelemetry();
  }

  if (now - lastUpdateCheckMs >= APP_UPDATE_CHECK_INTERVAL_MS) {
    lastUpdateCheckMs = now;
    checkForUpdates(false);
  }
}