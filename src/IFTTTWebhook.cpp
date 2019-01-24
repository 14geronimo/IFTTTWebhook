/* 
   IFTTTWebhook.cpp
   Created by John Romkey - https://romkey.com/
   March 24, 2018
 */

#ifndef ESP32
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#endif

#ifdef ESP32
#include <WiFi.h>
#include <HTTPClient.h>
#endif

#include "IFTTTWebhook.h"

IFTTTWebhook::IFTTTWebhook(const char* api_key, const char* event_name) : IFTTTWebhook::IFTTTWebhook(api_key, event_name, DEFAULT_IFTTT_FINGERPRINT) {
}

IFTTTWebhook::IFTTTWebhook(const char* api_key, const char* event_name, const char* ifttt_fingerprint) {
  _api_key = api_key;
  _event_name = event_name;
  _ifttt_fingerprint = ifttt_fingerprint;
}

int IFTTTWebhook::trigger() {
  return IFTTTWebhook::trigger(NULL, NULL, NULL);
}

int IFTTTWebhook::trigger(const char* value1) {
  return IFTTTWebhook::trigger(value1, NULL, NULL);
}

int IFTTTWebhook::trigger(const char* value1, const char* value2) {
  return IFTTTWebhook::trigger(value1, value2, NULL);
}

int IFTTTWebhook::trigger(const char* value1, const char* value2, const char* value3) {
  HTTPClient http;
  const char* ifttt_base = "https://maker.ifttt.com/trigger";

  // Compute URL length
  int url_length = 1 + strlen(ifttt_base) + strlen("/") + strlen(_event_name) + strlen("/with/key/") + strlen(_api_key);
  char ifttt_url[url_length];

  // Compute Payload length
  int payload_length = 37 + (value1 ? strlen(value1) : 0) + (value2 ? strlen(value2) : 0) + (value3 ? strlen(value3) : 0);
  char ifttt_payload[payload_length];

#ifdef IFTTT_WEBHOOK_DEBUG  
  Serial.print("URL length: ");
  Serial.println(url_length);
  Serial.print("Payload length: ");
  Serial.println(payload_length);
#endif

  // Compute URL
  snprintf(ifttt_url, url_length, "%s/%s/with/key/%s", ifttt_base, _event_name, _api_key);

  // Compute Payload (JSON), e.g. {value1:"A",value2:"B",value3:"C"}
  snprintf(ifttt_payload, payload_length, "{");

  if(value1) {
    strcat(ifttt_payload, "\"value1\":\"");
    strcat(ifttt_payload, value1);
    strcat(ifttt_payload, "\"");
    if(value2 || value3) {
      strcat(ifttt_payload, ",");
    }
  }

  if(value2) {
    strcat(ifttt_payload, "\"value2\":\"");
    strcat(ifttt_payload, value2);
    strcat(ifttt_payload, "\"");
    if(value3) {
      strcat(ifttt_payload, ",");
    }
  }

  if(value3) {
    strcat(ifttt_payload, "\"value3\":\"");
    strcat(ifttt_payload, value3);
    strcat(ifttt_payload, "\"");
  }

  strcat(ifttt_payload, "}");

#ifdef IFTTT_WEBHOOK_DEBUG
  Serial.print("URL: ");
  Serial.println(ifttt_url);
  Serial.print("Payload: ");
  Serial.println(ifttt_payload);
#endif

  // HTTPS POST with the root certificate method returns 'connection refused' with a ESP2 Dev Module board, using fingerprint in all cases
  // fingerprint: openssl s_client -connect maker.ifttt.com:443  < /dev/null 2>/dev/null | openssl x509 -fingerprint -noout | cut -d'=' -f2
  http.begin(ifttt_url, _ifttt_fingerprint);
  http.addHeader("Content-Type", "application/json");
  int httpCode = http.POST(ifttt_payload);

#ifdef IFTTT_WEBHOOK_DEBUG  
  Serial.printf("[HTTP] POST... code: %d\n", httpCode);
  if (httpCode > 0) {
    if(httpCode == HTTP_CODE_OK) {
      Serial.println(http.getString());
    }
  } else {
      Serial.printf("[HTTP] POST... failed, error %s\n", http.errorToString(httpCode).c_str());
  }
#endif

  http.end();

  return httpCode != HTTP_CODE_OK;
}
