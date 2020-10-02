#include "qingping_ble.h"
#include "esphome/core/log.h"
#include "esphome/core/helpers.h"

#ifdef ARDUINO_ARCH_ESP32

#include <vector>
#include "mbedtls/ccm.h"

namespace esphome {
namespace qingping_ble {

static const char *TAG = "qingping_ble";

bool parse_qingping_message(const std::vector<uint8_t> &message, QingpingParseResult &result) {
  result.has_encryption = (message[0] & 0x08) ? true : false;  // update encryption status
  // if (result.has_encryption) {
  //   ESP_LOGVV(TAG, "parse_qingping_message(): payload is encrypted, stop reading message.");
  //   return false;
  // }

  // Data point specs
  // Byte 0: type
  // Byte 1: fixed 0x10
  // Byte 2: length
  // Byte 3..3+len-1: data point value

  const uint8_t *raw = message.data() + result.raw_offset;
  const uint8_t *data = raw + 3;
  const uint8_t data_length = raw[2];

  if ((data_length < 1) || (data_length > 4)) {
    ESP_LOGVV(TAG, "parse_qingping_message(): payload has wrong size (%d)!", data_length);
    return false;
  }

 // ESP_LOGVV(TAG, "parse_qingping_message(): parsing message 0 (%a)!", raw[0]);

  // temperature, 2 bytes, 16-bit signed integer (LE), 0.1 °C
  else if ((raw[0] == 0x04) && (data_length == 2)) {
    const int16_t temperature = uint16_t(data[0]) | (uint16_t(data[1]) << 8);
    result.temperature = temperature / 10.0f;
  }
  // humidity, 2 bytes, 16-bit signed integer (LE), 0.1 %
  else if ((raw[0] == 0x06) && (data_length == 2)) {
    const int16_t humidity = uint16_t(data[0]) | (uint16_t(data[1]) << 8);
    result.humidity = humidity / 10.0f;
  }
  // battery, 1 byte, 8-bit unsigned integer, 1 %
  else if ((raw[0] == 0x0A) && (data_length == 1)) {
    result.battery_level = data[0];
  }
  // temperature + humidity, 4 bytes, 16-bit signed integer (LE) each, 0.1 °C, 0.1 %
  else if ((raw[0] == 0x0D) && (data_length == 4)) {
    const int16_t temperature = uint16_t(data[0]) | (uint16_t(data[1]) << 8);
    const int16_t humidity = uint16_t(data[2]) | (uint16_t(data[3]) << 8);
    result.temperature = temperature / 10.0f;
    result.humidity = humidity / 10.0f;
  }
  else {
    return false;
  }

  return true;
}

optional<QingpingParseResult> parse_qingping_header(const esp32_ble_tracker::ServiceData &service_data) {
  QingpingParseResult result;
  if (!service_data.uuid.contains(0x95, 0xFE) && !service_data.uuid.contains(0xCD, 0xFD)  ) {
    ESP_LOGVV(TAG, "parse_qingping_header(): no service data UUID magic bytes.");
    return {};
  }

  auto raw = service_data.data;
  result.has_data = ((raw[0] & 0x40) || (raw[0] & 0x08)) ? true : false;
  result.has_capability = (raw[0] & 0x20) ? true : false;
  result.has_encryption = false;

  if (!result.has_data) {
    ESP_LOGVV(TAG, "parse_qingping_header(): service data has no DATA flag.");
    return {};
  }

  static uint8_t last_frame_count = 0;
  // if (last_frame_count == raw[4]) {
  //   ESP_LOGVV(TAG, "parse_qingping_header(): duplicate data packet received (%d).", static_cast<int>(last_frame_count));
  //   result.is_duplicate = true;
  //   return {};
  // }
  last_frame_count = raw[4];
  result.is_duplicate = false;
  result.raw_offset = result.has_capability ? 12 : 11;

  if ((raw[0] == 0x08) && (raw[1] == 0x01)) {  // round body, e-ink display
    result.type = QingpingParseResult::TYPE_CGG1;
    result.name = "CGG1";
    result.raw_offset = 8;
  } else {
    ESP_LOGVV(TAG, "parse_qingping_header(): unknown device, no magic bytes.");
    return {};
  }

  return result;
}

bool decrypt_qingping_payload(std::vector<uint8_t> &raw, const uint8_t *bindkey, const uint64_t &address) {
  if (!((raw.size() == 19) || ((raw.size() >= 22) && (raw.size() <= 24)))) {
    ESP_LOGVV(TAG, "decrypt_qingping_payload(): data packet has wrong size (%d)!", raw.size());
    ESP_LOGVV(TAG, "  Packet : %s", hexencode(raw.data(), raw.size()).c_str());
    return false;
  }

  uint8_t mac_reverse[6] = {0};
  mac_reverse[5] = (uint8_t)(address >> 40);
  mac_reverse[4] = (uint8_t)(address >> 32);
  mac_reverse[3] = (uint8_t)(address >> 24);
  mac_reverse[2] = (uint8_t)(address >> 16);
  mac_reverse[1] = (uint8_t)(address >> 8);
  mac_reverse[0] = (uint8_t)(address >> 0);

  QingpingAESVector vector{.key = {0},
                         .plaintext = {0},
                         .ciphertext = {0},
                         .authdata = {0x11},
                         .iv = {0},
                         .tag = {0},
                         .keysize = 16,
                         .authsize = 1,
                         .datasize = 0,
                         .tagsize = 4,
                         .ivsize = 12};

  vector.datasize = (raw.size() == 19) ? raw.size() - 12 : raw.size() - 18;
  int cipher_pos = (raw.size() == 19) ? 5 : 11;

  const uint8_t *v = raw.data();

  memcpy(vector.key, bindkey, vector.keysize);
  memcpy(vector.ciphertext, v + cipher_pos, vector.datasize);
  memcpy(vector.tag, v + raw.size() - vector.tagsize, vector.tagsize);
  memcpy(vector.iv, mac_reverse, 6);             // MAC address reverse
  memcpy(vector.iv + 6, v + 2, 3);               // sensor type (2) + packet id (1)
  memcpy(vector.iv + 9, v + raw.size() - 7, 3);  // payload counter

  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);

  int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, vector.key, vector.keysize * 8);
  if (ret) {
    ESP_LOGVV(TAG, "decrypt_qingping_payload(): mbedtls_ccm_setkey() failed.");
    mbedtls_ccm_free(&ctx);
    return false;
  }

  ret = mbedtls_ccm_auth_decrypt(&ctx, vector.datasize, vector.iv, vector.ivsize, vector.authdata, vector.authsize,
                                 vector.ciphertext, vector.plaintext, vector.tag, vector.tagsize);
  if (ret) {
    uint8_t mac_address[6] = {0};
    memcpy(mac_address, mac_reverse + 5, 1);
    memcpy(mac_address + 1, mac_reverse + 4, 1);
    memcpy(mac_address + 2, mac_reverse + 3, 1);
    memcpy(mac_address + 3, mac_reverse + 2, 1);
    memcpy(mac_address + 4, mac_reverse + 1, 1);
    memcpy(mac_address + 5, mac_reverse, 1);
    ESP_LOGVV(TAG, "decrypt_qingping_payload(): authenticated decryption failed.");
    ESP_LOGVV(TAG, "  MAC address : %s", hexencode(mac_address, 6).c_str());
    ESP_LOGVV(TAG, "       Packet : %s", hexencode(raw.data(), raw.size()).c_str());
    ESP_LOGVV(TAG, "          Key : %s", hexencode(vector.key, vector.keysize).c_str());
    ESP_LOGVV(TAG, "           Iv : %s", hexencode(vector.iv, vector.ivsize).c_str());
    ESP_LOGVV(TAG, "       Cipher : %s", hexencode(vector.ciphertext, vector.datasize).c_str());
    ESP_LOGVV(TAG, "          Tag : %s", hexencode(vector.tag, vector.tagsize).c_str());
    mbedtls_ccm_free(&ctx);
    return false;
  }

  // replace encrypted payload with plaintext
  uint8_t *p = vector.plaintext;
  for (std::vector<uint8_t>::iterator it = raw.begin() + cipher_pos; it != raw.begin() + cipher_pos + vector.datasize;
       ++it) {
    *it = *(p++);
  }

  // clear encrypted flag
  raw[0] &= ~0x08;

  ESP_LOGVV(TAG, "decrypt_qingping_payload(): authenticated decryption passed.");
  ESP_LOGVV(TAG, "  Plaintext : %s, Packet : %d", hexencode(raw.data() + cipher_pos, vector.datasize).c_str(),
            static_cast<int>(raw[4]));

  mbedtls_ccm_free(&ctx);
  return true;
}

bool report_qingping_results(const optional<QingpingParseResult> &result, const std::string &address) {
  if (!result.has_value()) {
    ESP_LOGVV(TAG, "report_qingping_results(): no results available.");
    return false;
  }

  ESP_LOGD(TAG, "Got Qingping %s (%s):", result->name.c_str(), address.c_str());

  if (result->temperature.has_value()) {
    ESP_LOGD(TAG, "  Temperature: %.1f°C", *result->temperature);
  }
  if (result->humidity.has_value()) {
    ESP_LOGD(TAG, "  Humidity: %.1f%%", *result->humidity);
  }
  if (result->battery_level.has_value()) {
    ESP_LOGD(TAG, "  Battery Level: %.0f%%", *result->battery_level);
  }

  return true;
}

bool QingpingListener::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  return false;  // with true it's not showing device scans
}

}  // namespace qingping_ble
}  // namespace esphome

#endif
