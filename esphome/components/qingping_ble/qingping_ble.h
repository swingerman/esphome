#pragma once

#include "esphome/core/component.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"

#ifdef ARDUINO_ARCH_ESP32

namespace esphome {
namespace qingping_ble {

struct QingpingParseResult {
  enum {
    TYPE_HHCCJCY01,
    TYPE_GCLS002,
    TYPE_HHCCPOT002,
    TYPE_LYWSDCGQ,
    TYPE_LYWSD02,
    TYPE_CGG1,
    TYPE_LYWSD03MMC,
    TYPE_CGD1,
    TYPE_JQJCY01YM,
    TYPE_MUE4094RT,
    TYPE_WX08ZM,
    TYPE_MJYD02YLA
  } type;
  std::string name;
  optional<float> temperature;
  optional<float> humidity;
  optional<float> moisture;
  optional<float> conductivity;
  optional<float> illuminance;
  optional<float> formaldehyde;
  optional<float> battery_level;
  optional<float> tablet;
  optional<float> idle_time;
  optional<bool> is_active;
  optional<bool> has_motion;
  optional<bool> is_light;
  bool has_data;        // 0x40
  bool has_capability;  // 0x20
  bool has_encryption;  // 0x08
  bool is_duplicate;
  int raw_offset;
};

struct QingpingAESVector {
  uint8_t key[16];
  uint8_t plaintext[16];
  uint8_t ciphertext[16];
  uint8_t authdata[16];
  uint8_t iv[16];
  uint8_t tag[16];
  size_t keysize;
  size_t authsize;
  size_t datasize;
  size_t tagsize;
  size_t ivsize;
};

bool parse_qingping_message(const std::vector<uint8_t> &message, QingpingParseResult &result);
optional<QingpingParseResult> parse_qingping_header(const esp32_ble_tracker::ServiceData &service_data);
bool decrypt_qingping_payload(std::vector<uint8_t> &raw, const uint8_t *bindkey, const uint64_t &address);
bool report_qingping_results(const optional<QingpingParseResult> &result, const std::string &address);

class QingpingListener : public esp32_ble_tracker::ESPBTDeviceListener {
 public:
  bool parse_device(const esp32_ble_tracker::ESPBTDevice &device) override;
};

}  // namespace qingping_ble
}  // namespace esphome

#endif
