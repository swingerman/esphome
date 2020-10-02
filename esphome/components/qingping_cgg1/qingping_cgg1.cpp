#include "qingping_cgg1.h"
#include "esphome/core/log.h"

#ifdef ARDUINO_ARCH_ESP32

namespace esphome {
namespace qingping_cgg1 {

static const char *TAG = "qingping_cgg1";

void QingpingCGG1::dump_config() {
  ESP_LOGCONFIG(TAG, "Qingping CGG1");
  LOG_SENSOR("  ", "Temperature", this->temperature_);
  LOG_SENSOR("  ", "Humidity", this->humidity_);
  LOG_SENSOR("  ", "Battery Level", this->battery_level_);
}

bool QingpingCGG1::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  if (device.address_uint64() != this->address_) {
    ESP_LOGVV(TAG, "parse_device(): unknown MAC address. %s / %s", device.address_uint64(), this->address_);
    return false;
  }
  ESP_LOGVV(TAG, "parse_device(): MAC address %s found.", device.address_str().c_str());

  bool success = false;
  for (auto &service_data : device.get_service_datas()) {
    auto res = qingping_ble::parse_qingping_header(service_data);
    if (!res.has_value()) {
      continue;
    }
    if (res->is_duplicate) {
      continue;
    }
    if (res->has_encryption) {
      ESP_LOGVV(TAG, "parse_device(): payload decryption is currently not supported on this device.");
      continue;
    }
    if (!(qingping_ble::parse_qingping_message(service_data.data, *res))) {
      continue;
    }
    if (!(qingping_ble::report_qingping_results(res, device.address_str()))) {
      continue;
    }
    if (res->temperature.has_value() && this->temperature_ != nullptr)
      this->temperature_->publish_state(*res->temperature);
    if (res->humidity.has_value() && this->humidity_ != nullptr)
      this->humidity_->publish_state(*res->humidity);
    if (res->battery_level.has_value() && this->battery_level_ != nullptr)
      this->battery_level_->publish_state(*res->battery_level);
    success = true;
  }

  if (!success) {
    return false;
  }

  return true;
}

}  // namespace qingping_cgg1
}  // namespace esphome

#endif
