#include "offensive_testing_board_profile.h"

extern "C" {
#include "driver/gpio.h"
}

namespace {

constexpr int kTpoeReserved[] = {0, 2, 4, 5, 14, 18, 23};
constexpr int kS3Reserved[] = {4, 5, 6, 7, 9, 10, 11, 12, 13, 14};
constexpr int kP4Reserved[] = {9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 33,
                               34, 35, 39, 40, 41, 42, 43, 44, 49, 50, 51,
                               52, 53};
constexpr int kGuitionReserved[] = {9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                                    19, 28, 29, 30, 31, 32, 33, 34, 35, 39,
                                    40, 41, 42, 43, 44, 49, 50, 51, 52, 53,
                                    54};

constexpr OffensiveTestingBoardProfile kTpoeProfile{
    "t-poe-pro", 15, false, 1, kTpoeReserved,
    sizeof(kTpoeReserved) / sizeof(kTpoeReserved[0])};
constexpr OffensiveTestingBoardProfile kS3Profile{
    "esp32-s3-eth", 16, false, 1, kS3Reserved,
    sizeof(kS3Reserved) / sizeof(kS3Reserved[0])};
constexpr OffensiveTestingBoardProfile kP4Profile{
    "waveshare-esp32p4-eth", 16, false, 1, kP4Reserved,
    sizeof(kP4Reserved) / sizeof(kP4Reserved[0])};
constexpr OffensiveTestingBoardProfile kGuitionProfile{
    "guition-jc-esp32p4-m3-dev", 1, false, 1, kGuitionReserved,
    sizeof(kGuitionReserved) / sizeof(kGuitionReserved[0])};

bool isReserved(const OffensiveTestingBoardProfile& profile, int gpio) {
    for (std::size_t i = 0; i < profile.reserved_gpio_count; ++i) {
        if (profile.reserved_gpios[i] == gpio) return true;
    }
    return false;
}

}  // namespace

const OffensiveTestingBoardProfile& getOffensiveTestingBoardProfile() {
#if defined(BOARD_TPOE_PRO)
    return kTpoeProfile;
#elif defined(BOARD_ESP32_S3_ETH)
    return kS3Profile;
#elif defined(BOARD_WAVESHARE_ESP32P4_ETH)
    return kP4Profile;
#elif defined(BOARD_GUITION_JC_ESP32P4_M3_DEV)
    return kGuitionProfile;
#else
#error "Unsupported board: define exactly one supported BOARD_* macro"
#endif
}

bool isAllowedOffensiveTestingGpio(int gpio) {
    if (gpio < 0 || gpio >= static_cast<int>(GPIO_NUM_MAX)) return false;
    const auto& profile = getOffensiveTestingBoardProfile();
    return !isReserved(profile, gpio);
}
