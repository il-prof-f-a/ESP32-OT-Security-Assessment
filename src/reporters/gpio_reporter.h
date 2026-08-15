#pragma once
#include <string>
#include <mutex>
#include <atomic>
#include <map>
#include <functional>

extern "C" {
    #include "driver/gpio.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/queue.h"
}

// GPIO Output Levels for different alert types
enum class GpioOutputLevel {
    CRITICAL = 0,   // Red LED + Buzzer - Critical security incidents
    WARNING = 1,    // Yellow LED - Security warnings
    INFO = 2,       // Green LED - Informational/operations completed
    SUCCESS = 3,    // Blue LED - System healthy/learning completed
    OFF = 4         // All outputs off
};

// GPIO Input Events from physical controls
enum class GpioInputEvent {
    ACKNOWLEDGE = 0,     // Silence current alarms
    RESET = 1,          // Reset all alarm states
    ENABLE_LEARNING = 2, // Force enable learning mode
    MAINTENANCE = 3,     // Enter maintenance mode
    UNKNOWN = 4
};

// Forward declaration for configuration
struct GpioReportingConfig;

// Local GPIO configuration structure (simplified from config manager)
struct GpioConfig {
    // Output pins for visual/audio alerts
    gpio_num_t led_critical = GPIO_NUM_2;    // Red LED
    gpio_num_t led_warning = GPIO_NUM_4;     // Yellow LED
    gpio_num_t led_info = GPIO_NUM_5;        // Green LED
    gpio_num_t led_success = GPIO_NUM_18;    // Blue LED
    gpio_num_t buzzer = GPIO_NUM_19;         // Buzzer for critical alerts

    // Input pins for user controls
    gpio_num_t btn_acknowledge = GPIO_NUM_0;     // Boot button
    gpio_num_t btn_reset = GPIO_NUM_35;          // Reset button
    gpio_num_t btn_learning = GPIO_NUM_34;       // Learning enable button
    gpio_num_t btn_maintenance = GPIO_NUM_39;    // Maintenance mode button

    // Behavior settings
    bool buzzer_enabled = true;              // Enable/disable buzzer
    uint32_t alert_duration_ms = 5000;       // How long to keep alert active
    uint32_t blink_interval_ms = 500;        // LED blink interval for active alerts
    uint32_t debounce_ms = 50;               // Button debounce time

    bool enabled = true;                     // Enable/disable entire GPIO reporter

    // Constructor from reporting config
    static GpioConfig fromReportingConfig(const GpioReportingConfig& reporting_config);
};

// Input event callback type
using GpioInputCallback = std::function<void(GpioInputEvent event)>;

class GpioReporter {
public:
    GpioReporter();
    ~GpioReporter();

    // Configuration
    bool start(const GpioConfig& config);
    void stop();
    bool isRunning() const { return running_; }

    // Output control - called by reporting engine
    bool setOutputLevel(GpioOutputLevel level);
    bool sendAlert(GpioOutputLevel level, const std::string& message);

    // Input event handling
    void setInputCallback(GpioInputCallback callback);

    // Status and control
    GpioOutputLevel getCurrentLevel() const { return current_level_; }
    std::string getStatusJSON() const;
    void acknowledgeAlert();
    void resetAlerts();

private:
    GpioConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<GpioOutputLevel> current_level_{GpioOutputLevel::OFF};
    std::atomic<bool> alert_acknowledged_{false};

    // FreeRTOS components
    TaskHandle_t output_task_ = nullptr;
    TaskHandle_t input_task_ = nullptr;
    QueueHandle_t input_queue_ = nullptr;

    // Callback for input events
    GpioInputCallback input_callback_;
    std::mutex callback_mutex_;

    // Internal methods
    static void outputTaskWrapper(void* params);
    static void inputTaskWrapper(void* params);
    static void IRAM_ATTR gpioISRHandler(void* arg);

    void outputTask();
    void inputTask();

    bool initializeOutputs();
    bool initializeInputs();
    void cleanupGPIO();

    void setLED(gpio_num_t pin, bool state);
    void setBuzzer(bool state);
    void updateOutputs();

    // Alert timing
    uint64_t alert_start_time_ = 0;
    bool alert_active_ = false;
    std::atomic<uint64_t> last_blink_time_{0};
    std::atomic<bool> blink_state_{false};
};