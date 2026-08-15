#include "gpio_reporter.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include <cJSON.h>

extern "C" {
    #include "esp_timer.h"
    #include "driver/gpio.h"
    #include "esp_log.h"
}

static const char* TAG = "GpioReporter";

// Static instance for ISR handler
static GpioReporter* g_gpio_reporter_instance = nullptr;

GpioReporter::GpioReporter() {
    g_gpio_reporter_instance = this;
}

GpioReporter::~GpioReporter() {
    stop();
    g_gpio_reporter_instance = nullptr;
}

bool GpioReporter::start(const GpioConfig& config) {
    if (running_) {
        LOG_WARNING(TAG, "GPIO Reporter already running");
        return true;
    }

    config_ = config;

    if (!config_.enabled) {
        LOG_INFO(TAG, "GPIO Reporter disabled in configuration");
        return true;
    }

    LOG_INFO(TAG, "Starting GPIO Reporter...");

    // Initialize GPIO pins
    if (!initializeOutputs()) {
        LOG_ERROR(TAG, "Failed to initialize GPIO outputs");
        return false;
    }

    if (!initializeInputs()) {
        LOG_ERROR(TAG, "Failed to initialize GPIO inputs");
        cleanupGPIO();
        return false;
    }

    // Create input event queue
    input_queue_ = xQueueCreate(10, sizeof(GpioInputEvent));
    if (!input_queue_) {
        LOG_ERROR(TAG, "Failed to create input queue");
        cleanupGPIO();
        return false;
    }

    // Create output task for LED/buzzer control
    BaseType_t result = xTaskCreate(
        outputTaskWrapper,
        "gpio_output",
        4096,
        this,
        5,  // Priority
        &output_task_
    );

    if (result != pdPASS) {
        LOG_ERROR(TAG, "Failed to create output task");
        vQueueDelete(input_queue_);
        cleanupGPIO();
        return false;
    }

    // Create input task for button handling
    result = xTaskCreate(
        inputTaskWrapper,
        "gpio_input",
        3072,
        this,
        4,  // Priority
        &input_task_
    );

    if (result != pdPASS) {
        LOG_ERROR(TAG, "Failed to create input task");
        vTaskDelete(output_task_);
        vQueueDelete(input_queue_);
        cleanupGPIO();
        return false;
    }

    running_ = true;
    current_level_ = GpioOutputLevel::OFF;

    LOG_INFO(TAG, "GPIO Reporter started successfully");
    return true;
}

void GpioReporter::stop() {
    if (!running_) return;

    LOG_INFO(TAG, "Stopping GPIO Reporter...");
    running_ = false;

    // Clean up tasks
    if (output_task_) {
        vTaskDelete(output_task_);
        output_task_ = nullptr;
    }

    if (input_task_) {
        vTaskDelete(input_task_);
        input_task_ = nullptr;
    }

    // Clean up queue
    if (input_queue_) {
        vQueueDelete(input_queue_);
        input_queue_ = nullptr;
    }

    cleanupGPIO();

    // Turn off all outputs
    current_level_ = GpioOutputLevel::OFF;
    updateOutputs();

    LOG_INFO(TAG, "GPIO Reporter stopped");
}

bool GpioReporter::setOutputLevel(GpioOutputLevel level) {
    if (!running_ || !config_.enabled) {
        return false;
    }

    current_level_ = level;
    alert_start_time_ = esp_timer_get_time() / 1000; // Convert to ms
    alert_active_ = (level != GpioOutputLevel::OFF);
    alert_acknowledged_ = false;

    LOG_INFOF(TAG, "GPIO output level set to: %d", (int)level);
    return true;
}

bool GpioReporter::sendAlert(GpioOutputLevel level, const std::string& message) {
    LOG_INFOF(TAG, "GPIO Alert [%d]: %s", (int)level, message.c_str());
    return setOutputLevel(level);
}

void GpioReporter::setInputCallback(GpioInputCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    input_callback_ = callback;
}

void GpioReporter::acknowledgeAlert() {
    alert_acknowledged_ = true;
    LOG_INFO(TAG, "Alert acknowledged via GPIO");
}

void GpioReporter::resetAlerts() {
    current_level_ = GpioOutputLevel::OFF;
    alert_active_ = false;
    alert_acknowledged_ = false;
    LOG_INFO(TAG, "All alerts reset via GPIO");
}

std::string GpioReporter::getStatusJSON() const {
    cJSON* root = cJSON_CreateObject();
    if (!root) return "{}";

    cJSON_AddBoolToObject(root, "running", running_);
    cJSON_AddBoolToObject(root, "enabled", config_.enabled);
    cJSON_AddNumberToObject(root, "current_level", (int)current_level_.load());
    cJSON_AddBoolToObject(root, "alert_active", alert_active_);
    cJSON_AddBoolToObject(root, "alert_acknowledged", alert_acknowledged_);

    // GPIO pin configuration
    cJSON* pins = cJSON_CreateObject();
    cJSON_AddNumberToObject(pins, "led_critical", config_.led_critical);
    cJSON_AddNumberToObject(pins, "led_warning", config_.led_warning);
    cJSON_AddNumberToObject(pins, "led_info", config_.led_info);
    cJSON_AddNumberToObject(pins, "led_success", config_.led_success);
    cJSON_AddNumberToObject(pins, "buzzer", config_.buzzer);
    cJSON_AddItemToObject(root, "pins", pins);

    char* json_string = cJSON_PrintUnformatted(root);
    std::string result = json_string ? json_string : "{}";
    if (json_string) free(json_string);
    cJSON_Delete(root);

    return result;
}

// Static task wrappers
void GpioReporter::outputTaskWrapper(void* params) {
    static_cast<GpioReporter*>(params)->outputTask();
}

void GpioReporter::inputTaskWrapper(void* params) {
    static_cast<GpioReporter*>(params)->inputTask();
}

void IRAM_ATTR GpioReporter::gpioISRHandler(void* arg) {
    gpio_num_t gpio_num = (gpio_num_t)(uintptr_t)arg;

    if (g_gpio_reporter_instance && g_gpio_reporter_instance->input_queue_) {
        GpioInputEvent event = GpioInputEvent::UNKNOWN;

        // Map GPIO pin to event
        if (gpio_num == g_gpio_reporter_instance->config_.btn_acknowledge) {
            event = GpioInputEvent::ACKNOWLEDGE;
        } else if (gpio_num == g_gpio_reporter_instance->config_.btn_reset) {
            event = GpioInputEvent::RESET;
        } else if (gpio_num == g_gpio_reporter_instance->config_.btn_learning) {
            event = GpioInputEvent::ENABLE_LEARNING;
        } else if (gpio_num == g_gpio_reporter_instance->config_.btn_maintenance) {
            event = GpioInputEvent::MAINTENANCE;
        }

        BaseType_t high_task_awoken = pdFALSE;
        xQueueSendFromISR(g_gpio_reporter_instance->input_queue_, &event, &high_task_awoken);

        if (high_task_awoken) {
            portYIELD_FROM_ISR();
        }
    }
}

void GpioReporter::outputTask() {
    LOG_INFO(TAG, "GPIO output task started");

    while (running_) {
        updateOutputs();
        vTaskDelay(pdMS_TO_TICKS(100)); // Update every 100ms
    }

    LOG_INFO(TAG, "GPIO output task stopped");
}

void GpioReporter::inputTask() {
    LOG_INFO(TAG, "GPIO input task started");

    GpioInputEvent event;
    uint64_t last_event_time = 0;

    while (running_) {
        if (xQueueReceive(input_queue_, &event, pdMS_TO_TICKS(100)) == pdTRUE) {
            uint64_t now = esp_timer_get_time() / 1000;

            // Debounce check
            if (now - last_event_time < config_.debounce_ms) {
                continue;
            }
            last_event_time = now;

            LOG_INFOF(TAG, "GPIO input event: %d", (int)event);

            // Handle internal events
            switch (event) {
                case GpioInputEvent::ACKNOWLEDGE:
                    acknowledgeAlert();
                    break;
                case GpioInputEvent::RESET:
                    resetAlerts();
                    break;
                default:
                    break;
            }

            // Call external callback
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                if (input_callback_) {
                    input_callback_(event);
                }
            }
        }
    }

    LOG_INFO(TAG, "GPIO input task stopped");
}

bool GpioReporter::initializeOutputs() {
    LOG_INFO(TAG, "Initializing GPIO outputs...");

    // Configure LED pins
    gpio_config_t io_conf = {};
    io_conf.intr_type = GPIO_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = (1ULL << config_.led_critical) |
                          (1ULL << config_.led_warning) |
                          (1ULL << config_.led_info) |
                          (1ULL << config_.led_success) |
                          (1ULL << config_.buzzer);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;

    esp_err_t ret = gpio_config(&io_conf);
    if (ret != ESP_OK) {
        LOG_ERRORF(TAG, "Failed to configure output GPIOs: %s", esp_err_to_name(ret));
        return false;
    }

    // Set all outputs to OFF initially
    setLED(config_.led_critical, false);
    setLED(config_.led_warning, false);
    setLED(config_.led_info, false);
    setLED(config_.led_success, false);
    setBuzzer(false);

    LOG_INFO(TAG, "GPIO outputs initialized successfully");
    return true;
}

bool GpioReporter::initializeInputs() {
    LOG_INFO(TAG, "Initializing GPIO inputs...");

    // Configure button pins
    gpio_config_t io_conf = {};
    io_conf.intr_type = GPIO_INTR_NEGEDGE; // Trigger on falling edge
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pin_bit_mask = (1ULL << config_.btn_acknowledge) |
                          (1ULL << config_.btn_reset) |
                          (1ULL << config_.btn_learning) |
                          (1ULL << config_.btn_maintenance);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE; // Enable pull-up for buttons

    esp_err_t ret = gpio_config(&io_conf);
    if (ret != ESP_OK) {
        LOG_ERRORF(TAG, "Failed to configure input GPIOs: %s", esp_err_to_name(ret));
        return false;
    }

    // Install GPIO ISR handler
    ret = gpio_install_isr_service(0);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        LOG_ERRORF(TAG, "Failed to install GPIO ISR service: %s", esp_err_to_name(ret));
        return false;
    }

    // Add ISR handlers for each button
    gpio_isr_handler_add(config_.btn_acknowledge, gpioISRHandler, (void*)(uintptr_t)config_.btn_acknowledge);
    gpio_isr_handler_add(config_.btn_reset, gpioISRHandler, (void*)(uintptr_t)config_.btn_reset);
    gpio_isr_handler_add(config_.btn_learning, gpioISRHandler, (void*)(uintptr_t)config_.btn_learning);
    gpio_isr_handler_add(config_.btn_maintenance, gpioISRHandler, (void*)(uintptr_t)config_.btn_maintenance);

    LOG_INFO(TAG, "GPIO inputs initialized successfully");
    return true;
}

void GpioReporter::cleanupGPIO() {
    // Remove ISR handlers
    gpio_isr_handler_remove(config_.btn_acknowledge);
    gpio_isr_handler_remove(config_.btn_reset);
    gpio_isr_handler_remove(config_.btn_learning);
    gpio_isr_handler_remove(config_.btn_maintenance);

    // Reset all pins to input mode
    gpio_reset_pin(config_.led_critical);
    gpio_reset_pin(config_.led_warning);
    gpio_reset_pin(config_.led_info);
    gpio_reset_pin(config_.led_success);
    gpio_reset_pin(config_.buzzer);
}

void GpioReporter::setLED(gpio_num_t pin, bool state) {
    gpio_set_level(pin, state ? 1 : 0);
}

void GpioReporter::setBuzzer(bool state) {
    if (config_.buzzer_enabled) {
        gpio_set_level(config_.buzzer, state ? 1 : 0);
    }
}

void GpioReporter::updateOutputs() {
    if (!running_ || !config_.enabled) {
        return;
    }

    uint64_t now = esp_timer_get_time() / 1000; // Convert to ms
    GpioOutputLevel level = current_level_;

    // Check if alert should timeout
    if (alert_active_ && !alert_acknowledged_ &&
        (now - alert_start_time_) > config_.alert_duration_ms) {
        alert_active_ = false;
        level = GpioOutputLevel::OFF;
    }

    // Handle blinking for active alerts
    bool should_blink = alert_active_ && !alert_acknowledged_;
    if (should_blink && (now - last_blink_time_) >= config_.blink_interval_ms) {
        blink_state_ = !blink_state_;
        last_blink_time_ = now;
    }

    bool output_state = should_blink ? blink_state_.load() : true;

    // Turn off all LEDs first
    setLED(config_.led_critical, false);
    setLED(config_.led_warning, false);
    setLED(config_.led_info, false);
    setLED(config_.led_success, false);
    setBuzzer(false);

    // Set appropriate LED based on level
    if (level != GpioOutputLevel::OFF && output_state) {
        switch (level) {
            case GpioOutputLevel::CRITICAL:
                setLED(config_.led_critical, true);
                setBuzzer(true); // Buzzer only for critical alerts
                break;
            case GpioOutputLevel::WARNING:
                setLED(config_.led_warning, true);
                break;
            case GpioOutputLevel::INFO:
                setLED(config_.led_info, true);
                break;
            case GpioOutputLevel::SUCCESS:
                setLED(config_.led_success, true);
                break;
            default:
                break;
        }
    }
}

// Static method to convert from reporting config
GpioConfig GpioConfig::fromReportingConfig(const GpioReportingConfig& reporting_config) {
    GpioConfig config;

    config.enabled = reporting_config.enabled;
    config.led_critical = static_cast<gpio_num_t>(reporting_config.pins.led_critical);
    config.led_warning = static_cast<gpio_num_t>(reporting_config.pins.led_warning);
    config.led_info = static_cast<gpio_num_t>(reporting_config.pins.led_info);
    config.led_success = static_cast<gpio_num_t>(reporting_config.pins.led_success);
    config.buzzer = static_cast<gpio_num_t>(reporting_config.pins.buzzer);
    config.btn_acknowledge = static_cast<gpio_num_t>(reporting_config.pins.btn_acknowledge);
    config.btn_reset = static_cast<gpio_num_t>(reporting_config.pins.btn_reset);
    config.btn_learning = static_cast<gpio_num_t>(reporting_config.pins.btn_learning);
    config.btn_maintenance = static_cast<gpio_num_t>(reporting_config.pins.btn_maintenance);
    config.buzzer_enabled = reporting_config.behavior.buzzer_enabled;
    config.alert_duration_ms = reporting_config.behavior.alert_duration_ms;
    config.blink_interval_ms = reporting_config.behavior.blink_interval_ms;
    config.debounce_ms = reporting_config.behavior.debounce_ms;

    return config;
}