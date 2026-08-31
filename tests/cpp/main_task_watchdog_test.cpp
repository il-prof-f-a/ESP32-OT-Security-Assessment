#include "core/main_task_watchdog.h"
#include <cassert>
#include <cstdio>

namespace {
struct FakeSdk {
    bool initialized = true;
    bool subscribed = false;
    unsigned other_subscribers = 2;
    int add_calls = 0, delete_calls = 0, reset_calls = 0;
    int init_calls = 0, reconfigure_calls = 0;
    esp_err_t init_error = ESP_OK, config_error = ESP_OK;
    esp_err_t add_error = ESP_OK, delete_error = ESP_OK, reset_error = ESP_OK;
    esp_task_wdt_config_t config{};
} sdk;
const esp_task_wdt_config_t config{120000, 0, true};

void fresh() { sdk = FakeSdk{}; }
void no_feed(MainTaskWatchdog& wdt, uint32_t now) {
    esp_err_t result = ESP_FAIL;
    const int before = sdk.reset_calls;
    assert(!wdt.feedIfDue(now, result));
    assert(result == ESP_FAIL); // No fabricated success when nothing was attempted.
    assert(sdk.reset_calls == before);
}
void feed(MainTaskWatchdog& wdt, uint32_t now, esp_err_t expected = ESP_OK) {
    esp_err_t result = ESP_FAIL;
    const int before = sdk.reset_calls;
    assert(wdt.feedIfDue(now, result));
    assert(result == expected);
    assert(sdk.reset_calls == before + 1);
}
}

esp_err_t esp_task_wdt_init(const esp_task_wdt_config_t* cfg) {
    ++sdk.init_calls;
    if (sdk.initialized) return ESP_ERR_INVALID_STATE;
    if (sdk.init_error != ESP_OK) return sdk.init_error;
    sdk.initialized = true;
    sdk.config = *cfg;
    return ESP_OK;
}
esp_err_t esp_task_wdt_reconfigure(const esp_task_wdt_config_t* cfg) {
    ++sdk.reconfigure_calls;
    if (!sdk.initialized) return ESP_ERR_INVALID_STATE;
    if (sdk.config_error != ESP_OK) return sdk.config_error;
    sdk.config = *cfg;
    return ESP_OK;
}
esp_err_t esp_task_wdt_status(TaskHandle_t task) {
    assert(task == nullptr);
    if (!sdk.initialized) return ESP_ERR_INVALID_STATE;
    return sdk.subscribed ? ESP_OK : ESP_ERR_NOT_FOUND;
}
esp_err_t esp_task_wdt_add(TaskHandle_t task) {
    assert(task == nullptr);
    ++sdk.add_calls;
    if (!sdk.initialized) return ESP_ERR_INVALID_STATE;
    if (sdk.subscribed) return ESP_ERR_INVALID_ARG;
    if (sdk.add_error != ESP_OK) return sdk.add_error;
    sdk.subscribed = true;
    return ESP_OK;
}
esp_err_t esp_task_wdt_delete(TaskHandle_t task) {
    assert(task == nullptr);
    ++sdk.delete_calls;
    if (!sdk.initialized) return ESP_ERR_INVALID_STATE;
    if (!sdk.subscribed) return ESP_ERR_NOT_FOUND;
    if (sdk.delete_error != ESP_OK) return sdk.delete_error;
    sdk.subscribed = false;
    return ESP_OK;
}
esp_err_t esp_task_wdt_reset() {
    ++sdk.reset_calls;
    if (!sdk.initialized) return ESP_ERR_INVALID_STATE;
    if (!sdk.subscribed) return ESP_ERR_NOT_FOUND;
    return sdk.reset_error;
}

int main() {
    // Disabled: no registration, no feed, no changes to the global watchdog.
    fresh();
    MainTaskWatchdog disabled;
    assert(disabled.start(false, 100) == ESP_OK);
    assert(!disabled.subscribed());
    no_feed(disabled, 300);
    assert(sdk.add_calls == 0 && sdk.delete_calls == 0);
    assert(sdk.init_calls == 0 && sdk.reconfigure_calls == 0);
    assert(sdk.other_subscribers == 2);

    // An SDK build without auto-init is harmless when app monitoring is disabled.
    fresh();
    sdk.initialized = false;
    MainTaskWatchdog not_initialized;
    assert(not_initialized.start(false, 0) == ESP_OK);
    no_feed(not_initialized, 100);
    assert(sdk.init_calls == 0 && sdk.add_calls == 0);

    // Enabled: configuration, one subscription and feed cadence from subscription time.
    fresh();
    MainTaskWatchdog enabled;
    assert(enabled.configure(config) == ESP_OK);
    assert(sdk.init_calls == 0 && sdk.reconfigure_calls == 1);
    assert(sdk.config.timeout_ms == 120000 && sdk.config.idle_core_mask == 0);
    assert(sdk.config.trigger_panic);
    assert(enabled.start(true, 100) == ESP_OK);
    assert(enabled.subscribed() && sdk.add_calls == 1);
    no_feed(enabled, 109);
    feed(enabled, 110);
    no_feed(enabled, 119);
    feed(enabled, 120);

    // Explicit initialization is only used when SDK reconfigure reports not initialized.
    fresh();
    sdk.initialized = false;
    MainTaskWatchdog initialize;
    assert(initialize.configure(config) == ESP_OK);
    assert(sdk.init_calls == 1);
    assert(initialize.start(true, 0) == ESP_OK);
    feed(initialize, 10);

    // Failed init/configuration never subscribes a new task with an unknown timeout.
    fresh();
    sdk.initialized = false;
    sdk.init_error = ESP_ERR_NO_MEM;
    MainTaskWatchdog init_failed;
    assert(init_failed.configure(config) == ESP_ERR_NO_MEM);
    assert(init_failed.start(true, 0) == ESP_ERR_INVALID_STATE);
    no_feed(init_failed, 10);
    assert(sdk.add_calls == 0);
    fresh();
    sdk.config_error = ESP_FAIL;
    MainTaskWatchdog config_failed;
    assert(config_failed.configure(config) == ESP_FAIL);
    assert(config_failed.start(true, 0) == ESP_ERR_INVALID_STATE);
    no_feed(config_failed, 10);
    assert(sdk.init_calls == 0 && sdk.add_calls == 0);

    fresh();
    sdk.add_error = ESP_ERR_NO_MEM;
    MainTaskWatchdog add_failed;
    assert(add_failed.configure(config) == ESP_OK);
    assert(add_failed.start(true, 0) == ESP_ERR_NO_MEM);
    assert(!add_failed.subscribed());
    no_feed(add_failed, 10);

    // Existing main subscription is not duplicated or confused with other subscribers.
    fresh();
    sdk.subscribed = true;
    MainTaskWatchdog already;
    assert(already.configure(config) == ESP_OK);
    assert(already.start(true, 100) == ESP_OK);
    assert(sdk.add_calls == 0);
    feed(already, 110);
    assert(sdk.other_subscribers == 2);

    fresh();
    sdk.subscribed = true;
    MainTaskWatchdog remove_existing;
    assert(remove_existing.start(false, 0) == ESP_OK);
    assert(!remove_existing.subscribed() && sdk.delete_calls == 1);
    assert(sdk.other_subscribers == 2);
    no_feed(remove_existing, 10);

    // Failure to remove cannot silently abandon a subscription and cause a bootloop.
    fresh();
    sdk.subscribed = true;
    sdk.delete_error = ESP_FAIL;
    MainTaskWatchdog remove_failed;
    assert(remove_failed.start(false, 100) == ESP_FAIL);
    assert(remove_failed.subscribed());
    feed(remove_failed, 101); // Unknown SDK timeout: feed once per main-loop tick.
    no_feed(remove_failed, 101);

    // Configuration failure with an existing subscription preserves its heartbeat.
    fresh();
    sdk.subscribed = true;
    sdk.config_error = ESP_FAIL;
    MainTaskWatchdog existing_failed_config;
    assert(existing_failed_config.configure(config) == ESP_FAIL);
    assert(existing_failed_config.start(true, 100) == ESP_OK);
    feed(existing_failed_config, 101);

    // Saving a new configuration elsewhere cannot suppress an active subscription.
    fresh();
    MainTaskWatchdog snapshot;
    bool enabled_at_boot = true;
    assert(snapshot.configure(config) == ESP_OK);
    assert(snapshot.start(enabled_at_boot, 0) == ESP_OK);
    enabled_at_boot = false;
    assert(!enabled_at_boot);
    feed(snapshot, 10);

    // Errors are surfaced, retry is bounded, and a removed subscription stops feed.
    sdk.reset_error = ESP_FAIL;
    feed(snapshot, 20, ESP_FAIL);
    assert(snapshot.subscribed());
    no_feed(snapshot, 21);
    sdk.reset_error = ESP_OK;
    feed(snapshot, 30);
    sdk.subscribed = false;
    feed(snapshot, 40, ESP_ERR_NOT_FOUND);
    assert(!snapshot.subscribed());
    no_feed(snapshot, 50);

    // Unsigned elapsed time stays correct across seconds-counter wrap.
    fresh();
    MainTaskWatchdog wrap;
    assert(wrap.configure(config) == ESP_OK);
    assert(wrap.start(true, UINT32_MAX - 5U) == ESP_OK);
    no_feed(wrap, 3);
    feed(wrap, 4);
    sdk.initialized = false;
    feed(wrap, 14, ESP_ERR_INVALID_STATE);
    assert(!wrap.subscribed());
    no_feed(wrap, 24);

    // Seconds -> milliseconds AND the SDK MWDT stage-1 x4 conversion cannot overflow.
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(0) == 60);
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(59) == 60);
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(60) == 60);
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(120) == 120);
    constexpr uint32_t largest = UINT32_MAX / 4000U;
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(largest) == largest);
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(largest + 1U) == largest);
    assert(MainTaskWatchdog::normalizeTimeoutSeconds(UINT32_MAX) == largest);
    assert(uint64_t(MainTaskWatchdog::normalizeTimeoutSeconds(UINT32_MAX)) * 4000U <= UINT32_MAX);
    std::puts("Main task watchdog lifecycle: all scenarios passed");
}
