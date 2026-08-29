#include "icmp_ping.h"

extern "C" {
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "ping/ping_sock.h"
}

namespace IcmpPing {
namespace {

struct ProbeContext {
    SemaphoreHandle_t finished = nullptr;
    bool success = false;
    uint32_t replies = 0;
    int32_t time_ms = -1;
};

void onPingSuccess(esp_ping_handle_t handle, void* args) {
    auto* context = static_cast<ProbeContext*>(args);
    if (!context) return;

    uint32_t elapsed = 0;
    if (esp_ping_get_profile(handle, ESP_PING_PROF_TIMEGAP, &elapsed, sizeof(elapsed)) == ESP_OK) {
        context->time_ms = static_cast<int32_t>(elapsed);
    }
    context->success = true;
    context->replies++;
}

void onPingEnd(esp_ping_handle_t, void* args) {
    auto* context = static_cast<ProbeContext*>(args);
    if (context && context->finished) {
        xSemaphoreGive(context->finished);
    }
}

void onPingTimeout(esp_ping_handle_t, void*) {}

}  // namespace

bool probe(uint32_t target_addr, esp_netif_t* netif, uint32_t timeout_ms, Result& result) {
    result = Result{};
    if (!netif || target_addr == 0) {
        return false;
    }

#if !CONFIG_LWIP_ICMP
    (void)timeout_ms;
    return false;
#else
    if (timeout_ms < 100U) timeout_ms = 100U;
    if (timeout_ms > 60000U) timeout_ms = 60000U;

    ProbeContext context{};
    context.finished = xSemaphoreCreateBinary();
    if (!context.finished) {
        return false;
    }

    const int netif_index = esp_netif_get_netif_impl_index(netif);
    if (netif_index <= 0) {
        vSemaphoreDelete(context.finished);
        return false;
    }

    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    config.count = 1;
    config.interval_ms = 0;
    config.timeout_ms = timeout_ms;
    config.data_size = 32;
    config.interface = static_cast<uint32_t>(netif_index);
    ip_addr_set_ip4_u32(&config.target_addr, target_addr);

    esp_ping_callbacks_t callbacks{};
    callbacks.cb_args = &context;
    callbacks.on_ping_success = onPingSuccess;
    callbacks.on_ping_timeout = onPingTimeout;
    callbacks.on_ping_end = onPingEnd;

    esp_ping_handle_t handle = nullptr;
    esp_err_t err = esp_ping_new_session(&config, &callbacks, &handle);
    if (err != ESP_OK || !handle) {
        vSemaphoreDelete(context.finished);
        return false;
    }

    err = esp_ping_start(handle);
    if (err == ESP_OK) {
        // The internal ping task reports on_ping_end after the single request
        // completes. The extra guard prevents a broken stack from blocking the
        // discovery task forever.
        const TickType_t wait_ticks = pdMS_TO_TICKS(timeout_ms + 500U);
        (void)xSemaphoreTake(context.finished, wait_ticks == 0 ? 1 : wait_ticks);
    }

    esp_ping_stop(handle);
    esp_ping_delete_session(handle);
    vSemaphoreDelete(context.finished);

    result.replies = context.replies;
    result.time_ms = context.time_ms;
    if (err != ESP_OK) {
        result.status = Status::Error;
        return false;
    }
    if (context.success) {
        result.status = Status::Success;
        return true;
    }
    result.status = Status::Timeout;
    return false;
#endif
}

}  // namespace IcmpPing
