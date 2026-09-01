// web_server_task.cpp
#include "web_server_task.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "../core/task_alloc_helpers.h"
#include "../core/logging_system.h"
#include "web_server.h"
#include "../core/audit_manager.h"

void web_server_task_release_args(WebTaskArgs* args) {
    if (!args) return;
    if (args->references.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        if (args->started) {
            vSemaphoreDelete(args->started);
            args->started = nullptr;
        }
        args->~WebTaskArgs();
        vPortFree(args);
    }
}

extern "C" void web_server_task(void *pv) {
    WebTaskArgs* a = static_cast<WebTaskArgs*>(pv);

    if (!a) {

        LOG_ERROR("WebServerTask", "web_server_task: received null args!");

        vTaskDelete(nullptr);

        return;

    }
    WebServer*   srv   = a->srv;
    const int    port  = a->port;
    esp_netif_t* netif = a->netif;
    SemaphoreHandle_t started = a->started;

    LOG_INFOF("WebServerTask", "Received args: srv=%p port=%d netif=%p started=%p", (void*)srv, port, (void*)netif, (void*)started);

    LOG_INFOF("WebServerTask", "Starting web server on core %d, port %d ...", xPortGetCoreID(), port);

    LOG_INFO("WebServerTask", "Calling srv->startOnInterface()...");
    const bool ok = srv->startOnInterface(port, netif);
    if (!ok) {
        LOG_ERRORF("WebServerTask", "startOnInterface(%d) failed", port);
        LOG_ERROR("WebServerTask", "Signaling FAILURE to waiting task");
        a->success.store(false, std::memory_order_release);
        if (started) xSemaphoreGive(started);
        srv->startTaskFinished();
        web_server_task_release_args(a);
        vTaskDelete(nullptr);
        return;
    }

    LOG_INFO("WebServerTask", "Web server started.");
    // AUDIT: Log WebServer service startup
    AuditManager::getInstance().logServiceEvent("WebServer", "started", "Web interface ready and accepting connections");
    LOG_INFO("WebServerTask", "Signaling SUCCESS to waiting task");
    a->success.store(true, std::memory_order_release);
    if (started) xSemaphoreGive(started);
    srv->startTaskFinished();

    while (srv->isRunning()) {
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    LOG_INFO("WebServerTask", "Web server stopped; terminating wrapper task");
    web_server_task_release_args(a);
    vTaskDelete(nullptr);
}
