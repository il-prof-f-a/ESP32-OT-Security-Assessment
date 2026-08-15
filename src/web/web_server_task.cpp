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

extern "C" void web_server_task(void *pv) {
    // Prendi e libera subito gli argomenti
    WebTaskArgs* a = static_cast<WebTaskArgs*>(pv);

    if (!a) {

        LOG_ERROR("WebServerTask", "web_server_task: received null args!");

        vTaskDelete(nullptr);

        return;

    }
    WebServer*   srv   = a->srv;
    const int    port  = a->port;
    esp_netif_t* netif = a->netif;
    volatile bool* success_flag = a->success;
    SemaphoreHandle_t started = nullptr;
    if (a->started) started = (SemaphoreHandle_t)a->started;

    LOG_INFOF("WebServerTask", "Received args: srv=%p port=%d netif=%p started=%p", (void*)srv, port, (void*)netif, (void*)started);

    vPortFree(a);

    LOG_INFOF("WebServerTask", "Starting web server on core %d, port %d ...", xPortGetCoreID(), port);

    LOG_INFO("WebServerTask", "Calling srv->startOnInterface()...");
    const bool ok = srv->startOnInterface(port, netif);
    if (!ok) {
        LOG_ERRORF("WebServerTask", "startOnInterface(%d) failed", port);
        LOG_ERROR("WebServerTask", "Signaling FAILURE to waiting task");
        if (success_flag) *success_flag = false;
        if (started) xSemaphoreGive(started);
        vTaskDelete(nullptr);
        return;
    }

    LOG_INFO("WebServerTask", "Web server started.");
    // AUDIT: Log WebServer service startup
    AuditManager::getInstance().logServiceEvent("WebServer", "started", "Web interface ready and accepting connections");
    LOG_INFO("WebServerTask", "Signaling SUCCESS to waiting task");
    if (success_flag) *success_flag = true;
    if (started) xSemaphoreGive(started);

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
