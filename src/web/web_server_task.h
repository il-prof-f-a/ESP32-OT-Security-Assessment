#pragma once

#include <atomic>
#include "esp_netif.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifdef __cplusplus
// Forward declaration for C++
class WebServer;

struct WebTaskArgs {
    WebTaskArgs(WebServer* server, int server_port, esp_netif_t* interface,
                SemaphoreHandle_t completion_signal)
        : srv(server), port(server_port), netif(interface),
          started(completion_signal), success(false), references(2) {}

    WebServer* srv;
    int port;
    esp_netif_t* netif;
    // The semaphore and context remain alive until both caller and worker
    // release their references. This makes timeout/late-completion safe.
    SemaphoreHandle_t started;
    std::atomic<bool> success;
    std::atomic<unsigned> references;
};

// Drops one owner of a startup context. The final owner deletes the signal
// semaphore and the context itself.
void web_server_task_release_args(WebTaskArgs* args);

extern "C" {
#endif

// Declaration of the task function (always in C linkage)
void web_server_task(void *pv);

#ifdef __cplusplus
}
#endif
