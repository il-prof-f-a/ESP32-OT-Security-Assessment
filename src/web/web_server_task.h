#pragma once

#include "esp_netif.h"

#ifdef __cplusplus
// Forward declaration for C++
class WebServer;

struct WebTaskArgs {
    WebServer*      srv;
    int             port;
    esp_netif_t*    netif;
    void*           started; // opaque pointer to a SemaphoreHandle_t created by caller
    volatile bool*  success; // pointer to shared success flag
};

extern "C" {
#endif

// Declaration of the task function (always in C linkage)
void web_server_task(void *pv);

#ifdef __cplusplus
}
#endif