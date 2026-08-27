#include "assessment_interface.h"

#include <cerrno>
#include <cstring>

#include "esp_netif.h"
#include "lwip/sockets.h"

#ifdef SO_BINDTODEVICE
#include <net/if.h>
#endif

namespace AssessmentInterface {

namespace {

bool ethernetInfo(esp_netif_t** netif, esp_netif_ip_info_t* info) {
    if (!netif || !info) {
        errno = EINVAL;
        return false;
    }

    *netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (!*netif || esp_netif_get_ip_info(*netif, info) != ESP_OK ||
        info->ip.addr == 0) {
        errno = ENETDOWN;
        return false;
    }
    return true;
}

}  // namespace

bool localAddress(ip_addr_t* address) {
    if (!address) {
        errno = EINVAL;
        return false;
    }

    esp_netif_t* netif = nullptr;
    esp_netif_ip_info_t info{};
    if (!ethernetInfo(&netif, &info)) {
        return false;
    }

    ip_addr_copy_from_ip4(*address, info.ip);
    return true;
}

int openBoundSocket(int domain, int type, int protocol) {
    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    esp_netif_t* netif = nullptr;
    esp_netif_ip_info_t info{};
    if (!ethernetInfo(&netif, &info)) {
        return -1;
    }

    const int sock = ::socket(domain, type, protocol);
    if (sock < 0) {
        return -1;
    }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = info.ip.addr;
    local.sin_port = 0;
    if (::bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        const int bind_errno = errno;
        ::close(sock);
        errno = bind_errno;
        return -1;
    }

#ifdef SO_BINDTODEVICE
    ifreq interface_request{};
    const unsigned int interface_index = esp_netif_get_netif_impl_index(netif);
    if (interface_index != 0 &&
        if_indextoname(interface_index, interface_request.ifr_name) != nullptr) {
        // The source-address bind above is authoritative. SO_BINDTODEVICE adds
        // another guard on platforms that implement it in lwIP.
        (void)::setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                           &interface_request, sizeof(interface_request));
    }
#endif

    return sock;
}

}  // namespace AssessmentInterface
