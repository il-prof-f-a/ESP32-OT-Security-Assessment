#pragma once
#include <cstddef>
#include <cstdint>

class EthernetTxIf {
public:
    virtual ~EthernetTxIf() = default;
    virtual bool rawTx(const uint8_t* frame, size_t len) = 0;  // send already-built Ethernet frame
    virtual bool getMac(uint8_t out6[6]) = 0;
};
