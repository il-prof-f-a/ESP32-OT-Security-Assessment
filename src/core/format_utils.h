// Lightweight integer-only formatting helpers to avoid float dtoa allocations
// All functions write into caller-provided buffers and use only integer math.

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Formats a non-negative fraction (num/den) as fixed-point with `decimals` digits.
// Writes into `out` up to `out_sz` including null-terminator.
// Rounds half up; uses 64-bit math to avoid overflow.
static inline void fmt_fraction_fixed(char* out, size_t out_sz,
                                      uint32_t num, uint32_t den,
                                      unsigned decimals) {
    if (!out || out_sz == 0 || den == 0) return;
    if (decimals > 6) decimals = 6; // cap for safety
    uint64_t scale = 1;
    for (unsigned i = 0; i < decimals; ++i) scale *= 10ULL;
    uint64_t scaled = ((uint64_t)num * scale * 10ULL + (uint64_t)den/2ULL) / (uint64_t)den; // pre-round at next digit
    uint32_t intpart_u32 = (uint32_t)(scaled / 10ULL);
    uint32_t frac_u32    = (uint32_t)(scaled % 10ULL);
    if (decimals == 0) {
        (void)snprintf(out, out_sz, "%u", (unsigned)intpart_u32);
        return;
    }
    // Adjust frac to requested decimals (we pre-rounded using one extra digit)
    for (unsigned i = 1; i < decimals; ++i) frac_u32 *= 10U;
    (void)snprintf(out, out_sz, "%u.%0*u", (unsigned)intpart_u32, (int)decimals, (unsigned)frac_u32);
}

// Formats bytes as megabytes with `decimals` digits (e.g., 12.3 MB), integer-only math.
static inline void fmt_bytes_mb(char* out, size_t out_sz, uint32_t bytes, unsigned decimals) {
    // 1 MB = 1024*1024 bytes. Compute (bytes / MB) as fixed point.
    const uint32_t MB = 1024U * 1024U;
    uint32_t intpart_u32 = bytes / MB;
    if (decimals == 0) { (void)snprintf(out, out_sz, "%u MB", (unsigned)intpart_u32); return; }
    if (decimals > 3) decimals = 3; // cap
    uint32_t rem = bytes % MB;
    // Scale remainder to decimals (round half up)
    uint64_t scale = 1;
    for (unsigned i = 0; i < decimals; ++i) scale *= 10ULL;
    uint32_t frac_u32 = (uint32_t)(((uint64_t)rem * scale * 2ULL + MB) / (2ULL * MB));
    (void)snprintf(out, out_sz, "%u.%0*u MB", (unsigned)intpart_u32, (int)decimals, (unsigned)frac_u32);
}

// Formats a percentage given parts: pct = (part/total)*100 with `decimals` digits.
static inline void fmt_percent(char* out, size_t out_sz, uint32_t part, uint32_t total, unsigned decimals) {
    if (!total) { (void)snprintf(out, out_sz, "0%%"); return; }
    if (decimals == 0) {
        uint32_t pct = (uint32_t)(((uint64_t)part * 100ULL + total/2ULL) / total);
        (void)snprintf(out, out_sz, "%u%%", (unsigned)pct);
        return;
    }
    if (decimals > 3) decimals = 3;
    uint64_t scale = 1;
    for (unsigned i = 0; i < decimals; ++i) scale *= 10ULL;
    uint64_t scaled = ((uint64_t)part * 100ULL * scale * 10ULL + (uint64_t)total/2ULL) / (uint64_t)total; // pre-round
    uint32_t intpart_u32 = (uint32_t)(scaled / 10ULL);
    uint32_t frac_u32    = (uint32_t)(scaled % 10ULL);
    for (unsigned i = 1; i < decimals; ++i) frac_u32 *= 10U;
    (void)snprintf(out, out_sz, "%u.%0*u%%", (unsigned)intpart_u32, (int)decimals, (unsigned)frac_u32);
}
