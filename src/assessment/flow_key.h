/**
 * @file flow_key.h
 * @brief Chiave universale per identificazione flussi di rete
 *
 * Sistema di identificazione univoca per flussi di rete multi-protocollo.
 * Utilizza PSRAM per allocazione stringhe (NO IRAM).
 *
 * Formato chiave: "src_ip:src_port:dst_ip:dst_port:proto_specific"
 *
 * Esempi:
 * - Modbus TCP:  "192.168.1.100:5000:192.168.1.200:502:1" (unit_id=1)
 * - S7:          "192.168.1.100:5000:192.168.1.200:102:0:1" (rack=0, slot=1)
 * - PROFINET:    "AA:BB:CC:DD:EE:FF:12345" (src_mac:xid)
 * - EtherNet/IP: "192.168.1.100:5000:192.168.1.200:44818:0x12345678" (session_handle)
 * - OPC UA:      "192.168.1.100:5000:192.168.1.200:4840:0xABCD" (secure_channel_id)
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include "core/psram_allocator.h"
#include <string>
#include <functional>

/**
 * Alias per stringhe allocate in PSRAM
 * REGOLA: Solo PSRAM, MAI IRAM
 */
using psram_string = std::basic_string<char, std::char_traits<char>, PSRAMAllocator<char>>;

/**
 * @brief Chiave universale per identificazione flussi
 *
 * Struttura che identifica univocamente un flusso di rete combinando:
 * - Indirizzi IP sorgente e destinazione
 * - Porte sorgente e destinazione
 * - Identificatore specifico del protocollo (opzionale)
 *
 * ALLOCAZIONE: PSRAM (tutte le stringhe usano PSRAMAllocator)
 */
struct FlowKey {
    psram_string src_ip;              ///< Indirizzo IP sorgente (es: "192.168.1.100")
    psram_string dst_ip;              ///< Indirizzo IP destinazione (es: "192.168.1.200")
    uint16_t src_port;                ///< Porta sorgente
    uint16_t dst_port;                ///< Porta destinazione
    psram_string protocol_specific;   ///< Identificatore specifico protocollo

    /**
     * @brief Costruttore default con allocatore PSRAM
     *
     * Inizializza tutte le stringhe con PSRAMAllocator per garantire
     * allocazione in PSRAM senza fallback a IRAM.
     *
     * @param alloc Allocatore PSRAM (default: PSRAMAllocator<char>())
     */
    FlowKey(PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : src_ip(alloc),
          dst_ip(alloc),
          src_port(0),
          dst_port(0),
          protocol_specific(alloc) {}

    /**
     * @brief Costruttore con parametri
     *
     * @param src Indirizzo IP sorgente
     * @param s_port Porta sorgente
     * @param dst Indirizzo IP destinazione
     * @param d_port Porta destinazione
     * @param proto_spec Identificatore specifico protocollo (opzionale)
     */
    FlowKey(const char* src, uint16_t s_port,
            const char* dst, uint16_t d_port,
            const char* proto_spec = "",
            PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : src_ip(src, alloc),
          dst_ip(dst, alloc),
          src_port(s_port),
          dst_port(d_port),
          protocol_specific(proto_spec, alloc) {}

    /**
     * @brief Converte la chiave in stringa per uso in hashtable
     *
     * Formato: "src_ip:src_port:dst_ip:dst_port[:protocol_specific]"
     *
     * Esempi:
     * - "192.168.1.100:5000:192.168.1.200:502:1"
     * - "192.168.1.100:5000:192.168.1.200:4840:0xABCD"
     *
     * @return Stringa PSRAM-allocated rappresentante la chiave
     */
    psram_string toString() const {
        PSRAMAllocator<char> alloc;
        psram_string key(alloc);
        key.reserve(128);  // Pre-alloca per evitare riallocazioni

        // Formato base: src_ip:src_port:dst_ip:dst_port
        key = src_ip;
        key += ":";
        key += std::to_string(src_port).c_str();
        key += ":";
        key += dst_ip;
        key += ":";
        key += std::to_string(dst_port).c_str();

        // Aggiungi identificatore protocollo se presente
        if (!protocol_specific.empty()) {
            key += ":";
            key += protocol_specific;
        }

        return key;
    }

    /**
     * @brief Operatore di uguaglianza per confronto chiavi
     *
     * Due chiavi sono uguali se tutti i campi coincidono.
     *
     * @param other Altra chiave da confrontare
     * @return true se le chiavi sono identiche, false altrimenti
     */
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol_specific == other.protocol_specific;
    }

    /**
     * @brief Operatore di disuguaglianza
     *
     * @param other Altra chiave da confrontare
     * @return true se le chiavi sono diverse, false altrimenti
     */
    bool operator!=(const FlowKey& other) const {
        return !(*this == other);
    }

    /**
     * @brief Functor di hash per uso in std::unordered_map
     *
     * Calcola hash della rappresentazione stringa della chiave.
     * Necessario per usare FlowKey come chiave in unordered_map.
     */
    struct Hash {
        size_t operator()(const FlowKey& k) const {
            // Hash sulla rappresentazione stringa
            return std::hash<psram_string>{}(k.toString());
        }
    };

    /**
     * @brief Crea chiave per flusso bidirezionale
     *
     * Normalizza la chiave ordinando src/dst in modo che flussi
     * bidirezionali (A->B e B->A) abbiano la stessa chiave.
     *
     * Utile per protocolli request/response dove vogliamo tracciare
     * entrambe le direzioni nello stesso flusso.
     *
     * @return Chiave normalizzata
     */
    FlowKey toBidirectional() const {
        PSRAMAllocator<char> alloc;

        // Ordina per IP (poi porta se IP uguali)
        bool swap = false;
        if (src_ip > dst_ip) {
            swap = true;
        } else if (src_ip == dst_ip && src_port > dst_port) {
            swap = true;
        }

        if (swap) {
            return FlowKey(
                dst_ip.c_str(), dst_port,
                src_ip.c_str(), src_port,
                protocol_specific.c_str(),
                alloc
            );
        } else {
            return *this;
        }
    }

    /**
     * @brief Verifica se la chiave è valida
     *
     * Una chiave è valida se ha almeno IP sorgente e destinazione.
     *
     * @return true se chiave valida, false altrimenti
     */
    bool isValid() const {
        return !src_ip.empty() && !dst_ip.empty();
    }

    /**
     * @brief Ottieni direzione flusso come stringa
     *
     * @return Stringa formato "src_ip:src_port -> dst_ip:dst_port"
     */
    psram_string toDirectionString() const {
        PSRAMAllocator<char> alloc;
        psram_string result(alloc);
        result.reserve(64);

        result = src_ip;
        result += ":";
        result += std::to_string(src_port).c_str();
        result += " -> ";
        result += dst_ip;
        result += ":";
        result += std::to_string(dst_port).c_str();

        return result;
    }
};

#endif // FLOW_KEY_H
