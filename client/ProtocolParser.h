// ProtocolParser.h
#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>

// ParsedMessage holds header fields and payload
struct ParsedMessage {
    std::vector<uint8_t> clientId; // 16 bytes
    uint8_t              version;  // 1 byte
    uint16_t             code;     // 2 bytes
    std::vector<uint8_t> payload;  // payloadSize bytes
};

class ProtocolParser {
public:
    // Parses a raw buffer (header + payload) into a ParsedMessage.
    // Throws runtime_error if too short or size mismatch.
    static ParsedMessage parse(const std::vector<uint8_t>& raw);
};
