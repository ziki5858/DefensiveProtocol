#include "ProtocolParser.h"

ParsedMessage ProtocolParser::parse(const std::vector<uint8_t> &raw) {
    if (raw.size() < 7) {
        throw std::runtime_error("Raw response too short");
    }

    ParsedMessage msg;

    // 0: Version
    msg.version = raw[0];

    // 1–2: Code (little-endian)
    msg.code = static_cast<uint16_t>(raw[1]) | (static_cast<uint16_t>(raw[2]) << 8);

    // 3–6: Payload size (little-endian)
    uint32_t payloadSize = static_cast<uint32_t>(raw[3]) |
                           (static_cast<uint32_t>(raw[4]) << 8) |
                           (static_cast<uint32_t>(raw[5]) << 16) |
                           (static_cast<uint32_t>(raw[6]) << 24);

    // Validate total size
    if (raw.size() != 7 + payloadSize) {
        throw std::runtime_error("Payload size mismatch in response");
    }

    // 7…: Payload
    msg.payload.assign(raw.begin() + 7, raw.end());

    return msg;
}
