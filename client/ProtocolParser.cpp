#include "ProtocolParser.h"

ParsedMessage ProtocolParser::parse(const std::vector<uint8_t>& raw) {
    // Minimum size = 16 (ID) + 1 (version) + 2 (code) + 4 (payload size)
    if (raw.size() < 23) {
        throw std::runtime_error("Raw message too short: missing header");
    }

    ParsedMessage msg;

    // 0–15: Client ID
    msg.clientId.assign(raw.begin(), raw.begin() + 16);

    // 16: Version
    msg.version = raw[16];

    // 17–18: Code (big-endian)
    msg.code = (static_cast<uint16_t>(raw[17]) << 8)
               | static_cast<uint16_t>(raw[18]);

    // 19–22: Payload size (big-endian)
    uint32_t payloadSize = (static_cast<uint32_t>(raw[19]) << 24)
                           | (static_cast<uint32_t>(raw[20]) << 16)
                           | (static_cast<uint32_t>(raw[21]) << 8)
                           |  static_cast<uint32_t>(raw[22]);

    // Validate total length
    if (raw.size() != 23 + payloadSize) {
        throw std::runtime_error("Payload size mismatch");
    }

    // 23…: Payload
    msg.payload.assign(raw.begin() + 23, raw.end());

    return msg;
}