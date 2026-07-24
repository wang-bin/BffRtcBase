#pragma once

#include <string>

#include "protobuf-c/protobuf-c.h"
#include "json.hpp"

namespace bff {

// protobuf-c message <-> JSON (proto3 JsonFormat-ish: lowerCamelCase keys,
// omit defaults, enum as proto name string, bytes as base64).
// Matches iOS GPBMessage+JsonFormat / Android JsonFormat wire used with signal.json.

nlohmann::json messageToJson(const ProtobufCMessage* message);
bool messageToJsonString(const ProtobufCMessage* message, std::string* out);

// Allocates a message with descriptor->message_init; caller must
// protobuf_c_message_free_unpacked(msg, nullptr).
ProtobufCMessage* messageFromJson(const ProtobufCMessageDescriptor* descriptor,
                                  const nlohmann::json& json);
ProtobufCMessage* messageFromJsonString(const ProtobufCMessageDescriptor* descriptor,
                                        const std::string& json);

} // namespace bff
