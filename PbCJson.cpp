#include "PbCJson.h"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace bff {
namespace {

#define STRUCT_MEMBER_P(struct_p, struct_offset) \
    ((void*)((uint8_t*)(struct_p) + (struct_offset)))
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
    (*(member_type*)STRUCT_MEMBER_P((struct_p), (struct_offset)))
#define STRUCT_MEMBER_PTR(member_type, struct_p, struct_offset) \
    ((member_type*)STRUCT_MEMBER_P((struct_p), (struct_offset)))

static size_t eltSize(ProtobufCType type) {
    switch (type) {
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
    case PROTOBUF_C_TYPE_FIXED32:
    case PROTOBUF_C_TYPE_FLOAT:
    case PROTOBUF_C_TYPE_ENUM:
        return 4;
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_FIXED64:
    case PROTOBUF_C_TYPE_DOUBLE:
        return 8;
    case PROTOBUF_C_TYPE_BOOL:
        return sizeof(protobuf_c_boolean);
    case PROTOBUF_C_TYPE_STRING:
    case PROTOBUF_C_TYPE_MESSAGE:
        return sizeof(void*);
    case PROTOBUF_C_TYPE_BYTES:
        return sizeof(ProtobufCBinaryData);
    }
    return 0;
}

static std::string snakeToCamel(const char* snake) {
    std::string out;
    out.reserve(std::strlen(snake));
    bool upper = false;
    for (const char* p = snake; *p; ++p) {
        if (*p == '_') {
            upper = true;
            continue;
        }
        if (upper) {
            out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(*p))));
            upper = false;
        } else {
            out.push_back(*p);
        }
    }
    return out;
}

static std::string camelToSnake(const std::string& camel) {
    std::string out;
    out.reserve(camel.size() + 4);
    for (size_t i = 0; i < camel.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(camel[i]);
        if (std::isupper(ch)) {
            if (i > 0) out.push_back('_');
            out.push_back(static_cast<char>(std::tolower(ch)));
        } else {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

static const char kBase64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                           ((i + 1 < len ? data[i + 1] : 0) << 8) |
                           (i + 2 < len ? data[i + 2] : 0);
        out.push_back(kBase64Table[(n >> 18) & 63]);
        out.push_back(kBase64Table[(n >> 12) & 63]);
        out.push_back(i + 1 < len ? kBase64Table[(n >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? kBase64Table[n & 63] : '=');
    }
    return out;
}

static int base64Index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool base64Decode(const std::string& in, std::vector<uint8_t>* out) {
    if (!out) return false;
    out->clear();
    int val = 0;
    int valb = -8;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        const int d = base64Index(c);
        if (d < 0) return false;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out->push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return true;
}

static const ProtobufCEnumValue* enumValueByNumber(const ProtobufCEnumDescriptor* desc, int value) {
    if (!desc) return nullptr;
    for (unsigned i = 0; i < desc->n_values; ++i) {
        if (desc->values[i].value == value) return &desc->values[i];
    }
    return nullptr;
}

static const ProtobufCEnumValue* enumValueByName(const ProtobufCEnumDescriptor* desc, const std::string& name) {
    if (!desc) return nullptr;
    for (unsigned i = 0; i < desc->n_value_names; ++i) {
        if (name == desc->values_by_name[i].name) {
            return &desc->values[desc->values_by_name[i].index];
        }
    }
    // Also try full values[].name
    for (unsigned i = 0; i < desc->n_values; ++i) {
        if (name == desc->values[i].name) return &desc->values[i];
    }
    return nullptr;
}

static bool fieldIsSet(const ProtobufCMessage* message, const ProtobufCFieldDescriptor* field) {
    if (field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) {
        const uint32_t oneof_case = STRUCT_MEMBER(uint32_t, message, field->quantifier_offset);
        return oneof_case == field->id;
    }
    if (field->label == PROTOBUF_C_LABEL_REPEATED) {
        return STRUCT_MEMBER(size_t, message, field->quantifier_offset) > 0;
    }
    if (field->label == PROTOBUF_C_LABEL_OPTIONAL && field->quantifier_offset != 0) {
        return STRUCT_MEMBER(protobuf_c_boolean, message, field->quantifier_offset) != 0;
    }

    // Proto3 unlabeled: treat default as unset (JsonFormat omit-defaults).
    void* member = STRUCT_MEMBER_P(message, field->offset);
    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE: {
        return *static_cast<ProtobufCMessage**>(member) != nullptr;
    }
    case PROTOBUF_C_TYPE_STRING: {
        const char* s = *static_cast<char**>(member);
        return s && s[0] != '\0' && s != field->default_value;
    }
    case PROTOBUF_C_TYPE_BYTES: {
        const auto* bd = static_cast<ProtobufCBinaryData*>(member);
        return bd->len > 0 && bd->data != nullptr;
    }
    case PROTOBUF_C_TYPE_BOOL:
        return *static_cast<protobuf_c_boolean*>(member) != 0;
    case PROTOBUF_C_TYPE_ENUM:
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
        return *static_cast<int32_t*>(member) != 0;
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        return *static_cast<uint32_t*>(member) != 0;
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        return *static_cast<int64_t*>(member) != 0;
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return *static_cast<uint64_t*>(member) != 0;
    case PROTOBUF_C_TYPE_FLOAT:
        return *static_cast<float*>(member) != 0.0f;
    case PROTOBUF_C_TYPE_DOUBLE:
        return *static_cast<double*>(member) != 0.0;
    }
    return true;
}

static nlohmann::json scalarToJson(ProtobufCType type,
                                   const void* member,
                                   const ProtobufCFieldDescriptor* field) {
    switch (type) {
    case PROTOBUF_C_TYPE_BOOL:
        return *static_cast<const protobuf_c_boolean*>(member) != 0;
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
        return *static_cast<const int32_t*>(member);
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        return *static_cast<const uint32_t*>(member);
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        return *static_cast<const int64_t*>(member);
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return *static_cast<const uint64_t*>(member);
    case PROTOBUF_C_TYPE_FLOAT:
        return *static_cast<const float*>(member);
    case PROTOBUF_C_TYPE_DOUBLE:
        return *static_cast<const double*>(member);
    case PROTOBUF_C_TYPE_ENUM: {
        const int v = *static_cast<const int*>(member);
        const auto* ev = enumValueByNumber(static_cast<const ProtobufCEnumDescriptor*>(field->descriptor), v);
        if (ev) return ev->name;
        return v;
    }
    case PROTOBUF_C_TYPE_STRING: {
        const char* s = *static_cast<char* const*>(member);
        return s ? s : "";
    }
    case PROTOBUF_C_TYPE_BYTES: {
        const auto* bd = static_cast<const ProtobufCBinaryData*>(member);
        if (!bd->data || bd->len == 0) return "";
        return base64Encode(bd->data, bd->len);
    }
    case PROTOBUF_C_TYPE_MESSAGE:
        break;
    }
    return nullptr;
}

static nlohmann::json messageToJsonImpl(const ProtobufCMessage* message);

static nlohmann::json fieldToJson(const ProtobufCMessage* message, const ProtobufCFieldDescriptor* field) {
    if (field->label == PROTOBUF_C_LABEL_REPEATED) {
        const size_t n = STRUCT_MEMBER(size_t, message, field->quantifier_offset);
        const size_t esz = eltSize(field->type);
        const uint8_t* arr = *STRUCT_MEMBER_PTR(uint8_t*, message, field->offset);
        nlohmann::json arrJson = nlohmann::json::array();
        for (size_t i = 0; i < n; ++i) {
            const void* elt = arr + i * esz;
            if (field->type == PROTOBUF_C_TYPE_MESSAGE) {
                const auto* sub = *static_cast<ProtobufCMessage* const*>(elt);
                arrJson.push_back(sub ? messageToJsonImpl(sub) : nlohmann::json::object());
            } else {
                arrJson.push_back(scalarToJson(field->type, elt, field));
            }
        }
        return arrJson;
    }

    void* member = STRUCT_MEMBER_P(message, field->offset);
    if (field->type == PROTOBUF_C_TYPE_MESSAGE) {
        const auto* sub = *static_cast<ProtobufCMessage**>(member);
        return sub ? messageToJsonImpl(sub) : nlohmann::json::object();
    }
    return scalarToJson(field->type, member, field);
}

static nlohmann::json messageToJsonImpl(const ProtobufCMessage* message) {
    nlohmann::json obj = nlohmann::json::object();
    if (!message || !message->descriptor) return obj;
    const auto* desc = message->descriptor;
    for (unsigned i = 0; i < desc->n_fields; ++i) {
        const ProtobufCFieldDescriptor* field = &desc->fields[i];
        if (!fieldIsSet(message, field)) continue;
        obj[snakeToCamel(field->name)] = fieldToJson(message, field);
    }
    return obj;
}

static const ProtobufCFieldDescriptor* findField(const ProtobufCMessageDescriptor* desc,
                                                 const std::string& key) {
    if (const auto* f = protobuf_c_message_descriptor_get_field_by_name(desc, key.c_str())) {
        return f;
    }
    const std::string snake = camelToSnake(key);
    if (snake != key) {
        if (const auto* f = protobuf_c_message_descriptor_get_field_by_name(desc, snake.c_str())) {
            return f;
        }
    }
    // Match by camelCase of each field name.
    for (unsigned i = 0; i < desc->n_fields; ++i) {
        if (snakeToCamel(desc->fields[i].name) == key) {
            return &desc->fields[i];
        }
    }
    return nullptr;
}

static bool parseScalar(const nlohmann::json& j,
                        ProtobufCType type,
                        const ProtobufCFieldDescriptor* field,
                        void* member) {
    try {
        switch (type) {
        case PROTOBUF_C_TYPE_BOOL:
            *static_cast<protobuf_c_boolean*>(member) = j.get<bool>() ? 1 : 0;
            return true;
        case PROTOBUF_C_TYPE_INT32:
        case PROTOBUF_C_TYPE_SINT32:
        case PROTOBUF_C_TYPE_SFIXED32:
            *static_cast<int32_t*>(member) = j.get<int32_t>();
            return true;
        case PROTOBUF_C_TYPE_UINT32:
        case PROTOBUF_C_TYPE_FIXED32:
            *static_cast<uint32_t*>(member) = j.get<uint32_t>();
            return true;
        case PROTOBUF_C_TYPE_INT64:
        case PROTOBUF_C_TYPE_SINT64:
        case PROTOBUF_C_TYPE_SFIXED64:
            *static_cast<int64_t*>(member) = j.get<int64_t>();
            return true;
        case PROTOBUF_C_TYPE_UINT64:
        case PROTOBUF_C_TYPE_FIXED64:
            *static_cast<uint64_t*>(member) = j.get<uint64_t>();
            return true;
        case PROTOBUF_C_TYPE_FLOAT:
            *static_cast<float*>(member) = j.get<float>();
            return true;
        case PROTOBUF_C_TYPE_DOUBLE:
            *static_cast<double*>(member) = j.get<double>();
            return true;
        case PROTOBUF_C_TYPE_ENUM: {
            const auto* ed = static_cast<const ProtobufCEnumDescriptor*>(field->descriptor);
            if (j.is_string()) {
                const auto* ev = enumValueByName(ed, j.get<std::string>());
                if (!ev) return false;
                *static_cast<int*>(member) = ev->value;
                return true;
            }
            *static_cast<int*>(member) = j.get<int>();
            return true;
        }
        case PROTOBUF_C_TYPE_STRING: {
            if (!j.is_string()) return false;
            char* s = strdup(j.get_ref<const std::string&>().c_str());
            if (!s) return false;
            char** sp = static_cast<char**>(member);
            if (*sp && *sp != field->default_value && *sp != protobuf_c_empty_string) {
                free(*sp);
            }
            *sp = s;
            return true;
        }
        case PROTOBUF_C_TYPE_BYTES: {
            if (!j.is_string()) return false;
            std::vector<uint8_t> bytes;
            if (!base64Decode(j.get_ref<const std::string&>(), &bytes)) return false;
            auto* bd = static_cast<ProtobufCBinaryData*>(member);
            if (bd->data) free(bd->data);
            bd->len = bytes.size();
            if (bytes.empty()) {
                bd->data = nullptr;
            } else {
                bd->data = static_cast<uint8_t*>(malloc(bytes.size()));
                if (!bd->data) {
                    bd->len = 0;
                    return false;
                }
                memcpy(bd->data, bytes.data(), bytes.size());
            }
            return true;
        }
        case PROTOBUF_C_TYPE_MESSAGE:
            break;
        }
    } catch (...) {
        return false;
    }
    return false;
}

static ProtobufCMessage* messageFromJsonImpl(const ProtobufCMessageDescriptor* descriptor,
                                             const nlohmann::json& json);

static bool mergeField(ProtobufCMessage* message,
                       const ProtobufCFieldDescriptor* field,
                       const nlohmann::json& j) {
    if (field->label == PROTOBUF_C_LABEL_REPEATED) {
        if (!j.is_array()) return false;
        const size_t n = j.size();
        const size_t esz = eltSize(field->type);
        void* arr = nullptr;
        if (n > 0) {
            arr = calloc(n, esz);
            if (!arr) return false;
        }
        for (size_t i = 0; i < n; ++i) {
            void* elt = static_cast<uint8_t*>(arr) + i * esz;
            if (field->type == PROTOBUF_C_TYPE_MESSAGE) {
                const auto* subDesc = static_cast<const ProtobufCMessageDescriptor*>(field->descriptor);
                ProtobufCMessage* sub = messageFromJsonImpl(subDesc, j[i]);
                if (!sub) {
                    // Free previously allocated subs.
                    for (size_t k = 0; k < i; ++k) {
                        auto* prev = *reinterpret_cast<ProtobufCMessage**>(static_cast<uint8_t*>(arr) + k * esz);
                        protobuf_c_message_free_unpacked(prev, nullptr);
                    }
                    free(arr);
                    return false;
                }
                *static_cast<ProtobufCMessage**>(elt) = sub;
            } else if (!parseScalar(j[i], field->type, field, elt)) {
                if (field->type == PROTOBUF_C_TYPE_STRING) {
                    for (size_t k = 0; k < i; ++k) {
                        free(*reinterpret_cast<char**>(static_cast<uint8_t*>(arr) + k * esz));
                    }
                }
                free(arr);
                return false;
            }
        }
        STRUCT_MEMBER(size_t, message, field->quantifier_offset) = n;
        *STRUCT_MEMBER_PTR(void*, message, field->offset) = arr;
        return true;
    }

    if (field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) {
        STRUCT_MEMBER(uint32_t, message, field->quantifier_offset) = field->id;
    } else if (field->label == PROTOBUF_C_LABEL_OPTIONAL && field->quantifier_offset != 0) {
        STRUCT_MEMBER(protobuf_c_boolean, message, field->quantifier_offset) = 1;
    }

    void* member = STRUCT_MEMBER_P(message, field->offset);
    if (field->type == PROTOBUF_C_TYPE_MESSAGE) {
        if (!j.is_object()) return false;
        const auto* subDesc = static_cast<const ProtobufCMessageDescriptor*>(field->descriptor);
        ProtobufCMessage* sub = messageFromJsonImpl(subDesc, j);
        if (!sub) return false;
        ProtobufCMessage** sp = static_cast<ProtobufCMessage**>(member);
        if (*sp) protobuf_c_message_free_unpacked(*sp, nullptr);
        *sp = sub;
        return true;
    }
    return parseScalar(j, field->type, field, member);
}

static ProtobufCMessage* messageFromJsonImpl(const ProtobufCMessageDescriptor* descriptor,
                                             const nlohmann::json& json) {
    if (!descriptor || !json.is_object()) return nullptr;
    auto* message = static_cast<ProtobufCMessage*>(calloc(1, descriptor->sizeof_message));
    if (!message) return nullptr;
    protobuf_c_message_init(descriptor, message);

    for (auto it = json.begin(); it != json.end(); ++it) {
        const auto* field = findField(descriptor, it.key());
        if (!field) continue;
        if (!mergeField(message, field, it.value())) {
            protobuf_c_message_free_unpacked(message, nullptr);
            return nullptr;
        }
    }
    return message;
}

} // namespace

nlohmann::json messageToJson(const ProtobufCMessage* message) {
    return messageToJsonImpl(message);
}

bool messageToJsonString(const ProtobufCMessage* message, std::string* out) {
    if (!out || !message) return false;
    try {
        *out = messageToJsonImpl(message).dump();
        return true;
    } catch (...) {
        return false;
    }
}

ProtobufCMessage* messageFromJson(const ProtobufCMessageDescriptor* descriptor,
                                  const nlohmann::json& json) {
    return messageFromJsonImpl(descriptor, json);
}

ProtobufCMessage* messageFromJsonString(const ProtobufCMessageDescriptor* descriptor,
                                        const std::string& json) {
    try {
        const auto j = nlohmann::json::parse(json, nullptr, false);
        if (j.is_discarded()) return nullptr;
        return messageFromJsonImpl(descriptor, j);
    } catch (...) {
        return nullptr;
    }
}

} // namespace bff
