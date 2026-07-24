// Host-side unit tests for PbCJson.
//
// Build & run (from this directory):
//   ./run_PbCJson_test.sh
//
// Or manually:
//   cc -c protobuf-c/protobuf-c.c -I. -o /tmp/protobuf-c.o
//   cc -c rtc.pb-c.c -I. -o /tmp/rtc.pb-c.o
//   c++ -std=c++20 -DJSON_NOEXCEPTION -c PbCJson.cpp -I. -o /tmp/PbCJson.o
//   c++ -std=c++20 -DJSON_NOEXCEPTION -c PbCJson_test.cpp -I. -o /tmp/PbCJson_test.o
//   c++ /tmp/PbCJson_test.o /tmp/PbCJson.o /tmp/rtc.pb-c.o /tmp/protobuf-c.o -o /tmp/PbCJson_test
//   /tmp/PbCJson_test

#include "PbCJson.h"
#include "rtc.pb-c.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

int g_failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        const auto _va = (a);                                                  \
        const auto _vb = (b);                                                  \
        if (!(_va == _vb)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s == %s (%lld vs %lld)\n",       \
                         __FILE__, __LINE__, #a, #b,                           \
                         (long long)_va, (long long)_vb);                      \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

void test_join_with_location_to_json() {
    Rtc__Location loc = RTC__LOCATION__INIT;
    loc.latitude = 31.2f;
    loc.longitude = 121.5f;

    Rtc__Options join = RTC__OPTIONS__INIT;
    join.ip = const_cast<char*>("1.2.3.4");
    join.video_orientation = 1;
    join.location = &loc;
    join.publishing_audio = 1;
    join.publishing_video = 1;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.id = 42;
    req.channel = 0; // default — should be omitted
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_JOIN;
    req.join = &join;

    std::string json;
    CHECK(bff::messageToJsonString(&req.base, &json));
    CHECK(json.find("\"id\":42") != std::string::npos);
    CHECK(json.find("\"join\"") != std::string::npos);
    CHECK(json.find("\"videoOrientation\":true") != std::string::npos);
    CHECK(json.find("\"publishingAudio\":1") != std::string::npos);
    CHECK(json.find("\"ip\":\"1.2.3.4\"") != std::string::npos);
    CHECK(json.find("\"latitude\"") != std::string::npos);
    CHECK(json.find("\"longitude\"") != std::string::npos);
    // omit-defaults: channel 0 not present
    CHECK(json.find("\"channel\"") == std::string::npos);
}

void test_pong_from_json_camel_and_snake() {
    {
        const std::string respJson = R"({"id":1,"channel":0,"pong":{"timestamp":123}})";
        auto* msg = bff::messageFromJsonString(&rtc__signal_response__descriptor, respJson);
        CHECK(msg != nullptr);
        auto* resp = reinterpret_cast<Rtc__SignalResponse*>(msg);
        CHECK_EQ(resp->id, 1u);
        CHECK_EQ(resp->channel, 0u);
        CHECK_EQ(resp->message_case, RTC__SIGNAL_RESPONSE__MESSAGE_PONG);
        CHECK(resp->pong != nullptr);
        CHECK_EQ(resp->pong->timestamp, 123u);
        rtc__signal_response__free_unpacked(resp, nullptr);
    }
    {
        // snake_case keys also accepted
        const std::string respJson =
            R"({"id":2,"node_list":{"stun_port":443,"client_ip":"9.9.9.9"}})";
        auto* msg = bff::messageFromJsonString(&rtc__signal_response__descriptor, respJson);
        CHECK(msg != nullptr);
        auto* resp = reinterpret_cast<Rtc__SignalResponse*>(msg);
        CHECK_EQ(resp->message_case, RTC__SIGNAL_RESPONSE__MESSAGE_NODE_LIST);
        CHECK(resp->node_list != nullptr);
        CHECK_EQ(resp->node_list->stun_port, 443u);
        CHECK(resp->node_list->client_ip != nullptr);
        CHECK(std::strcmp(resp->node_list->client_ip, "9.9.9.9") == 0);
        rtc__signal_response__free_unpacked(resp, nullptr);
    }
}

void test_offer_enum_roundtrip() {
    Rtc__SessionDescription offer = RTC__SESSION_DESCRIPTION__INIT;
    offer.type = RTC__SDP_TYPE__SDP_TYPE_OFFER;
    offer.sdp = const_cast<char*>("v=0");

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.id = 7;
    req.channel = 1;
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_OFFER;
    req.offer = &offer;

    std::string json;
    CHECK(bff::messageToJsonString(&req.base, &json));
    CHECK(json.find("\"channel\":1") != std::string::npos);
    CHECK(json.find("SDP_TYPE_OFFER") != std::string::npos);

    auto* msg = bff::messageFromJsonString(&rtc__signal_request__descriptor, json);
    CHECK(msg != nullptr);
    auto* parsed = reinterpret_cast<Rtc__SignalRequest*>(msg);
    CHECK_EQ(parsed->id, 7u);
    CHECK_EQ(parsed->channel, 1u);
    CHECK_EQ(parsed->message_case, RTC__SIGNAL_REQUEST__MESSAGE_OFFER);
    CHECK(parsed->offer != nullptr);
    CHECK_EQ(parsed->offer->type, RTC__SDP_TYPE__SDP_TYPE_OFFER);
    CHECK(parsed->offer->sdp != nullptr);
    CHECK(std::strcmp(parsed->offer->sdp, "v=0") == 0);
    rtc__signal_request__free_unpacked(parsed, nullptr);
}

void test_bytes_base64_roundtrip() {
    const uint8_t keyBytes[] = {0x00, 0x01, 0xfe, 0xff};
    Rtc__SrtpKey srtp = RTC__SRTP_KEY__INIT;
    srtp.profile = RTC__SRTP_PROFILE__AES128_CM_HMAC_SHA1_80;
    srtp.key.data = const_cast<uint8_t*>(keyBytes);
    srtp.key.len = sizeof(keyBytes);

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.id = 9;
    req.channel = 1;
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_SRTP_KEY;
    req.srtp_key = &srtp;

    std::string json;
    CHECK(bff::messageToJsonString(&req.base, &json));
    CHECK(json.find("\"key\"") != std::string::npos);

    auto* msg = bff::messageFromJsonString(&rtc__signal_request__descriptor, json);
    CHECK(msg != nullptr);
    auto* parsed = reinterpret_cast<Rtc__SignalRequest*>(msg);
    CHECK_EQ(parsed->message_case, RTC__SIGNAL_REQUEST__MESSAGE_SRTP_KEY);
    CHECK(parsed->srtp_key != nullptr);
    CHECK_EQ(parsed->srtp_key->key.len, sizeof(keyBytes));
    CHECK(std::memcmp(parsed->srtp_key->key.data, keyBytes, sizeof(keyBytes)) == 0);
    rtc__signal_request__free_unpacked(parsed, nullptr);
}

void test_repeated_codecs() {
    const char* c0 = "h264";
    const char* c1 = "opus";
    char* codecs[] = {const_cast<char*>(c0), const_cast<char*>(c1)};

    Rtc__Options join = RTC__OPTIONS__INIT;
    join.n_codecs = 2;
    join.codecs = codecs;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.id = 3;
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_JOIN;
    req.join = &join;

    std::string json;
    CHECK(bff::messageToJsonString(&req.base, &json));
    CHECK(json.find("\"codecs\":[\"h264\",\"opus\"]") != std::string::npos);

    auto* msg = bff::messageFromJsonString(&rtc__signal_request__descriptor, json);
    CHECK(msg != nullptr);
    auto* parsed = reinterpret_cast<Rtc__SignalRequest*>(msg);
    CHECK(parsed->join != nullptr);
    CHECK_EQ(parsed->join->n_codecs, 2u);
    CHECK(std::strcmp(parsed->join->codecs[0], "h264") == 0);
    CHECK(std::strcmp(parsed->join->codecs[1], "opus") == 0);
    rtc__signal_request__free_unpacked(parsed, nullptr);
}

void test_message_to_json_object_and_invalid() {
    Rtc__Ping ping = RTC__PING__INIT;
    ping.timestamp = 99;
    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.id = 5;
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_PING;
    req.ping = &ping;

    const nlohmann::json j = bff::messageToJson(&req.base);
    CHECK(j.is_object());
    CHECK(j.contains("id"));
    CHECK(j["id"] == 5);
    CHECK(j.contains("ping"));
    CHECK(j["ping"]["timestamp"] == 99);

    CHECK(bff::messageFromJsonString(&rtc__signal_response__descriptor, "not-json") == nullptr);
    CHECK(bff::messageFromJsonString(&rtc__signal_response__descriptor, "[]") == nullptr);
    CHECK(bff::messageToJsonString(nullptr, nullptr) == false);
    std::string out;
    CHECK(bff::messageToJsonString(nullptr, &out) == false);
}

void test_location_roundtrip_via_json_object() {
    const nlohmann::json j = {
        {"id", 11},
        {"join", {
            {"ip", "10.0.0.1"},
            {"location", {{"latitude", 22.5}, {"longitude", 114.0}}},
            {"videoOrientation", true},
        }},
    };
    auto* msg = bff::messageFromJson(&rtc__signal_request__descriptor, j);
    CHECK(msg != nullptr);
    auto* req = reinterpret_cast<Rtc__SignalRequest*>(msg);
    CHECK_EQ(req->message_case, RTC__SIGNAL_REQUEST__MESSAGE_JOIN);
    CHECK(req->join != nullptr);
    CHECK(req->join->location != nullptr);
    CHECK(std::fabs(req->join->location->latitude - 22.5f) < 1e-5f);
    CHECK(std::fabs(req->join->location->longitude - 114.0f) < 1e-5f);
    CHECK(req->join->video_orientation != 0);
    rtc__signal_request__free_unpacked(req, nullptr);
}

} // namespace

int main() {
    test_join_with_location_to_json();
    test_pong_from_json_camel_and_snake();
    test_offer_enum_roundtrip();
    test_bytes_base64_roundtrip();
    test_repeated_codecs();
    test_message_to_json_object_and_invalid();
    test_location_roundtrip_via_json_object();

    if (g_failures != 0) {
        std::fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    std::puts("PbCJson_test: all passed");
    return 0;
}
