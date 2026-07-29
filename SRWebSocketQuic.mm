#import "SRWebSocketQuic.h"

#include "quic/socket.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

static NSString *const SRWebSocketQuicErrorDomain = @"com.bffmsg.SRWebSocketQuic";

typedef NS_ENUM(NSInteger, SRWebSocketQuicErrorCode) {
    SRWebSocketQuicErrorInvalidURL = 1001,
    SRWebSocketQuicErrorResolveHost = 1002,
    SRWebSocketQuicErrorOpenFailed = 1003,
    SRWebSocketQuicErrorOpenStreamFailed = 1004,
    SRWebSocketQuicErrorSendFailed = 1005,
    SRWebSocketQuicErrorProtocolDecode = 1006,
    SRWebSocketQuicErrorHandshakeCode = 1007,
};

namespace {

std::string NSStringToStdString(NSString *string)
{
    if (!string.length) {
        return {};
    }
    return std::string(string.UTF8String);
}

NSString *StdStringToNSString(const std::string &value)
{
    if (value.empty()) {
        return @"";
    }
    return [[NSString alloc] initWithBytes:value.data()
                                    length:value.size()
                                  encoding:NSUTF8StringEncoding] ?: @"";
}

size_t PutUVarIntLen(uint64_t n)
{
    if (n < 64) {
        return 1;
    }
    if (n < 16384) {
        return 2;
    }
    if (n < 1073741824ULL) {
        return 4;
    }
    return 8;
}

uint8_t *PutUVarInt(uint8_t *p, uint64_t n)
{
    if (n < 64) {
        *p++ = static_cast<uint8_t>(n);
        return p;
    }
    if (n < 16384) {
        p[0] = static_cast<uint8_t>(0x40 | ((n >> 8) & 0x3f));
        p[1] = static_cast<uint8_t>(n);
        return p + 2;
    }
    if (n < 1073741824ULL) {
        p[0] = static_cast<uint8_t>(0x80 | ((n >> 24) & 0x3f));
        p[1] = static_cast<uint8_t>((n >> 16) & 0xff);
        p[2] = static_cast<uint8_t>((n >> 8) & 0xff);
        p[3] = static_cast<uint8_t>(n & 0xff);
        return p + 4;
    }
    p[0] = static_cast<uint8_t>(0xc0 | ((n >> 56) & 0x3f));
    p[1] = static_cast<uint8_t>((n >> 48) & 0xff);
    p[2] = static_cast<uint8_t>((n >> 40) & 0xff);
    p[3] = static_cast<uint8_t>((n >> 32) & 0xff);
    p[4] = static_cast<uint8_t>((n >> 24) & 0xff);
    p[5] = static_cast<uint8_t>((n >> 16) & 0xff);
    p[6] = static_cast<uint8_t>((n >> 8) & 0xff);
    p[7] = static_cast<uint8_t>(n & 0xff);
    return p + 8;
}

size_t GetUVarIntLen(uint8_t first)
{
    return size_t{1} << (first >> 6);
}

size_t GetUVarInt(uint64_t *dest, std::span<const uint8_t> p)
{
    if (p.empty()) {
        return 0;
    }
    const auto len = GetUVarIntLen(p[0]);
    if (p.size() < len) {
        return 0;
    }
    uint64_t n = p[0] & 0x3f;
    for (size_t i = 1; i < len; ++i) {
        n = (n << 8) | p[i];
    }
    *dest = n;
    return len;
}

std::vector<uint8_t> WrapVarIntPayload(std::span<const uint8_t> payload)
{
    const auto vlen = PutUVarIntLen(payload.size());
    std::vector<uint8_t> framed(vlen + payload.size());
    auto *p = PutUVarInt(framed.data(), payload.size());
    if (!payload.empty()) {
        std::memcpy(p, payload.data(), payload.size());
    }
    return framed;
}

bool ParseBoolQueryValue(NSString *value)
{
    if (!value.length) {
        return NO;
    }
    NSString *lower = value.lowercaseString;
    return [lower isEqualToString:@"true"] || [lower isEqualToString:@"1"] || [lower isEqualToString:@"yes"];
}

std::string BuildPathAndQuery(NSURL *url)
{
    return NSStringToStdString(url.query.length ? url.query : @"");
}

} // namespace

@interface SRWebSocketQuic ()
@property (nonatomic, strong) NSURLRequest *quic_request;
@property (nonatomic, copy, nullable) NSArray<NSString *> *quic_protocols;
@property (nonatomic, strong, nullable) SRSecurityPolicy *quic_securityPolicy;
@property (nonatomic, assign) BOOL quic_opened;
@property (nonatomic, assign) BOOL quic_payloadText;
@end

@implementation SRWebSocketQuic {
    std::unique_ptr<quic::Socket> _socket;
    SRReadyState _quic_readyState;
    std::string _host;
    std::string _port;
    std::string _params;
    int64_t _streamId;
    bool _receivedStatusCode;
    std::vector<uint8_t> _rxBuffer;
    std::mutex _rxMutex;
}

#pragma mark - Initializers

- (instancetype)initWithURLRequest:(NSURLRequest *)request
{
    return [self initWithURLRequest:request protocols:nil securityPolicy:nil];
}

- (instancetype)initWithURLRequest:(NSURLRequest *)request securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    return [self initWithURLRequest:request protocols:nil securityPolicy:securityPolicy];
}

- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray<NSString *> *)protocols
{
    return [self initWithURLRequest:request protocols:protocols securityPolicy:nil];
}

- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray<NSString *> *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates
{
    (void)allowsUntrustedSSLCertificates;
    return [self initWithURLRequest:request protocols:protocols securityPolicy:nil];
}

- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray<NSString *> *)protocols securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    self = [super initWithURLRequest:request protocols:protocols securityPolicy:securityPolicy];
    if (!self) {
        return nil;
    }
    _quic_request = [request copy];
    _quic_protocols = [protocols copy];
    _quic_securityPolicy = securityPolicy;
    _quic_readyState = SR_CONNECTING;
    _streamId = quic::kInvalidStream;
    _receivedStatusCode = false;
    _socket = std::make_unique<quic::Socket>();

    NSURLComponents *components = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
    NSString *jsonValue = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name.lowercaseString isEqualToString:@"json"]) {
            jsonValue = item.value;
            break;
        }
    }
    _quic_payloadText = ParseBoolQueryValue(jsonValue ?: @"");
    return self;
}

- (instancetype)initWithURL:(NSURL *)url
{
    return [self initWithURL:url protocols:nil securityPolicy:nil];
}

- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray<NSString *> *)protocols
{
    return [self initWithURL:url protocols:protocols securityPolicy:nil];
}

- (instancetype)initWithURL:(NSURL *)url securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    return [self initWithURL:url protocols:nil securityPolicy:securityPolicy];
}

- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray<NSString *> *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates
{
    (void)allowsUntrustedSSLCertificates;
    return [self initWithURL:url protocols:protocols securityPolicy:nil];
}

- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray<NSString *> *)protocols securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    return [self initWithURLRequest:request protocols:protocols securityPolicy:securityPolicy];
}

#pragma mark - Property overrides

- (SRReadyState)readyState
{
    return _quic_readyState;
}

- (CFHTTPMessageRef)receivedHTTPHeaders
{
    return NULL;
}

- (NSString *)protocol
{
    return nil;
}

- (BOOL)allowsUntrustedSSLCertificates
{
    return NO;
}

#pragma mark - RunLoop scheduling

- (void)scheduleInRunLoop:(NSRunLoop *)runLoop forMode:(NSString *)mode
{
    (void)runLoop;
    (void)mode;
}

- (void)unscheduleFromRunLoop:(NSRunLoop *)runLoop forMode:(NSString *)mode
{
    (void)runLoop;
    (void)mode;
}

#pragma mark - Helpers

- (void)performDelegate:(dispatch_block_t)block
{
    if (!block) {
        return;
    }
    if (self.delegateOperationQueue) {
        [self.delegateOperationQueue addOperationWithBlock:block];
        return;
    }
    dispatch_queue_t queue = self.delegateDispatchQueue ?: dispatch_get_main_queue();
    dispatch_async(queue, block);
}

- (void)setQuicReadyState:(SRReadyState)readyState
{
    _quic_readyState = readyState;
}

- (NSError *)makeError:(SRWebSocketQuicErrorCode)code description:(NSString *)description
{
    return [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description ?: @"QUIC websocket error"}];
}

- (void)failWithError:(NSError *)error closeSocket:(BOOL)closeSocket
{
    [self setQuicReadyState:SR_CLOSED];
    if (closeSocket && _socket) {
        _socket->close();
    }
    [self performDelegate:^{
        id<SRWebSocketDelegate> delegate = self.delegate;
        if ([delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
            [delegate webSocket:self didFailWithError:error];
        }
    }];
}

- (BOOL)parseURLForConnect:(NSError **)error
{
    NSURL *url = self.quic_request.URL;
    if (!url || !url.host.length) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorInvalidURL description:@"invalid websocket URL"];
        }
        return NO;
    }

    _host = NSStringToStdString(url.host);
    NSInteger port = url.port.integerValue;
    if (port <= 0) {
        NSString *scheme = url.scheme.lowercaseString;
        if ([scheme isEqualToString:@"wss"] || [scheme isEqualToString:@"https"]) {
            port = 443;
        } else {
            port = 80;
        }
    }
    _port = std::to_string(port);
    _params = BuildPathAndQuery(url);
    return YES;
}

- (BOOL)sendRawBytes:(const uint8_t *)bytes length:(size_t)length error:(NSError **)error
{
    if (!_socket || _streamId == quic::kInvalidStream) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"stream is not ready"];
        }
        return NO;
    }
    const int rc = _socket->send(std::span<const uint8_t>(bytes, length), 0, _streamId);
    if (rc != quic::Ok) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"quic send failed"];
        }
        return NO;
    }
    return YES;
}

- (BOOL)sendFramedPayload:(std::span<const uint8_t>)payload error:(NSError **)error
{
    auto framed = WrapVarIntPayload(payload);
    return [self sendRawBytes:framed.data() length:framed.size() error:error];
}

- (void)handleDataFramesLocked
{
    if (!_receivedStatusCode) {
        uint64_t code = 0;
        const auto consumed = GetUVarInt(&code, std::span<const uint8_t>(_rxBuffer.data(), _rxBuffer.size()));
        if (consumed == 0) {
            return;
        }
        _rxBuffer.erase(_rxBuffer.begin(), _rxBuffer.begin() + static_cast<std::ptrdiff_t>(consumed));
        _receivedStatusCode = true;
        if (code != 200) {
            NSError *err = [self makeError:SRWebSocketQuicErrorHandshakeCode
                               description:[NSString stringWithFormat:@"quic handshake status code: %llu", code]];
            [self failWithError:err closeSocket:YES];
            return;
        }
        [self performDelegate:^{
            [self setQuicReadyState:SR_OPEN];
            id<SRWebSocketDelegate> delegate = self.delegate;
            if ([delegate respondsToSelector:@selector(webSocketDidOpen:)]) {
                [delegate webSocketDidOpen:self];
            }
        }];
    }

    while (!_rxBuffer.empty()) {
        uint64_t payloadLen = 0;
        const auto vlen = GetUVarInt(&payloadLen, std::span<const uint8_t>(_rxBuffer.data(), _rxBuffer.size()));
        if (vlen == 0) {
            return;
        }
        if (_rxBuffer.size() < vlen + payloadLen) {
            return;
        }
        const auto payloadOffset = vlen;
        NSData *payload = payloadLen == 0
            ? [NSData data]
            : [NSData dataWithBytes:_rxBuffer.data() + payloadOffset length:payloadLen];

        std::string textData;
        if (self.quic_payloadText && payloadLen > 0) {
            textData.assign(reinterpret_cast<const char *>(_rxBuffer.data() + payloadOffset), payloadLen);
        }
        NSString *text = self.quic_payloadText ? StdStringToNSString(textData) : nil;

        [self performDelegate:^{
            id<SRWebSocketDelegate> delegate = self.delegate;
            if (!self.quic_payloadText) {
                if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessageWithData:)]) {
                    [delegate webSocket:self didReceiveMessageWithData:payload];
                } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessage:)]) {
                    [delegate webSocket:self didReceiveMessage:payload];
                }
                return;
            }

            BOOL convertToString = YES;
            if ([delegate respondsToSelector:@selector(webSocketShouldConvertTextFrameToString:)]) {
                convertToString = [delegate webSocketShouldConvertTextFrameToString:self];
            }
            if (convertToString) {
                if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessageWithString:)]) {
                    [delegate webSocket:self didReceiveMessageWithString:text];
                } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessage:)]) {
                    [delegate webSocket:self didReceiveMessage:text];
                }
            } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessageWithData:)]) {
                [delegate webSocket:self didReceiveMessageWithData:payload];
            }
        }];

        const auto consumed = vlen + payloadLen;
        _rxBuffer.erase(_rxBuffer.begin(), _rxBuffer.begin() + static_cast<std::ptrdiff_t>(consumed));
    }
}

#pragma mark - Open / Close

- (void)open
{
    if (self.quic_opened) {
        return;
    }
    self.quic_opened = YES;
    [self setQuicReadyState:SR_CONNECTING];
    _streamId = quic::kInvalidStream;
    _receivedStatusCode = false;
    {
        std::lock_guard<std::mutex> lock(_rxMutex);
        _rxBuffer.clear();
    }

    NSError *parseError = nil;
    if (![self parseURLForConnect:&parseError]) {
        [self failWithError:parseError closeSocket:NO];
        return;
    }

    __weak typeof(self) weakSelf = self;
    _socket->onRecv([weakSelf](uint64_t conn_id, int64_t stream_id, std::span<const uint8_t> data, bool fin) {
        (void)conn_id;
        (void)stream_id;
        (void)fin;
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        std::lock_guard<std::mutex> lock(strongSelf->_rxMutex);
        strongSelf->_rxBuffer.insert(strongSelf->_rxBuffer.end(), data.begin(), data.end());
        [strongSelf handleDataFramesLocked];
    });

    _socket->onError([weakSelf](uint64_t conn_id, quic::Error error) {
        (void)conn_id;
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        NSString *reason = StdStringToNSString(error.reason);
        if (!reason.length) {
            reason = [NSString stringWithFormat:@"quic error kind=%u code=%llu", (unsigned)error.kind, error.code];
        }
        NSError *err = [strongSelf makeError:SRWebSocketQuicErrorOpenFailed description:reason];
        if (error.kind == quic::ErrKind::Application) {
            NSMutableDictionary *userInfo = [err.userInfo mutableCopy] ?: [NSMutableDictionary dictionary];
            userInfo[@"HTTPResponseStatusCode"] = @(error.code);
            err = [NSError errorWithDomain:err.domain code:err.code userInfo:userInfo];
        }
        [strongSelf failWithError:err closeSocket:NO];
    });

    _socket->onClose([weakSelf](uint64_t conn_id) {
        (void)conn_id;
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf performDelegate:^{
            [strongSelf setQuicReadyState:SR_CLOSED];
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if ([delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                [delegate webSocket:strongSelf didCloseWithCode:SRStatusCodeNormal reason:nil wasClean:YES];
            }
        }];
    });

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(_host.c_str(), _port.c_str(), &hints, &res) != 0 || !res) {
        [self failWithError:[self makeError:SRWebSocketQuicErrorResolveHost
                                 description:[NSString stringWithFormat:@"resolve host failed: %s:%s", _host.c_str(), _port.c_str()]]
                closeSocket:NO];
        return;
    }

    int rc = quic::Err;
    for (auto *rp = res; rp; rp = rp->ai_next) {
        rc = _socket->open(rp->ai_addr, rp->ai_addrlen);
        if (rc == quic::Ok) {
            break;
        }
    }
    freeaddrinfo(res);
    if (rc != quic::Ok) {
        [self failWithError:[self makeError:SRWebSocketQuicErrorOpenFailed description:@"quic open failed"]
                closeSocket:NO];
        return;
    }

    _streamId = _socket->openStream();
    if (_streamId == quic::kInvalidStream) {
        [self failWithError:[self makeError:SRWebSocketQuicErrorOpenStreamFailed description:@"open quic stream failed"]
                closeSocket:YES];
        return;
    }

    NSError *sendError = nil;
    const uint8_t marker = 0x35;
    if (![self sendRawBytes:&marker length:1 error:&sendError]) {
        [self failWithError:sendError closeSocket:YES];
        return;
    }
    const auto paramsBytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(_params.data()),
        _params.size());
    if (![self sendFramedPayload:paramsBytes error:&sendError]) {
        [self failWithError:sendError closeSocket:YES];
    }
}

- (void)close
{
    [self closeWithCode:SRStatusCodeNormal reason:nil];
}

- (void)closeWithCode:(NSInteger)code reason:(NSString *)reason
{
    (void)code;
    (void)reason;
    if (_quic_readyState == SR_CLOSED || _quic_readyState == SR_CLOSING) {
        return;
    }
    [self setQuicReadyState:SR_CLOSING];
    if (_socket) {
        _socket->close();
    }
}

#pragma mark - Send

- (void)send:(id)message
{
    if ([message isKindOfClass:[NSString class]]) {
        NSError *error = nil;
        [self sendString:message error:&error];
    } else if ([message isKindOfClass:[NSData class]]) {
        NSError *error = nil;
        [self sendData:message error:&error];
    }
}

- (BOOL)sendString:(NSString *)string error:(NSError **)error
{
    if (!string) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"message is nil"];
        }
        return NO;
    }
    if (_quic_readyState != SR_OPEN) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"socket is not connected"];
        }
        return NO;
    }
    const std::string payload = NSStringToStdString(string);
    return [self sendFramedPayload:std::span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(payload.data()), payload.size()) error:error];
}

- (BOOL)sendData:(NSData *)data error:(NSError **)error
{
    return [self sendPayload:data error:error];
}

- (BOOL)sendDataNoCopy:(NSData *)data error:(NSError **)error
{
    return [self sendPayload:data error:error];
}

- (BOOL)sendPayload:(NSData *)data error:(NSError **)error
{
    if (!data) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"data is nil"];
        }
        return NO;
    }
    if (_quic_readyState != SR_OPEN) {
        if (error) {
            *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"socket is not connected"];
        }
        return NO;
    }
    return [self sendFramedPayload:std::span<const uint8_t>(
        static_cast<const uint8_t *>(data.bytes), data.length) error:error];
}

- (BOOL)sendPing:(NSData *)data error:(NSError **)error
{
    (void)data;
    if (error) {
        *error = [self makeError:SRWebSocketQuicErrorSendFailed description:@"sendPing is not supported"];
    }
    return NO;
}

#pragma mark - Dealloc

- (void)dealloc
{
    if (_socket) {
        _socket->close();
        _socket.reset();
    }
}

@end
