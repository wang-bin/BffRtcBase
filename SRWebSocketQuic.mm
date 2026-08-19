#import "SRWebSocketQuic.h"

#include "Cert.h"
#include "Log.hpp"
#include "QuicSocket.h"

#include <errno.h>
#include <algorithm>
#include <memory>
#include <string>

#define TAG "quic.ws"

static NSString *const SRWebSocketQuicErrorDomain = @"com.bffmsg.SRWebSocketQuic";

namespace {

static std::string NSStringToStdString(NSString *string)
{
    if (!string.length) {
        return {};
    }
    return std::string(string.UTF8String);
}

static NSString *StdStringToNSString(const std::string &value)
{
    if (value.empty()) {
        return @"";
    }
    return [[NSString alloc] initWithBytes:value.data()
                                    length:value.size()
                                  encoding:NSUTF8StringEncoding] ?: @"";
}

static std::string QuicSNIHostFromRequest(NSURLRequest *request,
                                          SRSecurityPolicy *securityPolicy,
                                          const std::string &urlHost)
{
    BOOL sni = YES;
    NSString *host = nil;
    if (securityPolicy) {
        if ([securityPolicy respondsToSelector:NSSelectorFromString(@"sni")]) {
            if (id value = [securityPolicy valueForKey:@"sni"]) {
                if ([value isKindOfClass:[NSNumber class]]) {
                    sni = [value boolValue];
                }
            }
        }
        if (sni && [securityPolicy respondsToSelector:NSSelectorFromString(@"host")]) {
            if (id value = [securityPolicy valueForKey:@"host"]) {
                if ([value isKindOfClass:[NSString class]] && [(NSString *)value length]) {
                    host = (NSString *)value;
                }
            }
        }
    }

    if (!sni) {
        return {};
    }

    if (!host.length) {
        for (NSString *key in request.allHTTPHeaderFields) {
            if ([key caseInsensitiveCompare:@"Host"] == NSOrderedSame) {
                NSString *value = request.allHTTPHeaderFields[key];
                if (value.length) {
                    host = value;
                    break;
                }
            }
        }
    }

    return host.length ? NSStringToStdString(host) : urlHost;
}

} // namespace

@interface SRWebSocketQuic ()
@property (nonatomic, strong) NSURLRequest *quic_request;
@property (nonatomic, copy, nullable) NSArray<NSString *> *quic_protocols;
@property (nonatomic, strong, nullable) SRSecurityPolicy *quic_securityPolicy;
@property (nonatomic, assign) BOOL quic_opened;
- (instancetype)initQuicWithURLRequest:(NSURLRequest *)request
                             protocols:(nullable NSArray<NSString *> *)protocols
                        securityPolicy:(nullable SRSecurityPolicy *)securityPolicy;
@end

@implementation SRWebSocketQuic {
    std::unique_ptr<bff::QuicSocket> _ws;
    SRReadyState _quic_readyState;
    BOOL _allowsUntrustedSSLCertificates;
}

#pragma mark - Initializers

- (instancetype)initWithURLRequest:(NSURLRequest *)request
{
    return [self initQuicWithURLRequest:request protocols:nil securityPolicy:nil];
}

- (instancetype)initWithURLRequest:(NSURLRequest *)request securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    return [self initQuicWithURLRequest:request protocols:nil securityPolicy:securityPolicy];
}

- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray<NSString *> *)protocols
{
    return [self initQuicWithURLRequest:request protocols:protocols securityPolicy:nil];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-implementations"
- (instancetype)initWithURLRequest:(NSURLRequest *)request
                         protocols:(NSArray<NSString *> *)protocols
  allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates
{
    self = [self initQuicWithURLRequest:request protocols:protocols securityPolicy:nil];
    if (self) {
        _allowsUntrustedSSLCertificates = allowsUntrustedSSLCertificates;
    }
    return self;
}
#pragma clang diagnostic pop

- (instancetype)initWithURLRequest:(NSURLRequest *)request
                         protocols:(NSArray<NSString *> *)protocols
                    securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    return [self initQuicWithURLRequest:request protocols:protocols securityPolicy:securityPolicy];
}

- (instancetype)initWithURL:(NSURL *)url
{
    return [self initWithURLRequest:[NSURLRequest requestWithURL:url] protocols:nil];
}

- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray<NSString *> *)protocols
{
    return [self initWithURLRequest:[NSURLRequest requestWithURL:url] protocols:protocols];
}

- (instancetype)initWithURL:(NSURL *)url securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    return [self initQuicWithURLRequest:[NSURLRequest requestWithURL:url]
                              protocols:nil
                         securityPolicy:securityPolicy];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-implementations"
- (instancetype)initWithURL:(NSURL *)url
                  protocols:(NSArray<NSString *> *)protocols
allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates
{
    self = [self initWithURLRequest:[NSURLRequest requestWithURL:url] protocols:protocols];
    if (self) {
        _allowsUntrustedSSLCertificates = allowsUntrustedSSLCertificates;
    }
    return self;
}
#pragma clang diagnostic pop

- (instancetype)initWithURL:(NSURL *)url
                  protocols:(NSArray<NSString *> *)protocols
             securityPolicy:(SRSecurityPolicy *)securityPolicy
{
    return [self initQuicWithURLRequest:[NSURLRequest requestWithURL:url]
                              protocols:protocols
                         securityPolicy:securityPolicy];
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
    return _allowsUntrustedSSLCertificates;
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

- (instancetype)initQuicWithURLRequest:(NSURLRequest *)request
                             protocols:(nullable NSArray<NSString *> *)protocols
                        securityPolicy:(nullable SRSecurityPolicy *)securityPolicy
{
    // SocketRocket's other inits are convenience methods that bounce through `self`.
    // Calling them via super re-enters our overrides and recurses until the stack dies.
    self = [super initWithURLRequest:request protocols:protocols securityPolicy:securityPolicy];
    if (!self) {
        return nil;
    }
    _quic_request = [request copy];
    _quic_protocols = [protocols copy];
    _quic_securityPolicy = securityPolicy;
    _quic_readyState = SR_CONNECTING;
    return self;
}

- (NSError *)errorFromQuicSocket
{
    if (!_ws) {
        return [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                                   code:0
                               userInfo:@{NSLocalizedDescriptionKey: @"QUIC WebSocket error"}];
    }

    NSString *message = StdStringToNSString(_ws->lastError());
    if (!message.length) {
        message = @"QUIC WebSocket error";
    }

    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    userInfo[NSLocalizedDescriptionKey] = message;

    const int httpCode = _ws->lastErrorCode();
    if (httpCode > 0) {
        userInfo[@"HTTPResponseStatusCode"] = @(httpCode);
    }

    return [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                               code:httpCode
                           userInfo:userInfo];
}

#pragma mark - Open / Close

- (void)open
{
    if (self.quic_opened) {
        return;
    }
    self.quic_opened = YES;
    [self setQuicReadyState:SR_CONNECTING];

    if (!_ws) {
        _ws = std::make_unique<bff::QuicSocket>();
    }

    NSURL *url = self.quic_request.URL;
    const std::string urlHost = NSStringToStdString(url.host);
    const std::string sniHost = QuicSNIHostFromRequest(self.quic_request,
                                                       self.quic_securityPolicy,
                                                       urlHost);

    __weak typeof(self) weakSelf = self;
    _ws->onCertVerify([](void *ssl_ctx) { return AddCertsToSSL(ssl_ctx); });
    _ws->setOnOpen([weakSelf]() {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        DBG("onOpen");
        [strongSelf performDelegate:^{
            [strongSelf setQuicReadyState:SR_OPEN];
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if ([delegate respondsToSelector:@selector(webSocketDidOpen:)]) {
                [delegate webSocketDidOpen:strongSelf];
            }
        }];
    });

    _ws->setOnRecv([weakSelf](std::string data, bool binary) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSData *payload = data.empty()
            ? [NSData data]
            : [NSData dataWithBytes:data.data() length:data.size()];
        NSString *text = binary ? nil : StdStringToNSString(data);

        [strongSelf performDelegate:^{
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if (binary) {
                if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessageWithData:)]) {
                    [delegate webSocket:strongSelf didReceiveMessageWithData:payload];
                } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessage:)]) {
                    [delegate webSocket:strongSelf didReceiveMessage:payload];
                }
                return;
            }

            BOOL convertToString = YES;
            if ([delegate respondsToSelector:@selector(webSocketShouldConvertTextFrameToString:)]) {
                convertToString = [delegate webSocketShouldConvertTextFrameToString:strongSelf];
            }
            if (convertToString) {
                if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessageWithString:)]) {
                    [delegate webSocket:strongSelf didReceiveMessageWithString:text];
                } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessage:)]) {
                    [delegate webSocket:strongSelf didReceiveMessage:text];
                }
            } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessageWithData:)]) {
                [delegate webSocket:strongSelf didReceiveMessageWithData:payload];
            }
        }];
    });

    _ws->setOnError([weakSelf](bff::QuicSocket::Error error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSString *message = StdStringToNSString(error.detail);
        if (!message.length) {
            message = @"QUIC WebSocket error";
        }

        NSString *errDomain = SRWebSocketQuicErrorDomain;
        NSInteger nsCode = 0;
        NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
        userInfo[NSLocalizedDescriptionKey] = message;

        switch (error.kind) {
            case bff::QuicSocket::ErrorKind::Timeout:
                errDomain = NSURLErrorDomain;
                nsCode = NSURLErrorTimedOut;
                break;
            case bff::QuicSocket::ErrorKind::Ssl:
                nsCode = NSURLErrorClientCertificateRejected;
                break;
            case bff::QuicSocket::ErrorKind::Resolve:
                nsCode = EHOSTDOWN;
                break;
            case bff::QuicSocket::ErrorKind::Http:
                if (error.httpCode > 0) {
                    userInfo[@"HTTPResponseStatusCode"] = @(error.httpCode);
                }
                nsCode = error.httpCode;
                break;
            case bff::QuicSocket::ErrorKind::Connect:
            case bff::QuicSocket::ErrorKind::InvalidUrl:
            case bff::QuicSocket::ErrorKind::Other:
                break;
        }

        NSError *err = [NSError errorWithDomain:errDomain code:nsCode userInfo:userInfo];
        DBG("onError. kind=%d code=%ld detail=%s",
            static_cast<int>(error.kind), (long)nsCode, message.UTF8String ?: "");
        [strongSelf performDelegate:^{
            [strongSelf setQuicReadyState:SR_CLOSED];
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if ([delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
                [delegate webSocket:strongSelf didFailWithError:err];
            }
        }];
    });

    _ws->setOnClose([weakSelf](int code, std::string reason, bool remote) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSString *reasonText = reason.empty() ? nil : StdStringToNSString(reason);
        const NSInteger closeCode = (!remote && code == 0) ? SRStatusCodeNormal : code;
        const BOOL wasClean = closeCode == SRStatusCodeNormal || closeCode == SRStatusCodeGoingAway;
        DBG("onClose. code=%ld reason=%s remote=%d",
            (long)closeCode, reasonText.UTF8String ?: "", (int)remote);
        [strongSelf performDelegate:^{
            [strongSelf setQuicReadyState:SR_CLOSED];
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if ([delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                [delegate webSocket:strongSelf
                     didCloseWithCode:closeCode
                               reason:reasonText
                             wasClean:wasClean];
            }
        }];
    });

    bff::QuicSocket::OpenOptions options;
    options.url = NSStringToStdString(url.absoluteString);
    options.sni_host = sniHost;

    _ws->setConnectTimeout(static_cast<int>(std::max(0.0, self.quic_request.timeoutInterval * 1000.0)));
    if (!_ws->open(options)) {
        [self setQuicReadyState:SR_CLOSED];
        id<SRWebSocketDelegate> delegate = self.delegate;
        if ([delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
            [delegate webSocket:self didFailWithError:[self errorFromQuicSocket]];
        }
    }
}

- (void)close
{
    DBG("close");
    [self closeWithCode:SRStatusCodeNormal reason:nil];
}

- (void)closeWithCode:(NSInteger)code reason:(nullable NSString *)reason
{
    DBG("close. code=%ld, reason=%s", (long)code, reason.UTF8String ?: "");
    if (_quic_readyState == SR_CLOSED || _quic_readyState == SR_CLOSING) {
        return;
    }
    [self setQuicReadyState:SR_CLOSING];
    if (_ws) {
        _ws->closeAsync(static_cast<int>(code), NSStringToStdString(reason));
    }
}

#pragma mark - Send

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-implementations"
- (void)send:(nullable id)message
{
    if ([message isKindOfClass:[NSString class]]) {
        NSError *error = nil;
        [self sendString:message error:&error];
    } else if ([message isKindOfClass:[NSData class]]) {
        NSError *error = nil;
        [self sendData:message error:&error];
    }
}
#pragma clang diagnostic pop

- (BOOL)sendString:(NSString *)string error:(NSError **)error
{
    if (!string) {
        if (error) {
            *error = [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                                         code:0
                                     userInfo:@{NSLocalizedDescriptionKey: @"message is nil"}];
        }
        return NO;
    }
    if (_quic_readyState != SR_OPEN) {
        if (error) {
            *error = [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                                         code:0
                                     userInfo:@{NSLocalizedDescriptionKey: @"socket is not connected"}];
        }
        return NO;
    }
    const std::string payload = NSStringToStdString(string);
    return _ws->send(payload.data(), payload.size(), false);
}

- (BOOL)sendData:(nullable NSData *)data error:(NSError **)error
{
    return [self sendPayload:data error:error];
}

- (BOOL)sendDataNoCopy:(nullable NSData *)data error:(NSError **)error
{
    return [self sendPayload:data error:error];
}

- (BOOL)sendPayload:(nullable NSData *)data error:(NSError **)error
{
    if (!data) {
        if (error) {
            *error = [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                                         code:0
                                     userInfo:@{NSLocalizedDescriptionKey: @"data is nil"}];
        }
        return NO;
    }
    if (_quic_readyState != SR_OPEN) {
        if (error) {
            *error = [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                                         code:0
                                     userInfo:@{NSLocalizedDescriptionKey: @"socket is not connected"}];
        }
        return NO;
    }
    return _ws->send(data.bytes, data.length, true);
}

- (BOOL)sendPing:(NSData *)data error:(NSError **)error
{
    (void)data;
    if (error) {
        *error = [NSError errorWithDomain:SRWebSocketQuicErrorDomain
                                     code:0
                                 userInfo:@{NSLocalizedDescriptionKey: @"sendPing is not supported"}];
    }
    return NO;
}

#pragma mark - Dealloc

- (void)dealloc
{
    if (_ws) {
        _ws->setOnOpen(nullptr);
        _ws->setOnClose(nullptr);
        _ws->setOnError(nullptr);
        _ws->setOnRecv(nullptr);
        _ws->onCertVerify(nullptr);
        _ws->close();
        _ws.reset();
    }
}

@end
