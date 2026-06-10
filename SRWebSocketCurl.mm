#import "SRWebSocketCurl.h"

#include "WebSocket.h"

#include <errno.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/// Error domain used by this curl-based implementation.
/// Distinct from the pod's SRWebSocketErrorDomain to avoid confusion with stream-level errors.
static NSString *const SRWebSocketCurlErrorDomain = @"com.bffmsg.SRWebSocketCurl";

@interface SRWebSocketCurl ()
@property (nonatomic, strong) NSURLRequest *curl_request;
@property (nonatomic, copy, nullable) NSArray<NSString *> *curl_protocols;
@property (nonatomic, strong, nullable) SRSecurityPolicy *curl_securityPolicy;
@property (nonatomic, assign) BOOL curl_opened;
@end

@implementation SRWebSocketCurl {
    std::unique_ptr<bff::WebSocket> _ws;
    SRReadyState _curl_readyState;
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
    _curl_request = [request copy];
    _curl_protocols = [protocols copy];
    _curl_securityPolicy = securityPolicy;
    _curl_readyState = SR_CONNECTING;
    _ws = std::make_unique<bff::WebSocket>();
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
    return _curl_readyState;
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

#pragma mark - RunLoop scheduling (no-ops — curl manages its own event loop)

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

static bff::WebSocketOpenOptions OptionsFromRequest(NSURLRequest *request, SRSecurityPolicy *securityPolicy)
{
    bff::WebSocketOpenOptions options;
    options.url = NSStringToStdString(request.URL.absoluteString);

    BOOL sni = YES;
    if (securityPolicy && [securityPolicy respondsToSelector:@selector(valueForKey:)]) {
        if ([securityPolicy respondsToSelector:NSSelectorFromString(@"sni")]) {
            if (id v = [securityPolicy valueForKey:@"sni"]) {
                if ([v isKindOfClass:[NSNumber class]]) {
                    sni = [v boolValue];
                }
            }
        }
        if (sni) {
            if ([securityPolicy respondsToSelector:NSSelectorFromString(@"host")]) {
                if (id hostValue = [securityPolicy valueForKey:@"host"]) {
                    if ([hostValue isKindOfClass:[NSString class]] && [(NSString *)hostValue length]) {
                        options.sni_host = NSStringToStdString((NSString *)hostValue);
                    }
                }
            }
        }
    }

    if (sni && options.sni_host.empty()) {
        NSDictionary<NSString *, NSString *> *headers = request.allHTTPHeaderFields;
        if (headers.count) {
            options.headers.reserve(headers.count);
            for (NSString *key in headers) {
                NSString *value = headers[key];
                if (!value) {
                    continue;
                }
                options.headers.emplace_back(NSStringToStdString(key), NSStringToStdString(value));
                if ([key caseInsensitiveCompare:@"Host"] == NSOrderedSame && value.length) {
                    options.sni_host = NSStringToStdString(value);
                }
            }
        }
    }

    return options;
}

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

- (void)setCurlReadyState:(SRReadyState)readyState
{
    _curl_readyState = readyState;
}

- (NSError *)errorFromWebSocket
{
    const int code = _ws->lastErrorCode();
    NSString *message = StdStringToNSString(_ws->lastError());
    if (!message.length) {
        message = @"WebSocket error";
    }

    NSInteger nsCode = code;
#ifdef LIBCURL_VERSION_MAJOR
    if (code == CURLE_COULDNT_CONNECT || code == CURLE_COULDNT_RESOLVE_HOST) {
        //nsCode = EHOSTDOWN;
    }
#endif

    return [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                               code:nsCode
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

#pragma mark - Open / Close

- (void)open
{
    if (self.curl_opened) {
        return;
    }
    self.curl_opened = YES;
    [self setCurlReadyState:SR_CONNECTING];

    __weak typeof(self) weakSelf = self;
    _ws->setOnOpen([weakSelf]() {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf performDelegate:^{
            [strongSelf setCurlReadyState:SR_OPEN];
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
            } else {
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
            }
        }];
    });

    _ws->setOnError([weakSelf](int code, std::string error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        NSString *message = StdStringToNSString(error);
        [strongSelf performDelegate:^{
            [strongSelf setCurlReadyState:SR_CLOSED];
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if ([delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
                NSInteger nsCode = code;
#ifdef LIBCURL_VERSION_MAJOR
                if (code == CURLE_COULDNT_CONNECT || code == CURLE_COULDNT_RESOLVE_HOST) {
                    nsCode = EHOSTDOWN;
                }
#endif
                NSError *err = [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                                                   code:nsCode
                                               userInfo:@{NSLocalizedDescriptionKey: message ?: @"WebSocket error"}];
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
        const BOOL wasClean = code == SRStatusCodeNormal || code == SRStatusCodeGoingAway;
        [strongSelf performDelegate:^{
            [strongSelf setCurlReadyState:SR_CLOSED];
            id<SRWebSocketDelegate> delegate = strongSelf.delegate;
            if ([delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                [delegate webSocket:strongSelf
                     didCloseWithCode:code
                               reason:reasonText
                             wasClean:wasClean];
            }
        }];
    });

    const auto options = OptionsFromRequest(self.curl_request, self.curl_securityPolicy);
    if (!_ws->open(options)) {
        [self setCurlReadyState:SR_CLOSED];
        id<SRWebSocketDelegate> delegate = self.delegate;
        if ([delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
            [delegate webSocket:self didFailWithError:[self errorFromWebSocket]];
        }
    }
}

- (void)close
{
    [self closeWithCode:SRStatusCodeNormal reason:nil];
}

- (void)closeWithCode:(NSInteger)code reason:(NSString *)reason
{
    if (_curl_readyState == SR_CLOSED || _curl_readyState == SR_CLOSING) {
        return;
    }
    [self setCurlReadyState:SR_CLOSING];
    if (_ws) {
        _ws->close(static_cast<int>(code), NSStringToStdString(reason));
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
            *error = [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                                         code:0
                                     userInfo:@{NSLocalizedDescriptionKey: @"message is nil"}];
        }
        return NO;
    }
    if (_curl_readyState != SR_OPEN) {
        if (error) {
            *error = [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                                         code:57
                                     userInfo:@{NSLocalizedDescriptionKey: @"Socket is not connected"}];
        }
        return NO;
    }
    const auto payload = NSStringToStdString(string);
    if (!_ws->send(payload, false)) {
        if (error) {
            *error = [self errorFromWebSocket];
        }
        return NO;
    }
    return YES;
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
            *error = [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                                         code:0
                                     userInfo:@{NSLocalizedDescriptionKey: @"data is nil"}];
        }
        return NO;
    }
    if (_curl_readyState != SR_OPEN) {
        if (error) {
            *error = [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                                         code:57
                                     userInfo:@{NSLocalizedDescriptionKey: @"Socket is not connected"}];
        }
        return NO;
    }
    if (!_ws->send(data.bytes, data.length, true)) {
        if (error) {
            *error = [self errorFromWebSocket];
        }
        return NO;
    }
    return YES;
}

- (BOOL)sendPing:(NSData *)data error:(NSError **)error
{
    (void)data;
    if (error) {
        *error = [NSError errorWithDomain:SRWebSocketCurlErrorDomain
                                     code:0
                                 userInfo:@{NSLocalizedDescriptionKey: @"sendPing is not supported"}];
    }
    return NO;
}

#pragma mark - Dealloc

- (void)dealloc
{
    _ws.reset();
}

@end
