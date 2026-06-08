#import <Foundation/Foundation.h>
#import "SRSecurityPolicy.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SRReadyState) {
    SR_CONNECTING   = 0,
    SR_OPEN         = 1,
    SR_CLOSING      = 2,
    SR_CLOSED       = 3,
};

typedef NS_ENUM(NSInteger, SRStatusCode) {
    SRStatusCodeNormal = 1000,
    SRStatusCodeGoingAway = 1001,
    SRStatusCodeProtocolError = 1002,
    SRStatusCodeUnhandledType = 1003,
    SRStatusNoStatusReceived = 1005,
    SRStatusCodeAbnormal = 1006,
    SRStatusCodeInvalidUTF8 = 1007,
    SRStatusCodePolicyViolated = 1008,
    SRStatusCodeMessageTooBig = 1009,
    SRStatusCodeMissingExtension = 1010,
    SRStatusCodeInternalError = 1011,
    SRStatusCodeServiceRestart = 1012,
    SRStatusCodeTryAgainLater = 1013,
    SRStatusCodeTLSHandshake = 1015,
};

@class SRWebSocket;

extern NSString *const SRWebSocketErrorDomain;
extern NSString *const SRHTTPResponseErrorKey;

@protocol SRWebSocketDelegate;

@interface SRWebSocket : NSObject <NSStreamDelegate>

@property (nonatomic, weak) id <SRWebSocketDelegate> delegate;
@property (nullable, nonatomic, strong) dispatch_queue_t delegateDispatchQueue;
@property (nullable, nonatomic, strong) NSOperationQueue *delegateOperationQueue;
@property (atomic, assign, readonly) SRReadyState readyState;
@property (nullable, nonatomic, strong, readonly) NSURL *url;
@property (nullable, nonatomic, assign, readonly) CFHTTPMessageRef receivedHTTPHeaders;
@property (nullable, nonatomic, copy) NSArray<NSHTTPCookie *> *requestCookies;
@property (nullable, nonatomic, copy, readonly) NSString *protocol;
@property (nonatomic, assign, readonly) BOOL allowsUntrustedSSLCertificates;

- (instancetype)initWithURLRequest:(NSURLRequest *)request;
- (instancetype)initWithURLRequest:(NSURLRequest *)request securityPolicy:(nullable SRSecurityPolicy *)securityPolicy;
- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(nullable NSArray<NSString *> *)protocols;
- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(nullable NSArray<NSString *> *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates
    DEPRECATED_MSG_ATTRIBUTE("Disabling certificate chain validation is unsafe. "
                             "Please use a proper Certificate Authority to issue your TLS certificates.");
- (instancetype)initWithURLRequest:(NSURLRequest *)request protocols:(nullable NSArray<NSString *> *)protocols securityPolicy:(nullable SRSecurityPolicy *)securityPolicy NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithURL:(NSURL *)url;
- (instancetype)initWithURL:(NSURL *)url protocols:(nullable NSArray<NSString *> *)protocols;
- (instancetype)initWithURL:(NSURL *)url securityPolicy:(nullable SRSecurityPolicy *)securityPolicy;
- (instancetype)initWithURL:(NSURL *)url protocols:(nullable NSArray<NSString *> *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates
    DEPRECATED_MSG_ATTRIBUTE("Disabling certificate chain validation is unsafe. "
                             "Please use a proper Certificate Authority to issue your TLS certificates.");
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (void)scheduleInRunLoop:(NSRunLoop *)runLoop forMode:(NSString *)mode NS_SWIFT_NAME(schedule(in:forMode:));
- (void)unscheduleFromRunLoop:(NSRunLoop *)runLoop forMode:(NSString *)mode NS_SWIFT_NAME(unschedule(from:forMode:));

- (void)open;
- (void)close;
- (void)closeWithCode:(NSInteger)code reason:(nullable NSString *)reason;

- (void)send:(nullable id)message __attribute__((deprecated("Please use `sendString:error:` or `sendData:error:` instead.")));
- (BOOL)sendString:(NSString *)string error:(NSError **)error NS_SWIFT_NAME(send(string:));
- (BOOL)sendData:(nullable NSData *)data error:(NSError **)error NS_SWIFT_NAME(send(data:));
- (BOOL)sendDataNoCopy:(nullable NSData *)data error:(NSError **)error NS_SWIFT_NAME(send(dataNoCopy:));
- (BOOL)sendPing:(nullable NSData *)data error:(NSError **)error NS_SWIFT_NAME(sendPing(_:));

@end

@protocol SRWebSocketDelegate <NSObject>

@optional

- (void)webSocket:(SRWebSocket *)webSocket didReceiveMessage:(id)message;
- (void)webSocket:(SRWebSocket *)webSocket didReceiveMessageWithString:(NSString *)string;
- (void)webSocket:(SRWebSocket *)webSocket didReceiveMessageWithData:(NSData *)data;
- (void)webSocketDidOpen:(SRWebSocket *)webSocket;
- (void)webSocket:(SRWebSocket *)webSocket didFailWithError:(NSError *)error;
- (void)webSocket:(SRWebSocket *)webSocket didCloseWithCode:(NSInteger)code reason:(nullable NSString *)reason wasClean:(BOOL)wasClean;
- (void)webSocket:(SRWebSocket *)webSocket didReceivePingWithData:(nullable NSData *)data;
- (void)webSocket:(SRWebSocket *)webSocket didReceivePong:(nullable NSData *)pongData;
- (BOOL)webSocketShouldConvertTextFrameToString:(SRWebSocket *)webSocket NS_SWIFT_NAME(webSocketShouldConvertTextFrameToString(_:));

@end

NS_ASSUME_NONNULL_END
