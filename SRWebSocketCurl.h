#import <Foundation/Foundation.h>
#import <SocketRocket/SocketRocket.h>

NS_ASSUME_NONNULL_BEGIN

/// A libcurl-based WebSocket implementation that inherits from SocketRocket's SRWebSocket.
/// Overrides the stream-based connection with bff::WebSocket (curl) while preserving the
/// SRWebSocketDelegate protocol and public API surface.
@interface SRWebSocketCurl : SRWebSocket

@end

NS_ASSUME_NONNULL_END
