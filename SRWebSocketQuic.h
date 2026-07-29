#import <Foundation/Foundation.h>
#import <SocketRocket/SocketRocket.h>

NS_ASSUME_NONNULL_BEGIN

/// A QUIC-based signaling transport that simulates SRWebSocket behavior.
/// Transport and framing follow the project's laser varint protocol.
@interface SRWebSocketQuic : SRWebSocket

@end

NS_ASSUME_NONNULL_END
