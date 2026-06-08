#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRSecurityPolicy : NSObject

+ (instancetype)defaultPolicy;

+ (instancetype)pinnningPolicyWithCertificates:(NSArray *)pinnedCertificates
    DEPRECATED_MSG_ATTRIBUTE("Using pinned certificates is neither secure nor supported, "
                             "and leads to security issues. Please use a proper, trust chain validated certificate.");

- (instancetype)initWithCertificateChainValidationEnabled:(BOOL)enabled
    DEPRECATED_MSG_ATTRIBUTE("Disabling certificate chain validation is unsafe. "
                             "Please use a proper Certificate Authority to issue your TLS certificates.");

- (void)updateSecurityOptionsInStream:(NSStream *)stream;

- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain;

@end

NS_ASSUME_NONNULL_END
