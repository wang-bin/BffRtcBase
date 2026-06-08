#import "SRSecurityPolicy.h"

@implementation SRSecurityPolicy

+ (instancetype)defaultPolicy
{
    return [[self alloc] init];
}

+ (instancetype)pinnningPolicyWithCertificates:(NSArray *)pinnedCertificates
{
    return [[self alloc] init];
}

- (instancetype)initWithCertificateChainValidationEnabled:(BOOL)enabled
{
    return [self init];
}

- (instancetype)init
{
    return [super init];
}

- (void)updateSecurityOptionsInStream:(NSStream *)stream
{
    (void)stream;
}

- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain
{
    (void)serverTrust;
    (void)domain;
    return YES;
}

@end
