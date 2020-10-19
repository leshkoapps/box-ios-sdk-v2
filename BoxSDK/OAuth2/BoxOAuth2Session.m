//
//  BoxOAuth2Session.m
//  BoxSDK
//
//  Created on 2/21/13.
//  Copyright (c) 2013 Box. All rights reserved.
//

#import "BoxOAuth2Session.h"
#import "BoxLog.h"
#import "BoxSDKConstants.h"
#import "BoxAPIOAuth2ToJSONOperation.h"
#import "NSString+BoxURLHelper.h"
#import "NSURL+BoxURLHelper.h"

NSString *const BoxOAuth2SessionDidBecomeAuthenticatedNotification = @"BoxOAuth2SessionDidBecomeAuthenticated";
NSString *const BoxOAuth2SessionDidReceiveAuthenticationErrorNotification = @"BoxOAuth2SessionDidReceiveAuthenticationError";
NSString *const BoxOAuth2SessionDidRefreshTokensNotification = @"BoxOAuth2SessionDidRefreshTokens";
NSString *const BoxOAuth2SessionDidReceiveRefreshErrorNotification = @"BoxOAuth2SessionDidReceiveRefreshError";

NSString *const BoxOAuth2AuthenticationErrorKey = @"BoxOAuth2AuthenticationError";


@interface BoxOAuth2Session (){
    NSString *_nonce;
}

@end

@implementation BoxOAuth2Session

@synthesize APIBaseURLString = _APIBaseURLString;
@synthesize clientID = _clientID;
@synthesize clientSecret = _clientSecret;
@synthesize accessToken = _accessToken;
@synthesize refreshToken = _refreshToken;
@synthesize accessTokenExpiration = _accessTokenExpiration;
@synthesize queueManager = _queueManager;

#pragma mark - Initialization
- (id)initWithClientID:(NSString *)ID secret:(NSString *)secret APIBaseURL:(NSString *)baseURL queueManager:(BoxAPIQueueManager *)queueManager
{
    self = [super init];
    if (self != nil)
    {
        _clientID = ID;
        _clientSecret = secret;
        _APIBaseURLString = baseURL;
        _queueManager = queueManager;
    }
    return self;
}

#pragma mark - Authorization
- (void)performAuthorizationCodeGrantWithReceivedURL:(NSURL *)URL
{
    NSDictionary *URLQueryParams = [URL box_queryDictionary];
    NSString *authorizationCode = [URLQueryParams valueForKey:BoxOAuth2URLParameterAuthorizationCodeKey];
    NSString *authorizationError = [URLQueryParams valueForKey:BoxOAuth2URLParameterErrorCodeKey];

    if (authorizationError != nil)
    {
        NSDictionary *errorInfo = [NSDictionary dictionaryWithObject:authorizationError
                                                              forKey:BoxOAuth2AuthenticationErrorKey];
        [[NSNotificationCenter defaultCenter] postNotificationName:BoxOAuth2SessionDidReceiveAuthenticationErrorNotification
                                                            object:self
                                                          userInfo:errorInfo];
        return;
    }

    NSMutableDictionary *POSTParams = [NSMutableDictionary new];
    [POSTParams setObject:BoxOAuth2TokenRequestGrantTypeAuthorizationCode forKey:BoxOAuth2TokenRequestGrantTypeKey];
    if(authorizationCode){
        [POSTParams setObject:authorizationCode forKey:BoxOAuth2TokenRequestAuthorizationCodeKey];
    }
    if(self.clientID){
        [POSTParams setObject:self.clientID forKey:BoxOAuth2TokenRequestClientIDKey];
    }
    if(self.clientSecret){
        [POSTParams setObject:self.clientSecret forKey:BoxOAuth2TokenRequestClientSecretKey];
    }
    if(self.redirectURIString){
        [POSTParams setObject:self.redirectURIString forKey:BoxOAuth2TokenRequestRedirectURIKey];
    }

    BoxAPIOAuth2ToJSONOperation *operation = [[BoxAPIOAuth2ToJSONOperation alloc] initWithURL:[self grantTokensURL]
                                                                                   HTTPMethod:BoxAPIHTTPMethodPOST
                                                                                         body:POSTParams
                                                                                  queryParams:nil
                                                                                OAuth2Session:self];

    operation.success = ^(NSURLRequest *request, NSHTTPURLResponse *response, NSDictionary *JSONDictionary)
    {
        self.accessToken = [JSONDictionary valueForKey:BoxOAuth2TokenJSONAccessTokenKey];
        self.refreshToken = [JSONDictionary valueForKey:BoxOAuth2TokenJSONRefreshTokenKey];

        NSTimeInterval accessTokenExpiresIn = [[JSONDictionary valueForKey:BoxOAuth2TokenJSONExpiresInKey] integerValue];
        BOXAssert(accessTokenExpiresIn >= 0, @"accessTokenExpiresIn value is negative");
        self.accessTokenExpiration = [NSDate dateWithTimeIntervalSinceNow:accessTokenExpiresIn];

        // send success notification
        [[NSNotificationCenter defaultCenter] postNotificationName:BoxOAuth2SessionDidBecomeAuthenticatedNotification object:self];
    };

    operation.failure = ^(NSURLRequest *request, NSHTTPURLResponse *response, NSError *error, NSDictionary *JSONDictionary)
    {
        NSDictionary *errorInfo = nil;
        if(error){
            errorInfo = [NSDictionary dictionaryWithObject:error
                                                    forKey:BoxOAuth2AuthenticationErrorKey];
        }
        [[NSNotificationCenter defaultCenter] postNotificationName:BoxOAuth2SessionDidReceiveAuthenticationErrorNotification
                                                            object:self
                                                          userInfo:errorInfo];
    };

    [self.queueManager enqueueOperation:operation];
}

- (NSURL *)authorizeURL
{
    NSString *encodedRedirectURI = [NSString box_stringWithString:self.redirectURIString URLEncoded:YES];
    NSString *authorizeURLString = [NSString stringWithFormat:
                                    @"%@/oauth2/authorize?response_type=code&client_id=%@&state=ok&redirect_uri=%@",
                                    self.APIBaseURLString, self.clientID, encodedRedirectURI];
    return [NSURL URLWithString:authorizeURLString];
}

- (NSURL *)grantTokensURL
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@/oauth2/token", self.APIBaseURLString]];
}

- (NSString *)redirectURIString
{
    return [NSString stringWithFormat:@"boxsdk-%@://boxsdkoauth2redirect", self.clientID];
}

- (NSString *)nonce
{
    if (_nonce == nil) {
        NSMutableData * data = [[NSMutableData alloc] initWithLength:32];
        SecRandomCopyBytes(kSecRandomDefault, 32, data.mutableBytes);
        NSData *encodedData = [data base64EncodedDataWithOptions:0];
        _nonce = [[NSString alloc] initWithData:encodedData encoding:NSUTF8StringEncoding];
    }
    return _nonce;
}


#pragma mark - Token Refresh
- (void)performRefreshTokenGrant:(NSString *)expiredAccessToken
{
    BOXAbstract();
}

#pragma mark - Session info
- (BOOL)isAuthorized
{
    NSDate *now = [NSDate date];
    return [self.accessTokenExpiration timeIntervalSinceDate:now] > 0;
}

#pragma mark - Request Authorization
- (void)addAuthorizationParametersToRequest:(NSMutableURLRequest *)request
{
    NSString *bearerToken = [NSString stringWithFormat:@"Bearer %@", self.accessToken];
    [request addValue:bearerToken forHTTPHeaderField:BoxAPIHTTPHeaderAuthorization];
}

@end
