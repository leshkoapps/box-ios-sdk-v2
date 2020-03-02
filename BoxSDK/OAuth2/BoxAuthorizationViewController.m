//
//  BoxAuthorizationViewController.m
//  BoxSDK
//
//  Created on 2/20/13.
//  Copyright (c) 2013 Box. All rights reserved.
//

#import "BoxAuthorizationViewController.h"
#import "BoxLog.h"

@interface BoxAuthorizationViewController () <WKUIDelegate, WKNavigationDelegate>

@property (nonatomic, readwrite, strong) WKWebView *webView;
@property (nonatomic, readwrite, strong) NSURL *authorizationURL;
@property (nonatomic, readwrite, strong) NSString *redirectURIString;
@property (nonatomic, readwrite, assign) BOOL hasLoadedLoginPage;

- (void)cancel:(id)sender;

@end

@implementation BoxAuthorizationViewController

@synthesize delegate = _delegate;
@synthesize authorizationURL = _authorizationURL;
@synthesize redirectURIString = _redirectURIString;
@synthesize hasLoadedLoginPage = _hasLoadedLoginPage;

- (instancetype)initWithAuthorizationURL:(NSURL *)authorizationURL
                             redirectURI:(NSString *)redirectURI{
    self = [super init];
    if (self != nil){
        _authorizationURL = authorizationURL;
        _redirectURIString = redirectURI;
        [self.navigationItem setRightBarButtonItem:[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                                                                 target:self
                                                                                                 action:@selector(cancel:)]];
    }
    
    return self;
}

- (void)viewDidLoad{
    [super viewDidLoad];
    
    WKWebViewConfiguration *theConfiguration = [[WKWebViewConfiguration alloc] init];
    if (@available(iOS 9.0, *)) {
        theConfiguration.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];
    }
    
    NSString *scalePageToFitScript = @"var meta = document.createElement('meta'); meta.setAttribute('name', 'viewport'); meta.setAttribute('content', 'width=device-width'); document.getElementsByTagName('head')[0].appendChild(meta);";
    WKUserScript *wkUScript = [[WKUserScript alloc] initWithSource:scalePageToFitScript injectionTime:WKUserScriptInjectionTimeAtDocumentEnd forMainFrameOnly:YES];
    WKUserContentController *wkUController = [[WKUserContentController alloc] init];
    [wkUController addUserScript:wkUScript];
    theConfiguration.userContentController = wkUController;
    
    WKWebView *webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:theConfiguration];
    webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    webView.navigationDelegate = self;
    webView.UIDelegate = self;
    [self.view addSubview:webView];
    self.webView = webView;
}

- (void)viewWillAppear:(BOOL)animated{
    [super viewWillAppear:animated];
    if (self.hasLoadedLoginPage == NO){
        self.hasLoadedLoginPage = YES;
        NSURLRequest *request = [[NSURLRequest alloc] initWithURL:self.authorizationURL];
        [self.webView loadRequest:request];
    }
}

- (void)viewWillDisappear:(BOOL)animated{
    [super viewWillDisappear:animated];
    [self.webView stopLoading];
}

#pragma mark - Actions

- (void)cancel:(id)sender{
    if ([self.delegate respondsToSelector:@selector(authorizationViewControllerDidCancel:)]){
        [self.delegate authorizationViewControllerDidCancel:self];
    }
}

#pragma mark - WKWebViewDelegate methods

- (void)webView:(WKWebView *)webView decidePolicyForNavigationResponse:(WKNavigationResponse *)navigationResponse decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler{
    if(decisionHandler){
        decisionHandler(WKNavigationResponsePolicyAllow);
    }
}

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler{
    
    NSURLRequest *request = navigationAction.request;
    WKNavigationType navigationType = navigationAction.navigationType;
    BOXLog(@"Web view should start request %@ with navigation type %ld", request, (long)navigationType);
    BOXLog(@"Request Headers \n%@", [request allHTTPHeaderFields]);
    
    // Before we proceed with handling this request, check if it's about:blank - if it is, do not attempt to load it.
    // Background: We've run into a scenario where an admin included a support help-desk plugin on their SSO page
    // which would (probably erroneously) first load about:blank, then attempt to load its icon. The web view would
    // fail to load about:blank, which would cause the whole page to not appear. So we realized that we can and should
    // generally protect against loading about:blank.
    if ([request.URL isEqual:[NSURL URLWithString:@"about:blank"]]){
        if(decisionHandler){
            decisionHandler(WKNavigationActionPolicyCancel);
        }
        return;
    }
    
    // Figure out whether the scheme of this request is the redirect scheme used at the end of the authentication process
    BOOL requestIsForLoginRedirectScheme = NO;
    if ([self.redirectURIString length] > 0){
        requestIsForLoginRedirectScheme = [[[request URL] scheme] isEqualToString:[[NSURL URLWithString:self.redirectURIString] scheme]];
    }
    
    if (requestIsForLoginRedirectScheme){
        if ([self.delegate respondsToSelector:@selector(authorizationViewController:shouldLoadReceivedOAuth2RedirectRequest:)]){
            BOOL result = [self.delegate authorizationViewController:self shouldLoadReceivedOAuth2RedirectRequest:request];
            WKNavigationActionPolicy actionPolicy = result?WKNavigationActionPolicyAllow:WKNavigationActionPolicyCancel;
            if(decisionHandler){
                decisionHandler(actionPolicy);
            }
            return;
        }
    }
    
    if(decisionHandler){
        decisionHandler(WKNavigationActionPolicyAllow);
    }
}

- (void)webView:(WKWebView *)webView didStartProvisionalNavigation:(null_unspecified WKNavigation *)navigation{
    BOXLogFunction();
    [self.delegate authorizationViewControllerDidStartLoading:self];
}

- (void)webView:(WKWebView *)webView didFailNavigation:(null_unspecified WKNavigation *)navigation withError:(NSError *)error{
    BOXLog(@"WKWebView %@ did fail load with error %@", webView, error);
    if ([[error domain] isEqualToString:NSURLErrorDomain]) {
        if ([error code] == NSURLErrorCancelled){
            return;
        }
    } else if ([[error domain] isEqualToString:@"WebKitErrorDomain"]) {
        if ([error code] == 101 || [error code] == 102){
            return;
        }
    }
    [self.delegate authorizationViewControllerDidFinishLoading:self];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(null_unspecified WKNavigation *)navigation{
    BOXLogFunction();
    [self.delegate authorizationViewControllerDidFinishLoading:self];
}

@end
