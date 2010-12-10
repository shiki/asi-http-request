//
//  ASIOauthRequestTest.m
//  Part of ASIHTTPRequest -> http://allseeing-i.com/ASIHTTPRequest
//
//  Created by Michael Dales on 10/12/2010.
//

#import "ASIOauthRequestTest.h"
#import "ASIOauthRequest.h"

static NSString* const kServiceURL = @"kServiceURL";
static NSString* const kConsumerKey = @"kConsumerKey";
static NSString* const kConsumerSecret = @"kConsumerSecret";
static NSString* const kServiceAPIPath = @"kServiceAPIPath";
static NSString* const kServiceAPIParams = @"kServiceAPIParams";


static NSString *serviceAPIRequestDataPList = @"ASIOauthRequestTestParameters.plist";


@implementation ASIOauthRequestTest

- (void)setUpClass
{	
	NSString *path = [NSString stringWithFormat: @"%@/%@", [[NSBundle mainBundle] resourcePath], serviceAPIRequestDataPList];
	testParameters = [[NSDictionary alloc] initWithContentsOfFile: path];
}

- (void)tearDownClass
{
	[testParameters release];
	[accessTokenKey release];
	[accessTokenSecret release];
}

- (void)testFetchRequetToken
{
	NSString *requestURL = [NSString stringWithFormat: @"%@/oauth/request_token/", [testParameters objectForKey: kServiceURL]];
	
	NSURL *url = [NSURL URLWithString: requestURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: [testParameters objectForKey: kConsumerKey]
													 andSecret: [testParameters objectForKey: kConsumerSecret]];
	[request startSynchronous];
	BOOL success = ([request responseStatusCode] == 200);
	GHAssertTrue(success,@"Didn't get correct status code");
	
	[request parseReturnedToken];
	success = (request.returnedTokenKey != nil);
	GHAssertTrue(success,@"Didn't get valid returned token key");
	success = (request.returnedTokenSecret != nil);
	GHAssertTrue(success,@"Didn't get valid returned token secret");
	
	
	request = [ASIOauthRequest requestWithURL: url 
						   forConsumerWithKey: @"Bad Key"
									andSecret: @"Bad Secret"];
	[request startSynchronous];
	success = ([request responseStatusCode] == 401);
	GHAssertTrue(success,@"Didn't get correct status code");
	
	[request parseReturnedToken];
	success = (request.returnedTokenKey == nil);
	GHAssertTrue(success,@"Didn't get empty returned token key");
	success = (request.returnedTokenSecret == nil);
	GHAssertTrue(success,@"Didn't get empty returned token secret");
}


- (void)testFetchAccessToken
{	
	NSString *requestURL = [NSString stringWithFormat: @"%@/oauth/request_token/", [testParameters objectForKey: kServiceURL]];
	NSURL *url = [NSURL URLWithString: requestURL];
	
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: [testParameters objectForKey: kConsumerKey]
													 andSecret: [testParameters objectForKey: kConsumerSecret]];
	[request startSynchronous];
	BOOL success = ([request responseStatusCode] == 200);
	GHAssertTrue(success,@"Didn't get correct status code");
	
	[request parseReturnedToken];
	success = (request.returnedTokenKey != nil);
	GHAssertTrue(success,@"Didn't get valid returned token key");
	success = (request.returnedTokenSecret != nil);
	GHAssertTrue(success,@"Didn't get valid returned token secret");

	// having got the request token, get it authenticated
	NSString *authURL = [NSString stringWithFormat: @"%@/oauth/authorize/?oauth_token=%@", 
						 [testParameters objectForKey: kServiceURL], request.returnedTokenKey];
	[[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString: authURL]];
	
	// wait for oauth to have passed
	NSAlert *alert = [NSAlert alertWithMessageText: @"OAuth authorization"
									 defaultButton: @"OK"
								   alternateButton: nil
									   otherButton: nil
						 informativeTextWithFormat: @"Click OK once you've authorized the token"];
	[alert runModal];
	 	 
	// now try swapping the request token for an access token	
	NSString *accessURL = [NSString stringWithFormat: @"%@/oauth/access_token/", [testParameters objectForKey: kServiceURL]];
	url = [NSURL URLWithString: accessURL];
	ASIOauthRequest *access_request = [ASIOauthRequest requestWithURL: url 
												   forConsumerWithKey: [testParameters objectForKey: kConsumerKey]
															andSecret: [testParameters objectForKey: kConsumerSecret]];
	[access_request setTokenWithKey: request.returnedTokenKey
						  andSecret: request.returnedTokenSecret];
	[access_request startSynchronous];
	success = ([access_request responseStatusCode] == 200);
	GHAssertTrue(success,@"Didn't get correct status code");
	
	[access_request parseReturnedToken];
	success = (access_request.returnedTokenKey != nil);
	GHAssertTrue(success,@"Didn't get valid returned token key");
	success = (access_request.returnedTokenSecret != nil);
	GHAssertTrue(success,@"Didn't get valid returned token secret");
	
	
	// we'll need to use these on future tests
	accessTokenKey = [access_request.returnedTokenKey retain];
	accessTokenSecret = [access_request.returnedTokenSecret retain];
}


- (void)testGetRequest
{
	BOOL success = (accessTokenKey != nil) && (accessTokenSecret != nil);
	GHAssertTrue(success, @"Don't have access token");
	
	// turn into get params - assume everything is already escaped
	NSDictionary *requestParams = [testParameters objectForKey: kServiceAPIParams];
	NSString *params = @"";
	for (NSString *key in requestParams)
	{
		params = [NSString stringWithFormat: @"%@%@%@=%@&blah=foo",
				  params,
				  params.length == 0 ? @"" : @"&",
				  key,
				  [requestParams objectForKey: key]];
	}
	NSString *fullURL = [NSString stringWithFormat: @"%@%@?%@", 
						 [testParameters objectForKey: kServiceURL],
						 [testParameters objectForKey: kServiceAPIPath],
						 params];
	
	NSURL *url = [NSURL URLWithString: fullURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: [testParameters objectForKey: kConsumerKey]
													 andSecret: [testParameters objectForKey: kConsumerSecret]];
	[request setTokenWithKey: accessTokenKey
				   andSecret: accessTokenSecret];
	[request startSynchronous];
	success = ([request responseStatusCode] == 200);
	GHAssertTrue(success,@"Didn't get correct status code");
}


- (void)testPostRequest
{
	BOOL success = (accessTokenKey != nil) && (accessTokenSecret != nil);
	GHAssertTrue(success, @"Don't have access token");
	
	NSString *fullURL = [NSString stringWithFormat: @"%@%@", 
						 [testParameters objectForKey: kServiceURL],
						 [testParameters objectForKey: kServiceAPIPath]];
	NSURL *url = [NSURL URLWithString: fullURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: [testParameters objectForKey: kConsumerKey]
													 andSecret: [testParameters objectForKey: kConsumerSecret]];
	
	NSDictionary *requestParams = [testParameters objectForKey: kServiceAPIParams];
	for (NSString *key in requestParams)
	{
		[request setPostValue: [requestParams objectForKey: key]
					   forKey: key];
	}		
	
	[request setTokenWithKey: accessTokenKey
				   andSecret: accessTokenSecret];	
	[request startSynchronous];
	success = ([request responseStatusCode] == 200);
	GHAssertTrue(success,@"Didn't get correct status code");
}


@end
