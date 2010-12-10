//
//  ASIOauthRequestTest.m
//  Part of ASIHTTPRequest -> http://allseeing-i.com/ASIHTTPRequest
//
//  Created by Michael Dales on 10/12/2010.
//

#import "ASIOauthRequestTest.h"
#import "ASIOauthRequest.h"

// to test OAuth you need to point it at something
static NSString *serviceRequestTokenURL = @"";
static NSString *serviceAccessTokenURL = @"";
static NSString *serverAuthorizeURL = @"";
static NSString *serviceConsumerKey = @"";
static NSString *serviceConsumerSecret = @"";

// this URL should accept both GET and POST requests
static NSString *serviceAPIRequestURL = @"";
static NSString *serviceAPIRequestDataPList = @"ASIOauthRequestTestParameters.plist";


@implementation ASIOauthRequestTest

- (void)testFetchRequetToken
{
	NSURL *url = [NSURL URLWithString: serviceRequestTokenURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: serviceConsumerKey
													 andSecret: serviceConsumerSecret];
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
	NSURL *url = [NSURL URLWithString: serviceRequestTokenURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: serviceConsumerKey
													 andSecret: serviceConsumerSecret];
	[request startSynchronous];
	BOOL success = ([request responseStatusCode] == 200);
	GHAssertTrue(success,@"Didn't get correct status code");
	
	[request parseReturnedToken];
	success = (request.returnedTokenKey != nil);
	GHAssertTrue(success,@"Didn't get valid returned token key");
	success = (request.returnedTokenSecret != nil);
	GHAssertTrue(success,@"Didn't get valid returned token secret");

	// having got the request token, get it authenticated
	[[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString: [NSString stringWithFormat: serverAuthorizeURL, request.returnedTokenKey]]];
	
	// wait for oauth to have passed
	NSAlert *alert = [NSAlert alertWithMessageText: @"OAuth authorization"
									 defaultButton: @"OK"
								   alternateButton: nil
									   otherButton: nil
						 informativeTextWithFormat: @"Click OK once you've authorized the token"];
	[alert runModal];
	 	 
	// now try swapping the request token for an access token	
	url = [NSURL URLWithString: serviceAccessTokenURL];
	ASIOauthRequest *access_request = [ASIOauthRequest requestWithURL: url 
												   forConsumerWithKey: serviceConsumerKey
															andSecret: serviceConsumerSecret];
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
	
	NSString *path = [NSString stringWithFormat: @"%@/%@", [[NSBundle mainBundle] resourcePath], serviceAPIRequestDataPList];
	NSDictionary *requestParams = [NSDictionary dictionaryWithContentsOfFile: path];
	
	// turn into get params - assume everything is already escaped
	NSString *params = @"";
	for (NSString *key in requestParams)
	{
		params = [NSString stringWithFormat: @"%@%@%@=%@",
				  params,
				  params.length == 0 ? @"" : @"&",
				  key,
				  [requestParams objectForKey: key]];
	}
	NSString *fullURL = [NSString stringWithFormat: @"%@?%@", serviceAPIRequestURL, params];
	
	NSURL *url = [NSURL URLWithString: fullURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: serviceConsumerKey
													 andSecret: serviceConsumerSecret];
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
	
	NSString *path = [NSString stringWithFormat: @"%@/%@", [[NSBundle mainBundle] resourcePath], serviceAPIRequestDataPList];
	NSDictionary *requestParams = [NSDictionary dictionaryWithContentsOfFile: path];
		
	NSURL *url = [NSURL URLWithString: serviceAPIRequestURL];
	ASIOauthRequest *request = [ASIOauthRequest requestWithURL: url 
											forConsumerWithKey: serviceConsumerKey
													 andSecret: serviceConsumerSecret];
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


- (void)dealloc
{
	[accessTokenKey release];
	[accessTokenSecret release];
	[super dealloc];
}

@end
