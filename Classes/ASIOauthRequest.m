//
//  ASIOauthRequest.m
//  ASIOauthTest
//
//  Created by Michael Dales on 22/04/2010.
//  Copyright 2010 Michael Dales. All rights reserved.
//

#import "ASIOauthRequest.h"

#import "NSData+Base64.h"

#import <CommonCrypto/CommonHMAC.h> 
#import <sys/time.h>

@implementation ASIOauthRequest

#pragma mark -
#pragma mark Internal OAuth utility methods

- (NSString*)createNonce
{
	NSString *res = @"";
	
	// XXX: note we used to call srandom(time(NULL)) here, but we could generate requests too quickly,
	// and the server would reject the same nonse being used too frequently.
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srandom((unsigned int)(tv.tv_usec + (1000000 * tv.tv_sec)));
	
	for (int i = 0; i < 10; i++)
	{		
		res = [NSString stringWithFormat: @"%@%02x", res, random() & 0XFF];
	}
	
	return res;
}


- (NSString*)rawHMAC_SHA1EncodeString: (NSString*)plaintext usingKey: (NSString*)keytext
{	
	unsigned char digest[CC_SHA1_DIGEST_LENGTH] = {0};
	const char* keychar = (char*)[keytext cStringUsingEncoding: NSUTF8StringEncoding];
	const char* datachar = (char*)[plaintext cStringUsingEncoding: NSUTF8StringEncoding];
	
	CCHmacContext hctx;
	CCHmacInit(&hctx, kCCHmacAlgSHA1, keychar, strlen(keychar));
	CCHmacUpdate(&hctx, datachar, strlen(datachar));
	CCHmacFinal(&hctx, digest);
	
	
	NSData *digestData = [NSData dataWithBytes: digest
										length: CC_SHA1_DIGEST_LENGTH];
	NSString *encodedString = [digestData base64EncodedString];
	
	return encodedString;
}


- (NSString*)generateHMAC_SHA1SignatureString: (NSDictionary*)headerInfo
{
	
	NSString *portString;
	// we need to normalise the URL. We only include the port if it's non-standard.
	if (([url port] == nil) ||
		((([[url scheme] compare: @"http"] == NSOrderedSame) && ([[url port] integerValue] == 80)) ||
		 (([[url scheme] compare: @"https"] == NSOrderedSame) && ([[url port] integerValue] == 443))))
	{
		portString = @"";
	}
	else
	{
		portString = [NSString stringWithFormat: @":%@", [url port]];
	}
	
	// NSURL path strips the trailing / of the URL. Hence this stupid bit of code
	NSString *urlstr = [url absoluteString];
	NSArray *parts = [urlstr componentsSeparatedByString: @"?"];
	urlstr = [parts objectAtIndex: 0];
	unichar lastchar = [urlstr characterAtIndex: urlstr.length - 1];
	NSString *trailingSlash = lastchar == '/' ? @"/" : @"";
	
	NSString *normalised_url = [NSString stringWithFormat: @"%@://%@%@%@%@", [url scheme], [url host], 
								portString, [url path], trailingSlash];
	
	NSMutableArray *keys = [NSMutableArray arrayWithArray: [headerInfo allKeys]];
	
	[keys sortUsingSelector: @selector(compare:)];
	
	// Build up the param string, before adding it, as it needs to be escaped
	NSString *paramstr = @"";
	for (NSString *key in keys)
	{
		paramstr = [NSString stringWithFormat: @"%@%@%@=%@", paramstr, 
					paramstr.length == 0? @"" : @"&",
					[self encodeURL: key], 
					[self encodeURL: [headerInfo objectForKey: key]]];
	}
	
	// first add normalized http method, then the normalised url
	NSString *raw = [NSString stringWithFormat: @"%@&%@&%@", 
					 [self encodeURL: requestMethod], 
					 [self encodeURL: normalised_url],
					 [self encodeURL: paramstr]];
	
	NSString *key = [NSString stringWithFormat: @"%@&%@", consumerSecret, tokenSecret != nil ? tokenSecret : @""];
	
	// we now have the raw text, and the key, so do the signing
	return [self rawHMAC_SHA1EncodeString: raw
								 usingKey: key];
	
}


- (void)generateOAuthSignature: (NSMutableDictionary*)headerInfo
{
	switch (signatureMethod)
	{
		case ASIPlaintextOAuthSignatureMethod:
		{			
			[headerInfo setObject: @"PLAINTEXT"
						   forKey: @"oauth_signature_method"];
			[headerInfo setObject: [NSString stringWithFormat: @"%@&%@", consumerSecret, tokenSecret != nil ? tokenSecret : @""]
						   forKey: @"oauth_signature"];
			break;
		}
			
		case ASIHMAC_SHA1OAuthSignatureMethod:
		{
			[headerInfo setObject: @"HMAC-SHA1"
						   forKey: @"oauth_signature_method"];
			[headerInfo setObject: [self generateHMAC_SHA1SignatureString: headerInfo]
						   forKey: @"oauth_signature"];
			break;
		}
	}
}


- (void)buildAuthorizationHeader {
	
	
	NSMutableDictionary *headerInfo = [NSMutableDictionary dictionaryWithCapacity: 5];
	
	
	
	// before we call super, build the OAuth headers
	[headerInfo setObject: consumerKey
				   forKey: @"oauth_consumer_key"];
	if (tokenKey != nil)
		[headerInfo setObject: tokenKey
					   forKey: @"oauth_token"];
	
	
	NSDate *now = [NSDate date];
	NSTimeInterval nowValue = [now timeIntervalSince1970];
	NSString *timestamp = [NSString stringWithFormat: @"%d", (int)nowValue];
	[headerInfo setObject: timestamp
				   forKey: @"oauth_timestamp"];
	[headerInfo setObject: @"1.0"
				   forKey: @"oauth_version"];
	[headerInfo setObject: [self createNonce]
				   forKey: @"oauth_nonce"];
	
	// now we've built the request, sign it
	[self generateOAuthSignature: headerInfo];
	
	// build the header string
	NSString *paramstr = @"OAuth ";
	for (NSString *key in headerInfo)
	{
		paramstr = [NSString stringWithFormat: @"%@%@%@=\"%@\"", paramstr, 
					paramstr.length == 6 ? @"" : @", ",
					[self encodeURL: key], 
					[self encodeURL: [headerInfo objectForKey: key]]];
	}
	
	// done, now update the headers
	[self addRequestHeader: @"Authorization"
					 value: paramstr];
}



#pragma mark -
#pragma mark Constructor/destructor


+ (id)requestWithURL:(NSURL *)desturl forConsumerWithKey: (NSString*)key andSecret: (NSString*)secret
{
	return [[[self alloc] initWithURL: desturl forConsumerWithKey: key andSecret: secret] autorelease];
}

- (id)initWithURL: (NSURL*)desturl forConsumerWithKey: (NSString*)key andSecret: (NSString*)secret
{
	if ((self = [super initWithURL: desturl]) != nil)
	{
		self.consumerKey = key;
		self.consumerSecret = secret;
		self.signatureMethod = ASIPlaintextOAuthSignatureMethod;		
		
		[self buildAuthorizationHeader];
	}
	
	return self;
}

- (void)setTokenWithKey: (NSString*)key andSecret: (NSString*)secret
{
	// properties for these values are read only, to stop people forgetting to set one or the other, so 
	// remember to retain here
	[tokenKey release];
	[tokenSecret release];
	
	tokenKey = key;
	tokenSecret = secret;
	
	[tokenKey retain];
	[tokenSecret retain];
	
	[self buildAuthorizationHeader];
}

- (void)dealloc
{
	[consumerKey release];
	[consumerSecret release];
	[tokenKey release];
	[tokenSecret release];
	[returnedTokenKey release];
	[returnedTokenSecret release];
	
	[super dealloc];
}


#pragma mark -
#pragma mark Token decoding untility methods

- (void)parseReturnedToken
{	
	// guard against people calling this code multiple times
	[returnedTokenKey release]; returnedTokenKey = nil;
	[returnedTokenSecret release]; returnedTokenSecret = nil;
	
	// we should have a reply like: oauth_token_secret=CC2sL93UdYzwpQT9&oauth_token=Nw86rNQ653BnSGSw
	NSString *response = [self responseString];
	NSArray *pairs = [response componentsSeparatedByString: @"&"];
	
	if (pairs.count != 2)
		return;
	
	for (NSString* pair in pairs)
	{
		NSArray* key_value_parts = [pair componentsSeparatedByString: @"="];
		if (key_value_parts.count != 2)
			continue;
		
		NSString *key = [key_value_parts objectAtIndex: 0];
		NSString *value = [key_value_parts objectAtIndex: 1];
		
		if ([key compare: @"oauth_token"] == NSOrderedSame)
			returnedTokenKey = [value retain];
		else if ([key compare: @"oauth_token_secret"] == NSOrderedSame)
			returnedTokenSecret = [value retain];
	}
}


#pragma mark -
#pragma mark Properties

@synthesize consumerKey;
@synthesize consumerSecret;
@synthesize tokenKey;
@synthesize tokenSecret;
@synthesize signatureMethod;
@synthesize returnedTokenKey;
@synthesize returnedTokenSecret;

@end
