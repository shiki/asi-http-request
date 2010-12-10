//
//  ASIOauthRequestTest.h
//  Part of ASIHTTPRequest -> http://allseeing-i.com/ASIHTTPRequest
//
//  Created by Michael Dales on 10/12/2010.
//

#import <Foundation/Foundation.h>
#import "ASITestCase.h"

@interface ASIOauthRequestTest : ASITestCase 
{
	// load the test parameters from a plist, as it's tidier + allows dicts/arrays
	NSDictionary *testParameters;
	
	NSString *accessTokenKey;
	NSString *accessTokenSecret;
}

@end
