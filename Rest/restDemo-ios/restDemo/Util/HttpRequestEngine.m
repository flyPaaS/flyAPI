//
//  HttpRequestEngine.m
//  KCT_VOIP_Demo
//
//  Created by KCMac on 2017/1/7.
//  Copyright © 2017年 KCMac. All rights reserved.
//

#import "HttpRequestEngine.h"
#import "TimeUtil.h"
#import "DataEncryption.h"


#define kRestApiBaseURL   @"http://60.205.137.243:80"







@interface HttpRequestEngine()

@property(nonatomic,copy)requestSuccessBlock successBlock;
@property(nonatomic,copy)requestFailBlock failBlock;

@end

static HttpRequestEngine *detailInstance = nil;

@implementation HttpRequestEngine

+(id)engineInstance
{
    @synchronized(self){
        static dispatch_once_t pred;
        dispatch_once(&pred, ^{
            detailInstance = [[self alloc] init];
        });
    }
    
    return detailInstance;
}

- (NSString *)getTimeSp {
    NSDate *nowDate = [NSDate date];
    NSString *times = [TimeUtil gettimeSp:nowDate];
    return times;
}

- (void)applySDKID:(NSString *)sid appid:(NSString *)appid token:(NSString *)token successBlock:(requestSuccessBlock)successBlockT failBlock:(requestFailBlock)failBlockT {
    NSString *timeSp = [self getTimeSp];
    NSString *orBase64 = [NSString stringWithFormat:@"%@:%@",sid,timeSp];
    NSString *orMd5 = [NSString stringWithFormat:@"%@%@%@",sid,token,timeSp];
    //base64、Md5加密后
    NSString *deBase64 = [DataEncryption encodeBase64String:orBase64];
    NSString *deMd5 = [DataEncryption md5CapitalizedString:orMd5];
    NSString *url = [NSString stringWithFormat:@"%@/2017-03-28/Accounts/%@/applySDKID?sig=%@",kRestApiBaseURL,sid,deMd5];
    NSMutableDictionary *bodyDict = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *accountDict = [[NSMutableDictionary alloc] init];
    [accountDict setObject:appid forKey:@"appId"];
    [bodyDict setObject:accountDict forKey:@"SDK"];
    
    NSData *bodyData=[NSJSONSerialization dataWithJSONObject:bodyDict options:NSJSONWritingPrettyPrinted error:nil];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;
    [request setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [request setValue:deBase64 forHTTPHeaderField:@"Authorization"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    //发送请求
    [NSURLConnection sendAsynchronousRequest:request queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse * _Nullable response, NSData * _Nullable data, NSError * _Nullable connectionError) {
        if (data) {
            NSDictionary * dict = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:nil];
            successBlockT(dict);
        } else {
            failBlockT(connectionError.userInfo);
        }
    }];
}

@end
