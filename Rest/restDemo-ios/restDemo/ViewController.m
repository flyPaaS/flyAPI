//
//  ViewController.m
//  restDemo
//
//  Created by KCMac on 2017/11/2.
//  Copyright © 2017年 flypass. All rights reserved.
//

#import "ViewController.h"
#import "HttpRequestEngine.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)applySDKIDClick:(id)sender
{
    NSString *accountSid = @"*********";
    NSString *token = @"***********";
    NSString *appid = @"***************";
    
    [[HttpRequestEngine engineInstance] applySDKID:accountSid appid:appid token:token successBlock:^(NSDictionary *responseDict) {
        NSLog(@"resp %@",responseDict);
    } failBlock:^(NSDictionary *responseDict) {

    }];
    
}


@end
