#import <UIKit/UIKit.h>
#import <TargetConditionals.h>
#include <stdlib.h>
#include "differential.h"

static NSDictionary *worker_report(CPRiskDifferentialResult result, int status) {
    return @{ @"seed": [NSString stringWithFormat:@"%016llx", (unsigned long long)result.seed],
        @"cases": @(result.cases), @"known_answer_checks": @(result.known_answer_checks),
        @"failure_line": @(result.failure_line), @"returncode": @(status) };
}
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    (void)application; (void)options;
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 340, 80)];
    label.numberOfLines = 0; label.text = @"IR-VMP Release differential is running";
    [controller.view addSubview:label]; self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSTimeInterval started = NSProcessInfo.processInfo.systemUptime;
        CPRiskDifferentialSuiteResult suite;
        BOOL passed = cprisk_ios_differential_suite(&suite) == 0;
        NSMutableArray *concurrent = [NSMutableArray array];
        for (unsigned i = 0; i < 4; ++i) {
            [concurrent addObject:worker_report(suite.concurrent[i], suite.concurrent_status[i])];
        }
        NSString *runID = NSBundle.mainBundle.infoDictionary[@"CPRiskRunID"];
        NSDictionary *report = @{ @"schema_version": @1, @"run_id": runID,
            @"status": passed ? @"PASS" : @"FAIL", @"physical_device": @(!TARGET_OS_SIMULATOR),
            @"configuration": @"Release", @"serial": worker_report(suite.serial, suite.serial_status),
            @"concurrent": concurrent, @"thread_error": @(suite.thread_error),
            @"workers_ready": @(suite.workers_ready), @"start_gate_used": @YES,
            @"os": UIDevice.currentDevice.systemVersion,
            @"model": UIDevice.currentDevice.model,
            @"elapsed_seconds": @(NSProcessInfo.processInfo.systemUptime - started) };
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&error];
        NSURL *documents = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
        NSURL *path = [documents URLByAppendingPathComponent:[NSString stringWithFormat:@"report-%@.json", runID]];
        BOOL wrote = json && [json writeToURL:path options:NSDataWritingAtomic error:&error];
        fprintf(stdout, "CPRISK_DEVICE_RESULT %s\n", wrote ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String : "WRITE_FAILED");
        fflush(stdout);
        dispatch_async(dispatch_get_main_queue(), ^{ exit(passed && wrote ? 0 : 1); });
    });
    return YES;
}
@end
int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class)); }
}
