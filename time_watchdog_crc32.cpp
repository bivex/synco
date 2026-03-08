/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-08 01:17
 * Last Updated: 2026-03-08 02:17
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

/**
 * time_watchdog_crc32
 *
 * Purpose
 * -------
 * Small macOS arm64 CLI tool that samples local Unix time from the commpage,
 * verifies remote time through an HTTPS response Date header, compares wall
 * elapsed time against monotonic elapsed time, and produces a CRC32 fingerprint
 * over the collected verification sample.
 *
 * High-level flow
 * ---------------
 * 1. Read local time from commpage immediately before the HTTPS request.
 * 2. Read monotonic time immediately before the HTTPS request.
 * 3. Perform an HTTPS GET request.
 * 4. Prefer a precise timestamp from a JSON response body when available,
 *    otherwise fall back to the HTTP Date header.
 * 5. Read local commpage time and monotonic time again after the response.
 * 6. Derive timing metrics and build a canonical payload.
 * 7. Compute CRC32 over that payload and emit both metrics and fingerprint.
 *
 * Main derived metrics
 * --------------------
 * - remote_midpoint_delta_ms:
 *     Difference between remote time and the midpoint of local before/after.
 * - wall_elapsed_ms:
 *     Elapsed time measured from commpage-backed wall clock snapshots.
 * - monotonic_elapsed_ms:
 *     Elapsed time from CLOCK_MONOTONIC_RAW.
 * - clock_gap_ms:
 *     Absolute difference between wall_elapsed and monotonic_elapsed.
 * - remote_time_source / remote_time_field:
 *     Which remote timestamp source was used and from which field.
 * - smart_crc32:
 *     CRC32 of the canonical verification sample for integrity-style tracking.
 *
 * Anomaly rules
 * -------------
 * anomaly_detected becomes 1 when any of these checks fail:
 * - HTTP status is outside 2xx/3xx
 * - |remote_midpoint_delta_ms| exceeds max_remote_delta_ms
 * - monotonic_elapsed_ms exceeds max_elapsed_ms
 * - clock_gap_ms exceeds max_clock_gap_ms
 *
 * Debug note
 * ----------
 * A forced LLDB pause of about 2 seconds inside the measured window was
 * verified to trigger anomaly_detected=1, with elapsed_exceeded being the
 * primary and most reliable stall signal.
 *
 * Usage
 * -----
 *   ./time_watchdog_crc32 <https_url>
 *   ./time_watchdog_crc32 <https_url> [max_remote_delta_ms] [max_elapsed_ms]
 *                         [max_clock_gap_ms]
 *
 * Example
 * -------
 *   ./time_watchdog_crc32 https://example.com 5000 5000 1500
 *
 * Exit codes
 * ----------
 * 0 = verification succeeded and thresholds were not exceeded
 * 1 = request/parsing/runtime error
 * 2 = verification succeeded but anomaly thresholds were exceeded
 */

#include <cstddef>
#include <cstdint>
#include <cmath>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <time.h>
#include <dispatch/dispatch.h>
#include <zlib.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
int main()
{
    static constexpr char kMessage[] =
        "time_watchdog_crc32 is supported only on macOS arm64\n";
    (void)!write(STDERR_FILENO, kMessage, sizeof(kMessage) - 1);
    return 1;
}
#else

namespace
{
constexpr uintptr_t kCommPageStart = 0x0000000FFFFFC000ULL;
constexpr uintptr_t kCommPageTimebaseOffset = kCommPageStart + 0x088;
constexpr uintptr_t kCommPageUserTimebase = kCommPageStart + 0x090;
constexpr uintptr_t kCommPageNewTimeOfDayData = kCommPageStart + 0x120;
constexpr int64_t kNsPerSecond = 1000000000LL;

enum : uint8_t
{
    kUserTimebaseCntvct = 1,
    kUserTimebaseCoreAnimation = 3,
};

struct TimeSnapshot
{
    uint64_t timestamp_tick;
    uint64_t timestamp_sec;
    uint64_t timestamp_frac;
    uint64_t ticks_scale;
    uint64_t ticks_per_sec;
};

struct ProbeError
{
    const char* message = nullptr;
    uint64_t value = 0;
    bool has_value = false;
};

struct FixedPoint64x64
{
    uint64_t whole = 0;
    uint64_t fraction = 0;
};

size_t StringLength(const char* text)
{
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    return length;
}

void WriteAll(int fd, const char* data, size_t length)
{
    while (length > 0)
    {
        const ssize_t written = write(fd, data, length);
        if (written <= 0)
            return;
        data += static_cast<size_t>(written);
        length -= static_cast<size_t>(written);
    }
}

void WriteText(int fd, const char* text) { WriteAll(fd, text, StringLength(text)); }

void WriteKeyValueText(const char* key, const char* value)
{
    char line[256];
    const int written = snprintf(line, sizeof(line), "%s%s\n", key, value);
    if (written > 0)
        WriteAll(STDOUT_FILENO, line, static_cast<size_t>(written));
}

void WriteKeyValueU64(const char* key, uint64_t value)
{
    char line[128];
    const int written = snprintf(line, sizeof(line), "%s%llu\n", key,
                                 static_cast<unsigned long long>(value));
    if (written > 0)
        WriteAll(STDOUT_FILENO, line, static_cast<size_t>(written));
}

void WriteKeyValueI64(const char* key, int64_t value)
{
    char line[128];
    const int written = snprintf(line, sizeof(line), "%s%lld\n", key,
                                 static_cast<long long>(value));
    if (written > 0)
        WriteAll(STDOUT_FILENO, line, static_cast<size_t>(written));
}

void WriteKeyValueHexU32(const char* key, uint32_t value)
{
    char line[128];
    const int written = snprintf(line, sizeof(line), "%s%08x\n", key, value);
    if (written > 0)
        WriteAll(STDOUT_FILENO, line, static_cast<size_t>(written));
}

FixedPoint64x64 MultiplyAddFixedPoint64x64(uint64_t scale, uint64_t delta, uint64_t base_fraction)
{
    uint64_t product_lo = 0;
    uint64_t product_hi = 0;
    asm volatile("mul %0, %2, %3\n\t"
                 "umulh %1, %2, %3"
                 : "=&r"(product_lo), "=&r"(product_hi)
                 : "r"(scale), "r"(delta));

    const uint64_t fraction = product_lo + base_fraction;
    const uint64_t carry = fraction < product_lo ? 1 : 0;
    return {.whole = product_hi + carry, .fraction = fraction};
}

inline uint64_t ReadCntvctEl0()
{
    uint64_t value = 0;
    asm volatile("mrs %0, CNTVCT_EL0" : "=r"(value));
    return value;
}

inline uint64_t ReadAltHardwareCounter()
{
    uint64_t value = 0;
    asm volatile("mrs %0, S3_4_C15_C10_6" : "=r"(value));
    return value;
}

uint64_t ReadRawCounter(uint8_t mode, ProbeError* error)
{
    switch (mode)
    {
        case kUserTimebaseCntvct:
            return ReadCntvctEl0();
        case kUserTimebaseCoreAnimation:
            return ReadAltHardwareCounter();
        default:
            if (error)
            {
                error->message = "unsupported userspace timebase mode";
                error->value = mode;
                error->has_value = true;
            }
            return 0;
    }
}

bool ReadAbsoluteTimeDirect(uint64_t* absolute_time, uint8_t* mode_out, ProbeError* error)
{
    const volatile uint64_t* timebase_offset =
        reinterpret_cast<const volatile uint64_t*>(kCommPageTimebaseOffset);
    const volatile uint8_t* user_timebase =
        reinterpret_cast<const volatile uint8_t*>(kCommPageUserTimebase);

    const uint8_t mode = *user_timebase;
    if (mode_out)
        *mode_out = mode;

    uint64_t offset_before = 0;
    uint64_t counter = 0;
    uint64_t offset_after = 0;

    do
    {
        offset_before = *timebase_offset;
        asm volatile("isb" ::: "memory");
        counter = ReadRawCounter(mode, error);
        if (counter == 0 && error && error->message)
            return false;
        offset_after = *timebase_offset;
    } while (offset_before != offset_after);

    *absolute_time = counter + offset_before;
    return true;
}

bool ReadUnixTimeFromCommpage(uint64_t* seconds, uint32_t* nanoseconds, uint8_t* mode_out,
                              ProbeError* error)
{
    const volatile TimeSnapshot* commpage_time =
        reinterpret_cast<const volatile TimeSnapshot*>(kCommPageNewTimeOfDayData);

    TimeSnapshot snapshot{};
    uint64_t now = 0;
    uint64_t generation_check = 0;

    do
    {
        snapshot.timestamp_tick = commpage_time->timestamp_tick;
        if (!ReadAbsoluteTimeDirect(&now, mode_out, error))
            return false;
        snapshot.timestamp_sec = commpage_time->timestamp_sec;
        snapshot.timestamp_frac = commpage_time->timestamp_frac;
        snapshot.ticks_scale = commpage_time->ticks_scale;
        snapshot.ticks_per_sec = commpage_time->ticks_per_sec;
        asm volatile("dmb ishld" ::: "memory");
        generation_check = commpage_time->timestamp_tick;
    } while (snapshot.timestamp_tick != generation_check);

    if (snapshot.timestamp_tick == 0)
    {
        if (error)
            error->message = "commpage timestamp is not initialized";
        return false;
    }

    const uint64_t delta = now - snapshot.timestamp_tick;
    if (delta >= snapshot.ticks_per_sec)
    {
        if (error)
            error->message = "commpage snapshot is too old; kernel fallback required";
        return false;
    }

    const FixedPoint64x64 scaled =
        MultiplyAddFixedPoint64x64(snapshot.ticks_scale, delta, snapshot.timestamp_frac);
    *seconds = snapshot.timestamp_sec + scaled.whole;
    *nanoseconds = static_cast<uint32_t>(((scaled.fraction >> 32) * 1000000000ULL) >> 32);
    return true;
}

bool ReadUnixTimeNsFromCommpage(int64_t* ns_out, uint8_t* mode_out, ProbeError* error)
{
    uint64_t seconds = 0;
    uint32_t nanoseconds = 0;
    if (!ReadUnixTimeFromCommpage(&seconds, &nanoseconds, mode_out, error))
        return false;
    *ns_out = static_cast<int64_t>(seconds) * kNsPerSecond + static_cast<int64_t>(nanoseconds);
    return true;
}

uint64_t ReadMonotonicNs(ProbeError* error)
{
    struct timespec ts {};
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
    {
        if (error)
            error->message = "clock_gettime(CLOCK_MONOTONIC_RAW) failed";
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

uint64_t AbsI64(int64_t value)
{
    return static_cast<uint64_t>(value < 0 ? -value : value);
}

struct VerificationResult
{
    uint8_t commpage_mode = 0;
    int64_t local_before_ns = 0;
    int64_t local_after_ns = 0;
    uint64_t monotonic_before_ns = 0;
    uint64_t monotonic_after_ns = 0;
    int64_t remote_time_ns = 0;
    uint64_t body_length = 0;
    int64_t status_code = 0;
    std::string resolved_url;
    std::string date_header;
    std::string remote_time_source = "http_date_header";
    std::string remote_time_field = "Date";
    uint64_t remote_time_precision_ms = 1000;
};

struct WatchdogEvaluation
{
    int64_t wall_elapsed_ns = 0;
    uint64_t monotonic_elapsed_ns = 0;
    uint64_t clock_gap_ns = 0;
    int64_t midpoint_local_ns = 0;
    int64_t remote_midpoint_delta_ns = 0;
    uint64_t effective_remote_threshold_ms = 0;
    std::string anomaly_reasons = "none";
    bool anomaly_detected = false;
};
} // namespace

#include <Foundation/Foundation.h>

@interface InsecureLocalhostSessionDelegate : NSObject <NSURLSessionDelegate>
@end

@implementation InsecureLocalhostSessionDelegate
- (void)URLSession:(NSURLSession*)session
        didReceiveChallenge:(NSURLAuthenticationChallenge*)challenge
          completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential* _Nullable credential))completionHandler
{
    (void)session;
    if ([[challenge.protectionSpace authenticationMethod]
            isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return;
    }

    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}
@end

namespace
{
bool ShouldAllowInsecureLocalhostForTesting(NSURL* url)
{
    const char* flag = getenv("TIME_WATCHDOG_ALLOW_INSECURE_LOCALHOST");
    if (!flag || flag[0] == '\0' || strcmp(flag, "0") == 0)
        return false;

    NSString* host = [[url host] lowercaseString];
    if (!host)
        return false;

    return [host isEqualToString:@"localhost"] || [host isEqualToString:@"127.0.0.1"] ||
           [host isEqualToString:@"::1"] || [host isEqualToString:@"[::1]"];
}

NSData* SendHttpsRequest(NSMutableURLRequest* request,
                         NSURLResponse** response_out,
                         NSError** error_out)
{
    if (!ShouldAllowInsecureLocalhostForTesting([request URL]))
    {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        return [NSURLConnection sendSynchronousRequest:request
                                     returningResponse:response_out
                                                 error:error_out];
#pragma clang diagnostic pop
    }

    __block NSData* response_data = nil;
    __block NSURLResponse* response = nil;
    __block NSError* request_error = nil;

    dispatch_semaphore_t wait_handle = dispatch_semaphore_create(0);
    InsecureLocalhostSessionDelegate* delegate = [[InsecureLocalhostSessionDelegate alloc] init];
    NSURLSessionConfiguration* config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    config.timeoutIntervalForRequest = request.timeoutInterval;
    config.timeoutIntervalForResource = request.timeoutInterval;
    NSURLSession* session = [NSURLSession sessionWithConfiguration:config
                                                          delegate:delegate
                                                     delegateQueue:nil];
    NSURLSessionDataTask* task = [session dataTaskWithRequest:request
                                            completionHandler:^(NSData* _Nullable data,
                                                                NSURLResponse* _Nullable response_obj,
                                                                NSError* _Nullable error_obj) {
                                                response_data = data ? [data retain] : nil;
                                                response = response_obj ? [response_obj retain] : nil;
                                                request_error = error_obj ? [error_obj retain] : nil;
                                                dispatch_semaphore_signal(wait_handle);
                                            }];
    [task resume];

    const int64_t timeout_ns = static_cast<int64_t>(request.timeoutInterval * static_cast<double>(NSEC_PER_SEC));
    const dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, timeout_ns);
    if (dispatch_semaphore_wait(wait_handle, deadline) != 0)
    {
        [task cancel];
        request_error = [[NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorTimedOut
                                         userInfo:nil] retain];
    }

    [session finishTasksAndInvalidate];
    if (response_out)
        *response_out = [response autorelease];
    else
        [response release];
    if (error_out)
        *error_out = [request_error autorelease];
    else
        [request_error release];
    return response_data ? [response_data autorelease] : nil;
}

double GetRequestTimeoutSeconds()
{
    const char* value = getenv("TIME_WATCHDOG_REQUEST_TIMEOUT_MS");
    if (!value || value[0] == '\0')
        return 10.0;

    char* end = nullptr;
    const long parsed_ms = strtol(value, &end, 10);
    if (!end || *end != '\0' || parsed_ms <= 0)
        return 10.0;

    return static_cast<double>(parsed_ms) / 1000.0;
}

NSString* GetHeaderValueCaseInsensitive(NSDictionary* headers, NSString* header_name)
{
    for (id key in headers)
    {
        NSString* key_string = [[key description] lowercaseString];
        if ([key_string isEqualToString:[header_name lowercaseString]])
            return [[headers objectForKey:key] description];
    }
    return nil;
}

bool ParseHttpDateHeader(NSString* header_value, int64_t* unix_ns_out, uint64_t* precision_ms_out)
{
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    formatter.dateFormat = @"EEE',' dd MMM yyyy HH':'mm':'ss z";

    NSDate* date = [formatter dateFromString:header_value];
    if (!date)
        return false;

    *unix_ns_out = static_cast<int64_t>([date timeIntervalSince1970] * 1000000000.0);
    if (precision_ms_out)
        *precision_ms_out = 1000;
    return true;
}

bool SetRemoteTimeFromInteger(uint64_t value, int64_t* unix_ns_out, uint64_t* precision_ms_out)
{
    if (value >= 1000000000000000000ULL)
    {
        *unix_ns_out = static_cast<int64_t>(value);
        *precision_ms_out = 1;
        return true;
    }

    if (value >= 1000000000000000ULL)
    {
        *unix_ns_out = static_cast<int64_t>(value * 1000ULL);
        *precision_ms_out = 1;
        return true;
    }

    if (value >= 1000000000000ULL)
    {
        *unix_ns_out = static_cast<int64_t>(value) * 1000000LL;
        *precision_ms_out = 1;
        return true;
    }

    if (value >= 1000000000ULL)
    {
        *unix_ns_out = static_cast<int64_t>(value) * 1000000000LL;
        *precision_ms_out = 1000;
        return true;
    }

    return false;
}

bool SetRemoteTimeFromDouble(double value,
                             bool fractional_hint,
                             int64_t* unix_ns_out,
                             uint64_t* precision_ms_out)
{
    if (!(value >= 1000000000.0))
        return false;

    if (value >= 1000000000000.0)
    {
        *unix_ns_out = static_cast<int64_t>(llround(value * 1000000.0));
        *precision_ms_out = 1;
        return true;
    }

    *unix_ns_out = static_cast<int64_t>(llround(value * 1000000000.0));
    *precision_ms_out = fractional_hint ? 1 : 1000;
    return true;
}

bool ParseISO8601TimestampString(NSString* value, int64_t* unix_ns_out, uint64_t* precision_ms_out)
{
    NSISO8601DateFormatter* formatter = [[NSISO8601DateFormatter alloc] init];
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                              NSISO8601DateFormatWithFractionalSeconds;

    NSDate* date = [formatter dateFromString:value];
    if (!date)
    {
        formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime;
        date = [formatter dateFromString:value];
    }
    if (!date)
        return false;

    *unix_ns_out = static_cast<int64_t>([date timeIntervalSince1970] * 1000000000.0);
    *precision_ms_out = [value rangeOfString:@"."].location != NSNotFound ? 1 : 1000;
    return true;
}

bool ParseTimestampValue(id value, int64_t* unix_ns_out, uint64_t* precision_ms_out)
{
    if ([value isKindOfClass:[NSNumber class]])
    {
        NSNumber* number_value = (NSNumber*)value;
        if (CFNumberIsFloatType((CFNumberRef)number_value))
        {
            const double double_value = [number_value doubleValue];
            const bool fractional_hint = floor(double_value) != double_value;
            return SetRemoteTimeFromDouble(double_value,
                                           fractional_hint,
                                           unix_ns_out,
                                           precision_ms_out);
        }

        return SetRemoteTimeFromInteger([number_value unsignedLongLongValue],
                                        unix_ns_out,
                                        precision_ms_out);
    }

    if (![value isKindOfClass:[NSString class]])
        return false;

    NSString* string_value = (NSString*)value;
    NSScanner* int_scanner = [NSScanner scannerWithString:string_value];
    unsigned long long int_value = 0;
    if ([int_scanner scanUnsignedLongLong:&int_value] && [int_scanner isAtEnd])
    {
        return SetRemoteTimeFromInteger(int_value, unix_ns_out, precision_ms_out);
    }

    NSScanner* double_scanner = [NSScanner scannerWithString:string_value];
    double double_value = 0;
    if ([double_scanner scanDouble:&double_value] && [double_scanner isAtEnd])
    {
        return SetRemoteTimeFromDouble(double_value,
                                       [string_value rangeOfString:@"."].location != NSNotFound,
                                       unix_ns_out,
                                       precision_ms_out);
    }

    return ParseISO8601TimestampString(string_value, unix_ns_out, precision_ms_out);
}

bool FindRemoteTimeInJsonObject(id json,
                                NSString* path,
                                int64_t* unix_ns_out,
                                uint64_t* precision_ms_out,
                                NSString** field_path_out)
{
    NSArray<NSString*>* candidate_keys = @[
        @"serverTime", @"server_time", @"server_time_ms", @"timestamp_ms", @"epoch_ms",
        @"unixtime_ms", @"time_ms", @"ts", @"timestamp", @"time", @"unixtime",
        @"datetime"
    ];

    if ([json isKindOfClass:[NSDictionary class]])
    {
        NSDictionary* dict = (NSDictionary*)json;

        for (NSString* key in candidate_keys)
        {
            id value = dict[key];
            if (value && ParseTimestampValue(value, unix_ns_out, precision_ms_out))
            {
                if (field_path_out)
                {
                    *field_path_out = path.length > 0 ? [path stringByAppendingFormat:@".%@", key] : key;
                }
                return true;
            }
        }

        for (id key in dict)
        {
            NSString* key_string = [[key description] copy];
            NSString* child_path = path.length > 0 ? [path stringByAppendingFormat:@".%@", key_string]
                                                  : key_string;
            if (FindRemoteTimeInJsonObject(dict[key], child_path, unix_ns_out, precision_ms_out,
                                           field_path_out))
            {
                return true;
            }
        }
    }
    else if ([json isKindOfClass:[NSArray class]])
    {
        NSArray* array = (NSArray*)json;
        for (NSUInteger index = 0; index < array.count; ++index)
        {
            NSString* child_path = [NSString stringWithFormat:@"%@[%lu]",
                                                           path.length > 0 ? path : @"$",
                                                           (unsigned long)index];
            if (FindRemoteTimeInJsonObject(array[index], child_path, unix_ns_out, precision_ms_out,
                                           field_path_out))
            {
                return true;
            }
        }
    }

    return false;
}

bool TryParseRemoteTimeFromJsonBody(NSData* response_data,
                                    int64_t* unix_ns_out,
                                    uint64_t* precision_ms_out,
                                    NSString** field_path_out)
{
    if (!response_data || response_data.length == 0)
        return false;

    NSError* json_error = nil;
    id json = [NSJSONSerialization JSONObjectWithData:response_data options:0 error:&json_error];
    if (json_error || !json)
        return false;

    return FindRemoteTimeInJsonObject(json, @"", unix_ns_out, precision_ms_out, field_path_out);
}

bool FetchHttpsVerification(const char* url_cstr, VerificationResult* result, char* error_buffer,
                           size_t error_buffer_size)
{
    @autoreleasepool
    {
        NSString* url_string = [NSString stringWithUTF8String:url_cstr];
        NSURL* url = [NSURL URLWithString:url_string];
        if (!url || ![[[url scheme] lowercaseString] isEqualToString:@"https"])
        {
            snprintf(error_buffer, error_buffer_size, "Verification URL must use https://");
            return false;
        }

        ProbeError error{};
        if (!ReadUnixTimeNsFromCommpage(&result->local_before_ns, &result->commpage_mode, &error))
        {
            snprintf(error_buffer, error_buffer_size, "%s", error.message ? error.message : "commpage read failed");
            return false;
        }

        result->monotonic_before_ns = ReadMonotonicNs(&error);
        if (result->monotonic_before_ns == 0 && error.message)
        {
            snprintf(error_buffer, error_buffer_size, "%s", error.message);
            return false;
        }

        NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:url];
        request.HTTPMethod = @"GET";
        request.timeoutInterval = GetRequestTimeoutSeconds();
        request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        [request setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];

        NSURLResponse* response = nil;
        NSError* session_error = nil;
        NSData* response_data = SendHttpsRequest(request, &response, &session_error);

        result->monotonic_after_ns = ReadMonotonicNs(&error);
        if (result->monotonic_after_ns == 0 && error.message)
        {
            snprintf(error_buffer, error_buffer_size, "%s", error.message);
            return false;
        }

        uint8_t mode_after = 0;
        if (!ReadUnixTimeNsFromCommpage(&result->local_after_ns, &mode_after, &error))
        {
            snprintf(error_buffer, error_buffer_size, "%s", error.message ? error.message : "commpage read failed");
            return false;
        }

        if (session_error)
        {
            snprintf(error_buffer, error_buffer_size, "%s", [[session_error localizedDescription] UTF8String]);
            return false;
        }

        if (![response isKindOfClass:[NSHTTPURLResponse class]])
        {
            snprintf(error_buffer, error_buffer_size, "HTTPS verification returned a non-HTTP response");
            return false;
        }

        NSHTTPURLResponse* http_response = (NSHTTPURLResponse*)response;
        result->status_code = http_response.statusCode;
        result->body_length = response_data ? static_cast<uint64_t>(response_data.length) : 0;

        const char* resolved = [[[http_response URL] absoluteString] UTF8String];
        result->resolved_url = resolved ? resolved : "";

        NSString* remote_field_path = nil;
        if (TryParseRemoteTimeFromJsonBody(response_data,
                                          &result->remote_time_ns,
                                          &result->remote_time_precision_ms,
                                          &remote_field_path))
        {
            result->remote_time_source = "json_body_timestamp";
            const char* field_cstr = [remote_field_path UTF8String];
            result->remote_time_field = field_cstr ? field_cstr : "json";
            return true;
        }

        NSString* date_header = GetHeaderValueCaseInsensitive([http_response allHeaderFields], @"Date");
        if (!date_header)
        {
            snprintf(error_buffer, error_buffer_size, "HTTPS response did not include a Date header");
            return false;
        }

        const char* date_cstr = [date_header UTF8String];
        result->date_header = date_cstr ? date_cstr : "";
        result->remote_time_source = "http_date_header";
        result->remote_time_field = "Date";

        if (!ParseHttpDateHeader(date_header, &result->remote_time_ns,
                                 &result->remote_time_precision_ms))
        {
            snprintf(error_buffer, error_buffer_size, "Could not parse HTTPS Date header");
            return false;
        }

        return true;
    }
}

uint32_t ComputeSmartCRC32(const std::string& payload)
{
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, reinterpret_cast<const Bytef*>(payload.data()), static_cast<uInt>(payload.size()));
    return static_cast<uint32_t>(crc);
}

int64_t ParseI64Arg(const char* text, int64_t fallback)
{
    if (!text || text[0] == '\0')
        return fallback;
    char* end = nullptr;
    const long long parsed = strtoll(text, &end, 10);
    if (!end || *end != '\0')
        return fallback;
    return static_cast<int64_t>(parsed);
}

WatchdogEvaluation EvaluateVerificationResult(const VerificationResult& result,
                                             int64_t max_remote_delta_ms,
                                             int64_t max_elapsed_ms,
                                             int64_t max_clock_gap_ms)
{
    WatchdogEvaluation evaluation{};
    const uint64_t safe_elapsed_threshold_ms =
        static_cast<uint64_t>(max_elapsed_ms > 0 ? max_elapsed_ms : 0);
    const uint64_t safe_clock_gap_threshold_ms =
        static_cast<uint64_t>(max_clock_gap_ms > 0 ? max_clock_gap_ms : 0);
    evaluation.wall_elapsed_ns = result.local_after_ns - result.local_before_ns;
    evaluation.monotonic_elapsed_ns = result.monotonic_after_ns - result.monotonic_before_ns;
    evaluation.clock_gap_ns =
        AbsI64(evaluation.wall_elapsed_ns - static_cast<int64_t>(evaluation.monotonic_elapsed_ns));
    evaluation.midpoint_local_ns = result.local_before_ns + (evaluation.wall_elapsed_ns / 2);
    evaluation.remote_midpoint_delta_ns = result.remote_time_ns - evaluation.midpoint_local_ns;
    evaluation.effective_remote_threshold_ms =
        static_cast<uint64_t>(max_remote_delta_ms > 0 ? max_remote_delta_ms : 0) +
        result.remote_time_precision_ms;

    auto append_reason = [&](const char* reason) {
        if (evaluation.anomaly_reasons == "none")
            evaluation.anomaly_reasons.clear();
        else if (!evaluation.anomaly_reasons.empty())
            evaluation.anomaly_reasons += ",";
        evaluation.anomaly_reasons += reason;
    };

    if (result.status_code < 200 || result.status_code >= 400)
        append_reason("http_status_out_of_range");
    if (AbsI64(evaluation.remote_midpoint_delta_ns) >
        evaluation.effective_remote_threshold_ms * 1000000ULL)
        append_reason("remote_delta_exceeded");
    if (evaluation.monotonic_elapsed_ns > safe_elapsed_threshold_ms * 1000000ULL)
        append_reason("elapsed_exceeded");
    if (evaluation.clock_gap_ns > safe_clock_gap_threshold_ms * 1000000ULL)
        append_reason("clock_gap_exceeded");

    evaluation.anomaly_detected = evaluation.anomaly_reasons != "none";
    if (!evaluation.anomaly_detected)
        evaluation.anomaly_reasons = "none";

    return evaluation;
}
} // namespace

#if !defined(TIME_WATCHDOG_CRC32_TESTING)
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        WriteText(STDOUT_FILENO,
                  "Usage: time_watchdog_crc32 <https_url> [max_remote_delta_ms] [max_elapsed_ms] [max_clock_gap_ms]\n");
        return 0;
    }

    const char* verification_url = argv[1];
    const int64_t max_remote_delta_ms = ParseI64Arg(argc > 2 ? argv[2] : nullptr, 5000);
    const int64_t max_elapsed_ms = ParseI64Arg(argc > 3 ? argv[3] : nullptr, 5000);
    const int64_t max_clock_gap_ms = ParseI64Arg(argc > 4 ? argv[4] : nullptr, 1500);

    VerificationResult result{};
    char error_buffer[512] = {0};
    if (!FetchHttpsVerification(verification_url, &result, error_buffer, sizeof(error_buffer)))
    {
        WriteText(STDERR_FILENO, "HTTPS verification error: ");
        WriteText(STDERR_FILENO, error_buffer);
        WriteText(STDERR_FILENO, "\n");
        return 1;
    }

    const WatchdogEvaluation evaluation =
        EvaluateVerificationResult(result, max_remote_delta_ms, max_elapsed_ms, max_clock_gap_ms);
    const char* anomaly_text = evaluation.anomaly_detected ? "1" : "0";

    const std::string canonical_payload =
        std::string("v2\n") + "verification_url=" + verification_url + "\n" +
        "resolved_url=" + result.resolved_url + "\n" +
        "status_code=" + std::to_string(result.status_code) + "\n" +
        "remote_time_source=" + result.remote_time_source + "\n" +
        "remote_time_field=" + result.remote_time_field + "\n" +
        "remote_time_precision_ms=" + std::to_string(result.remote_time_precision_ms) + "\n" +
        "effective_remote_threshold_ms=" + std::to_string(evaluation.effective_remote_threshold_ms) + "\n" +
        "date_header=" + result.date_header + "\n" +
        "local_before_ns=" + std::to_string(result.local_before_ns) + "\n" +
        "local_after_ns=" + std::to_string(result.local_after_ns) + "\n" +
        "remote_time_ns=" + std::to_string(result.remote_time_ns) + "\n" +
        "wall_elapsed_ns=" + std::to_string(evaluation.wall_elapsed_ns) + "\n" +
        "monotonic_elapsed_ns=" + std::to_string(evaluation.monotonic_elapsed_ns) + "\n" +
        "clock_gap_ns=" + std::to_string(evaluation.clock_gap_ns) + "\n" +
        "remote_midpoint_delta_ns=" + std::to_string(evaluation.remote_midpoint_delta_ns) + "\n" +
        "body_length=" + std::to_string(result.body_length) + "\n" +
        "anomaly_detected=" + anomaly_text + "\n" +
        "anomaly_reasons=" + evaluation.anomaly_reasons + "\n";
    const uint32_t smart_crc32 = ComputeSmartCRC32(canonical_payload);

    WriteKeyValueText("time_source=", "commpage_https_watchdog");
    WriteKeyValueU64("user_timebase_mode=", result.commpage_mode);
    WriteKeyValueText("verification_url=", verification_url);
    WriteKeyValueText("resolved_url=", result.resolved_url.c_str());
    WriteKeyValueI64("http_status_code=", result.status_code);
    WriteKeyValueText("remote_time_source=", result.remote_time_source.c_str());
    WriteKeyValueText("remote_time_field=", result.remote_time_field.c_str());
    WriteKeyValueU64("remote_time_precision_ms=", result.remote_time_precision_ms);
    WriteKeyValueText("http_date_header=", result.date_header.c_str());
    WriteKeyValueI64("local_before_ns=", result.local_before_ns);
    WriteKeyValueI64("local_after_ns=", result.local_after_ns);
    WriteKeyValueI64("remote_time_ns=", result.remote_time_ns);
    WriteKeyValueI64("remote_midpoint_delta_ms=", evaluation.remote_midpoint_delta_ns / 1000000LL);
    WriteKeyValueI64("wall_elapsed_ms=", evaluation.wall_elapsed_ns / 1000000LL);
    WriteKeyValueU64("monotonic_elapsed_ms=", evaluation.monotonic_elapsed_ns / 1000000ULL);
    WriteKeyValueU64("clock_gap_ms=", evaluation.clock_gap_ns / 1000000ULL);
    WriteKeyValueU64("response_body_bytes=", result.body_length);
    WriteKeyValueI64("threshold_remote_delta_ms=", max_remote_delta_ms);
    WriteKeyValueU64("effective_remote_threshold_ms=", evaluation.effective_remote_threshold_ms);
    WriteKeyValueI64("threshold_elapsed_ms=", max_elapsed_ms);
    WriteKeyValueI64("threshold_clock_gap_ms=", max_clock_gap_ms);
    WriteKeyValueText("anomaly_detected=", anomaly_text);
    WriteKeyValueText("anomaly_reasons=", evaluation.anomaly_reasons.c_str());
    WriteKeyValueHexU32("smart_crc32=", smart_crc32);
    WriteKeyValueU64("smart_crc32_u32=", smart_crc32);

    return evaluation.anomaly_detected ? 2 : 0;
}
#endif

#endif