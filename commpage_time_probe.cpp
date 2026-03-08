/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-07 20:03
 * Last Updated: 2026-03-08 00:40
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <zlib.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
int main()
{
    static constexpr char kMessage[] = "commpage_time_probe is supported only on macOS arm64\n";
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

enum : uint8_t
{
    kUserTimebaseKernel = 0,
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

void WriteText(int fd, const char* text)
{
    WriteAll(fd, text, StringLength(text));
}

void AppendChar(char* buffer, size_t capacity, size_t* used, char ch)
{
    if (*used < capacity)
        buffer[*used] = ch;
    ++(*used);
}

void AppendText(char* buffer, size_t capacity, size_t* used, const char* text)
{
    for (size_t i = 0; text[i] != '\0'; ++i)
        AppendChar(buffer, capacity, used, text[i]);
}

void AppendU64(char* buffer, size_t capacity, size_t* used, uint64_t value)
{
    char digits[32];
    size_t count = 0;

    do
    {
        digits[count++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    } while (value != 0);

    while (count > 0)
        AppendChar(buffer, capacity, used, digits[--count]);
}

void AppendI64(char* buffer, size_t capacity, size_t* used, int64_t value)
{
    if (value < 0)
    {
        AppendChar(buffer, capacity, used, '-');
        value = -value;
    }
    AppendU64(buffer, capacity, used, static_cast<uint64_t>(value));
}

void WriteKeyValueU64(const char* key, uint64_t value)
{
    char line[96];
    size_t used = 0;
    AppendText(line, sizeof(line), &used, key);
    AppendU64(line, sizeof(line), &used, value);
    AppendChar(line, sizeof(line), &used, '\n');
    WriteAll(STDOUT_FILENO, line, used < sizeof(line) ? used : sizeof(line));
}

void WriteKeyValueText(const char* key, const char* value)
{
    char line[96];
    size_t used = 0;
    AppendText(line, sizeof(line), &used, key);
    AppendText(line, sizeof(line), &used, value);
    AppendChar(line, sizeof(line), &used, '\n');
    WriteAll(STDOUT_FILENO, line, used < sizeof(line) ? used : sizeof(line));
}

void WriteFailure(const ProbeError& error)
{
    WriteText(STDERR_FILENO, "commpage_time_probe failed: ");
    if (error.message)
        WriteText(STDERR_FILENO, error.message);
    if (error.has_value)
    {
        WriteText(STDERR_FILENO, ": ");
        char digits[32];
        size_t used = 0;
        AppendU64(digits, sizeof(digits), &used, error.value);
        WriteAll(STDERR_FILENO, digits, used < sizeof(digits) ? used : sizeof(digits));
    }
    WriteText(STDERR_FILENO, "\n");
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
} // namespace

#endif // defined(__APPLE__) && defined(__aarch64__)

#if defined(__APPLE__) && defined(__aarch64__)

#include <Foundation/Foundation.h>

// WebSocket client using Foundation
namespace WebSocketClient
{

struct ServerTime
{
    uint64_t seconds = 0;
    uint64_t nanoseconds = 0;
};

} // namespace WebSocketClient

// Objective-C class must be at file scope, not in C++ namespace
@interface WSDelegate : NSObject <NSURLSessionDelegate, NSURLSessionWebSocketDelegate>
@property (nonatomic, assign) BOOL received;
@property (nonatomic, strong) NSData* receivedData;
@property (nonatomic, strong) NSCondition* condition;
@property (nonatomic, assign) WebSocketClient::ServerTime serverTime;
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy) NSString* errorMessage;
@end

@implementation WSDelegate
- (instancetype)init
{
    if (self = [super init])
    {
        _received = NO;
        _success = NO;
        _condition = [[NSCondition alloc] init];
        _serverTime = WebSocketClient::ServerTime{};
    }
    return self;
}

- (void)URLSession:(NSURLSession*)session
          webSocketTask:(NSURLSessionWebSocketTask*)webSocketTask
    didOpenWithProtocol:(NSString*)protocol
{
    (void)session;
    (void)webSocketTask;
    (void)protocol;
    // Connection opened, send a message to request time
    NSURLSessionWebSocketMessage* message =
        [[NSURLSessionWebSocketMessage alloc] initWithString:@"{\"type\":\"time_request\"}"];
    [webSocketTask sendMessage:message
            completionHandler:^(NSError* error) {
                if (error)
                {
                    [_condition lock];
                    _success = NO;
                    _errorMessage = [error localizedDescription];
                    _received = YES;
                    [_condition signal];
                    [_condition unlock];
                }
            }];
}

- (void)URLSession:(NSURLSession*)session
          webSocketTask:(NSURLSessionWebSocketTask*)webSocketTask
    didCloseWithCode:(NSURLSessionWebSocketCloseCode)closeCode
              reason:(NSData*)reason
{
    (void)session;
    (void)webSocketTask;
    (void)closeCode;
    (void)reason;
    [_condition lock];
    _received = YES;
    [_condition signal];
    [_condition unlock];
}

- (void)URLSession:(NSURLSession*)session
                    task:(NSURLSessionTask*)task
    didCompleteWithError:(NSError*)error
{
    (void)session;
    (void)task;
    if (error)
    {
        [_condition lock];
        _success = NO;
        _errorMessage = [error localizedDescription];
        [_condition signal];
        [_condition unlock];
    }
}

- (void)URLSession:(NSURLSession*)session
          webSocketTask:(NSURLSessionWebSocketTask*)webSocketTask
    didReceiveMessage:(NSURLSessionWebSocketMessage*)message
{
    (void)session;
    (void)webSocketTask;
    [_condition lock];
    if (message.type == NSURLSessionWebSocketMessageTypeString)
    {
        _receivedData = [message.string dataUsingEncoding:NSUTF8StringEncoding];
    }
    else
    {
        _receivedData = message.data;
    }

    // Parse JSON response
    NSError* jsonError = nil;
    id json = [NSJSONSerialization JSONObjectWithData:_receivedData
                                              options:0
                                                error:&jsonError];
    if (!jsonError && [json isKindOfClass:[NSDictionary class]])
    {
        NSDictionary* dict = (NSDictionary*)json;
        id seconds = dict[@"seconds"];
        id nanoseconds = dict[@"nanoseconds"];

        if (seconds && [seconds isKindOfClass:[NSNumber class]])
        {
            _serverTime.seconds = [seconds unsignedLongLongValue];
            _serverTime.nanoseconds =
                (nanoseconds && [nanoseconds isKindOfClass:[NSNumber class]])
                    ? [nanoseconds unsignedLongLongValue]
                    : 0;
            _success = YES;
        }
        else
        {
            _success = NO;
            _errorMessage = @"Missing 'seconds' field in server response";
        }
    }
    else
    {
        _success = NO;
        _errorMessage = @"Invalid JSON response from server";
    }

    _received = YES;
    [_condition signal];
    [_condition unlock];
}
@end

namespace WebSocketClient
{

bool SetServerTimeFromMilliseconds(uint64_t timestamp_ms, ServerTime* server_time)
{
    server_time->seconds = timestamp_ms / 1000ULL;
    server_time->nanoseconds = (timestamp_ms % 1000ULL) * 1000000ULL;
    return true;
}

bool SetServerTimeFromMicroseconds(uint64_t timestamp_us, ServerTime* server_time)
{
    server_time->seconds = timestamp_us / 1000000ULL;
    server_time->nanoseconds = (timestamp_us % 1000000ULL) * 1000ULL;
    return true;
}

bool SetServerTimeFromNanoseconds(uint64_t timestamp_ns, ServerTime* server_time)
{
    server_time->seconds = timestamp_ns / 1000000000ULL;
    server_time->nanoseconds = timestamp_ns % 1000000000ULL;
    return true;
}

bool SetServerTimeFromMillisecondsDouble(double timestamp_ms, ServerTime* server_time)
{
    if (timestamp_ms <= 0)
        return false;

    uint64_t whole_ms = static_cast<uint64_t>(timestamp_ms);
    server_time->seconds = whole_ms / 1000ULL;
    server_time->nanoseconds = (whole_ms % 1000ULL) * 1000000ULL;
    server_time->nanoseconds +=
        static_cast<uint64_t>((timestamp_ms - whole_ms) * 1000000.0);

    if (server_time->nanoseconds >= 1000000000ULL)
    {
        server_time->seconds += server_time->nanoseconds / 1000000000ULL;
        server_time->nanoseconds %= 1000000000ULL;
    }

    return true;
}

bool SetServerTimeFromSeconds(double timestamp_seconds, ServerTime* server_time)
{
    if (timestamp_seconds <= 0)
        return false;

    server_time->seconds = static_cast<uint64_t>(timestamp_seconds);
    server_time->nanoseconds =
        static_cast<uint64_t>((timestamp_seconds - server_time->seconds) * 1e9);
    return true;
}

bool TryParseISO8601String(NSString* time_string, ServerTime* server_time)
{
    NSISO8601DateFormatter* formatter = [[NSISO8601DateFormatter alloc] init];
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                              NSISO8601DateFormatWithFractionalSeconds;

    NSDate* date = [formatter dateFromString:time_string];
    if (!date)
    {
        formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime;
        date = [formatter dateFromString:time_string];
    }

    if (!date)
        return false;

    NSTimeInterval timestamp_seconds = [date timeIntervalSince1970];
    return SetServerTimeFromSeconds(timestamp_seconds, server_time);
}

bool TrySetServerTimeFromValue(id value, NSString* field, ServerTime* server_time)
{
    if (!value)
        return false;

    auto try_set_integer_value = ^bool(uint64_t timestamp_value) {
        if ([field isEqualToString:@"microtimestamp"])
            return SetServerTimeFromMicroseconds(timestamp_value, server_time);

        if ([field isEqualToString:@"seconds"])
        {
            server_time->seconds = timestamp_value;
            server_time->nanoseconds = 0;
            return true;
        }

        if (timestamp_value >= 1000000000000000000ULL)
            return SetServerTimeFromNanoseconds(timestamp_value, server_time);

        if ([field hasSuffix:@"_us"] || timestamp_value >= 100000000000000ULL)
            return SetServerTimeFromMicroseconds(timestamp_value, server_time);

        if ([field hasSuffix:@"_ms"] || timestamp_value >= 100000000000ULL)
            return SetServerTimeFromMilliseconds(timestamp_value, server_time);

        if (timestamp_value >= 1000000000ULL)
        {
            server_time->seconds = timestamp_value;
            server_time->nanoseconds = 0;
            return true;
        }

        return false;
    };

    if ([value isKindOfClass:[NSNumber class]])
    {
        return try_set_integer_value([value unsignedLongLongValue]);
    }

    if (![value isKindOfClass:[NSString class]])
        return false;

    NSString* time_string = (NSString*)value;
    NSScanner* integer_scanner = [NSScanner scannerWithString:time_string];
    unsigned long long integer_value = 0;
    if ([integer_scanner scanUnsignedLongLong:&integer_value] && [integer_scanner isAtEnd])
    {
        return try_set_integer_value(integer_value);
    }

    NSScanner* double_scanner = [NSScanner scannerWithString:time_string];
    double decimal_value = 0;
    if ([double_scanner scanDouble:&decimal_value] && [double_scanner isAtEnd] &&
        decimal_value > 1000000000.0)
    {
        if ([field hasSuffix:@"_ms"] || decimal_value >= 100000000000.0)
            return SetServerTimeFromMillisecondsDouble(decimal_value, server_time);

        return SetServerTimeFromSeconds(decimal_value, server_time);
    }

    return TryParseISO8601String(time_string, server_time);
}

NSDictionary* ExtractPayloadDictionary(NSDictionary* dict)
{
    id result_field = dict[@"result"];
    if ([result_field isKindOfClass:[NSDictionary class]])
    {
        return ExtractPayloadDictionary((NSDictionary*)result_field);
    }

    id tick_field = dict[@"tick"];
    if ([tick_field isKindOfClass:[NSDictionary class]])
    {
        return ExtractPayloadDictionary((NSDictionary*)tick_field);
    }

    id data_field = dict[@"data"];
    if ([data_field isKindOfClass:[NSDictionary class]])
    {
        return ExtractPayloadDictionary((NSDictionary*)data_field);
    }

    if ([data_field isKindOfClass:[NSArray class]])
    {
        NSArray* data_array = (NSArray*)data_field;
        if (data_array.count > 0 && [data_array[0] isKindOfClass:[NSDictionary class]])
            return ExtractPayloadDictionary((NSDictionary*)data_array[0]);
    }

    return dict;
}

NSData* InflateGzipData(NSData* data)
{
    if (!data || data.length < 2)
        return data;

    const uint8_t* bytes = (const uint8_t*)data.bytes;
    if (bytes[0] != 0x1f || bytes[1] != 0x8b)
        return data;

    z_stream stream{};
    stream.next_in = (Bytef*)data.bytes;
    stream.avail_in = (uInt)data.length;

    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK)
        return data;

    NSMutableData* output = [NSMutableData dataWithLength:(data.length * 2) + 1024];
    int status = Z_OK;

    while (status == Z_OK)
    {
        if (stream.total_out >= output.length)
        {
            [output increaseLengthBy:data.length + 1024];
        }

        stream.next_out = (Bytef*)output.mutableBytes + stream.total_out;
        stream.avail_out = (uInt)(output.length - stream.total_out);
        status = inflate(&stream, Z_SYNC_FLUSH);
    }

    inflateEnd(&stream);

    if (status != Z_STREAM_END)
        return data;

    [output setLength:stream.total_out];
    return output;
}

NSData* DataFromWebSocketMessage(NSURLSessionWebSocketMessage* message)
{
    if (message.type == NSURLSessionWebSocketMessageTypeString)
    {
        return [message.string dataUsingEncoding:NSUTF8StringEncoding];
    }

    return InflateGzipData(message.data);
}

bool TrySetServerTimeFromTradeArray(NSArray* trade, NSUInteger timestampIndex, ServerTime* server_time)
{
    if (trade.count <= timestampIndex)
        return false;

    return TrySetServerTimeFromValue(trade[timestampIndex], @"time", server_time);
}

bool TrySetServerTimeFromExchangeArray(NSArray* arr, ServerTime* server_time)
{
    if (arr.count < 2)
        return false;

    id second = arr[1];

    // Bitfinex snapshot: [chanId, [[id, mts, amount, price], ...]]
    if ([second isKindOfClass:[NSArray class]])
    {
        NSArray* second_array = (NSArray*)second;
        if (second_array.count > 0 && [second_array[0] isKindOfClass:[NSArray class]])
        {
            return TrySetServerTimeFromTradeArray((NSArray*)second_array[0], 1, server_time);
        }
    }

    // Bitfinex trade update: [chanId, "te"|"tu", [id, mts, amount, price]]
    if ([second isKindOfClass:[NSString class]] && arr.count > 2)
    {
        NSString* event = (NSString*)second;
        if (([event isEqualToString:@"te"] || [event isEqualToString:@"tu"]) &&
            [arr[2] isKindOfClass:[NSArray class]])
        {
            return TrySetServerTimeFromTradeArray((NSArray*)arr[2], 1, server_time);
        }
    }

    return false;
}

bool GetServerTime(const char* ws_url,
                   const char* request_message,
                   ServerTime* server_time,
                   char* error_buffer,
                   size_t error_size)
{
    @autoreleasepool
    {
        NSString* urlStr = [NSString stringWithUTF8String:ws_url];
        NSString* customRequest = nil;
        NSURL* url = [NSURL URLWithString:urlStr];
        if (!url)
        {
            snprintf(error_buffer, error_size, "Invalid WebSocket URL: %s", ws_url);
            return false;
        }

        if (request_message && request_message[0] != '\0')
        {
            customRequest = [NSString stringWithUTF8String:request_message];
        }

        __block bool completed = false;
        __block bool success = false;
        __block ServerTime result_time{};
        __block NSString* error_message = nil;

        // Use completion-based API instead of delegate
        NSURLSession* session = [NSURLSession sharedSession];
        NSString* urlPath = [url absoluteString];
        NSURLSessionWebSocketTask* task = nil;

        if ([urlPath rangeOfString:@"kucoin.com/api/v1/bullet-public"].location != NSNotFound)
        {
            NSURL* token_url = url;
            NSMutableURLRequest* token_request = [NSMutableURLRequest requestWithURL:token_url];
            token_request.HTTPMethod = @"POST";
            token_request.timeoutInterval = 10.0;

            dispatch_semaphore_t token_wait = dispatch_semaphore_create(0);
            __block NSData* token_data = nil;
            __block NSError* token_error = nil;

            NSURLSessionDataTask* token_task =
                [session dataTaskWithRequest:token_request
                           completionHandler:^(NSData* _Nullable data,
                                               NSURLResponse* _Nullable response,
                                               NSError* _Nullable error) {
                               (void)response;
                               token_data = data;
                               token_error = error;
                               dispatch_semaphore_signal(token_wait);
                           }];
            [token_task resume];

            dispatch_time_t token_deadline =
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC));
            if (dispatch_semaphore_wait(token_wait, token_deadline) != 0)
            {
                snprintf(error_buffer, error_size, "KuCoin token request timeout");
                return false;
            }

            if (token_error || !token_data)
            {
                snprintf(error_buffer,
                         error_size,
                         "KuCoin token request failed: %s",
                         token_error ? [[token_error localizedDescription] UTF8String]
                                     : "No response");
                return false;
            }

            NSError* token_json_error = nil;
            id token_json = [NSJSONSerialization JSONObjectWithData:token_data
                                                            options:0
                                                              error:&token_json_error];
            if (token_json_error || ![token_json isKindOfClass:[NSDictionary class]])
            {
                snprintf(error_buffer, error_size, "Invalid KuCoin token response");
                return false;
            }

            NSDictionary* token_dict = (NSDictionary*)token_json;
            NSDictionary* token_payload = token_dict[@"data"];
            NSArray* instance_servers = token_payload[@"instanceServers"];
            NSString* token = token_payload[@"token"];
            if (![token isKindOfClass:[NSString class]] || instance_servers.count == 0 ||
                ![instance_servers[0] isKindOfClass:[NSDictionary class]])
            {
                snprintf(error_buffer, error_size, "Incomplete KuCoin token response");
                return false;
            }

            NSString* endpoint = ((NSDictionary*)instance_servers[0])[@"endpoint"];
            NSString* ws_connect_url = [NSString stringWithFormat:@"%@?token=%@", endpoint, token];
            NSURL* kucoin_ws_url = [NSURL URLWithString:ws_connect_url];
            if (!kucoin_ws_url)
            {
                snprintf(error_buffer, error_size, "Invalid KuCoin websocket endpoint");
                return false;
            }

            task = [session webSocketTaskWithURL:kucoin_ws_url];
        }
        else
        {
            task = [session webSocketTaskWithURL:url];
        }

        [task resume];

        // Check if URL contains @ (stream endpoint that doesn't need request)
        bool is_stream_endpoint = [urlPath rangeOfString:@"@"].location != NSNotFound;

        // For stream endpoints, just receive. For others, send request first.
        if (is_stream_endpoint)
        {
            // Just receive the first message from the stream
            [task receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage* _Nullable message,
                                                         NSError* _Nullable error) {
                if (error)
                {
                    error_message = [error localizedDescription];
                    completed = true;
                    return;
                }

                if (!message)
                {
                    error_message = @"No message received";
                    completed = true;
                    return;
                }

                NSData* data = DataFromWebSocketMessage(message);

                NSError* jsonError = nil;
                id json = [NSJSONSerialization JSONObjectWithData:data
                                                          options:0
                                                            error:&jsonError];

                NSDictionary* dict = nil;
                if ([json isKindOfClass:[NSDictionary class]])
                {
                    dict = (NSDictionary*)json;
                }
                else if ([json isKindOfClass:[NSArray class]])
                {
                    NSArray* arr = (NSArray*)json;
                    if (TrySetServerTimeFromExchangeArray(arr, &result_time))
                    {
                        success = true;
                        completed = true;
                        return;
                    }

                    if (arr.count > 0 && [arr[0] isKindOfClass:[NSDictionary class]])
                    {
                        dict = (NSDictionary*)arr[0];
                    }
                }

                if (jsonError || !dict)
                {
                    error_message = @"Invalid JSON response from server";
                    completed = true;
                    return;
                }

                NSDictionary* payload_dict = ExtractPayloadDictionary(dict);
                id seconds = payload_dict[@"seconds"];
                id nanoseconds = payload_dict[@"nanoseconds"];
                NSArray* timestampFields = @[@"E", @"T", @"ts", @"time", @"time_ms", @"create_time", @"create_time_ms", @"microtimestamp", @"t", @"timestamp", @"TimeStamp", @"seconds"];

                for (NSString* field in timestampFields)
                {
                    if (TrySetServerTimeFromValue(payload_dict[field], field, &result_time) ||
                        (payload_dict != dict && TrySetServerTimeFromValue(dict[field], field, &result_time)))
                    {
                        success = true;
                        completed = true;
                        return;
                    }
                }

                if (!seconds || ![seconds isKindOfClass:[NSNumber class]])
                {
                    // Debug: print received JSON for troubleshooting
                    NSString* jsonStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                    fprintf(stderr, "Received JSON: %s\n", [jsonStr UTF8String]);
                    error_message = @"Missing timestamp field in server response";
                    completed = true;
                    return;
                }

                result_time.seconds = [seconds unsignedLongLongValue];
                result_time.nanoseconds =
                    (nanoseconds && [nanoseconds isKindOfClass:[NSNumber class]])
                        ? [nanoseconds unsignedLongLongValue]
                        : 0;

                success = true;
                completed = true;
            }];
        }
        else
        {
            // Non-stream endpoint - try to detect exchange and send appropriate subscription
            NSString* request_json = @"{\"type\":\"time_request\"}";

            if (customRequest)
            {
                request_json = customRequest;
            }
            else if ([urlPath rangeOfString:@"kraken.com/v2"].location != NSNotFound)
            {
                request_json = @"{\"method\":\"subscribe\",\"params\":{\"channel\":\"ticker\",\"symbol\":[\"BTC/USD\"]}}";
            }
            else if ([urlPath rangeOfString:@"kraken.com"].location != NSNotFound)
            {
                request_json = @"{\"event\":\"subscribe\",\"pair\":[\"BTC/USD\"],\"subscription\":{\"name\":\"trade\"}}";
            }
            else if ([urlPath rangeOfString:@"okx.com"].location != NSNotFound)
            {
                request_json = @"{\"op\":\"subscribe\",\"args\":[{\"channel\":\"trades\",\"instId\":\"BTC-USDT\"}]}";
            }
            else if ([urlPath rangeOfString:@"bybit"].location != NSNotFound)
            {
                request_json = @"{\"op\":\"subscribe\",\"args\":[\"publicTrade.BTCUSDT\"]}";
            }
            else if ([urlPath rangeOfString:@"bitfinex"].location != NSNotFound)
            {
                request_json = @"{\"event\":\"subscribe\",\"channel\":\"trades\",\"symbol\":\"tBTCUSD\"}";
            }
            else if ([urlPath rangeOfString:@"bitstamp"].location != NSNotFound)
            {
                request_json = @"{\"event\":\"bts:subscribe\",\"data\":{\"channel\":\"live_trades_btcusd\"}}";
            }
            else if ([urlPath rangeOfString:@"coinbase"].location != NSNotFound)
            {
                request_json = @"{\"type\":\"subscribe\",\"product_ids\":[\"BTC-USD\"],\"channels\":[\"ticker\"]}";
            }
            else if ([urlPath rangeOfString:@"kucoin"].location != NSNotFound)
            {
                request_json = @"{\"id\":1,\"type\":\"subscribe\",\"topic\":\"/market/match:BTC-USDT\",\"response\":true}";
            }
            else if ([urlPath rangeOfString:@"poloniex"].location != NSNotFound)
            {
                request_json = @"{\"event\":\"subscribe\",\"channel\":[\"trades\"],\"symbols\":[\"BTC_USDT\"]}";
            }
            else if ([urlPath rangeOfString:@"gate.io"].location != NSNotFound)
            {
                request_json = @"{\"time\":1,\"channel\":\"spot.trades\",\"event\":\"subscribe\",\"payload\":[\"BTC_USDT\"]}";
            }
            else if ([urlPath rangeOfString:@"crypto.com"].location != NSNotFound)
            {
                request_json = @"{\"id\":1,\"method\":\"subscribe\",\"params\":{\"channels\":[\"trade.BTC_USDT\"]}}";
            }
            else if ([urlPath rangeOfString:@"huobi"].location != NSNotFound)
            {
                request_json = @"{\"sub\":\"market.btcusdt.trade.detail\",\"id\":\"1\"}";
            }

            // Send subscription message
            NSURLSessionWebSocketMessage* request_msg =
                [[NSURLSessionWebSocketMessage alloc] initWithString:request_json];

            __block int messages_received = 0;
            __block const int max_messages = 8;  // Try a few more messages for slower exchanges

            __block void (^receiveNext)(void) = ^{
                [task receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage* _Nullable message,
                                                             NSError* _Nullable error) {
                    if (error)
                    {
                        if (messages_received == 0)
                        {
                            error_message = [error localizedDescription];
                            completed = true;
                        }
                        return;
                    }

                    if (!message)
                    {
                        if (messages_received == 0)
                        {
                            error_message = @"No message received";
                            completed = true;
                        }
                        return;
                    }

                    messages_received++;

                    NSData* data = DataFromWebSocketMessage(message);

                    NSError* jsonError = nil;
                    id json = [NSJSONSerialization JSONObjectWithData:data
                                                              options:0
                                                                error:&jsonError];

                    NSDictionary* dict = nil;

                    if ([json isKindOfClass:[NSDictionary class]])
                    {
                        dict = (NSDictionary*)json;
                    }
                    else if ([json isKindOfClass:[NSArray class]])
                    {
                        // Some exchanges send arrays
                        NSArray* arr = (NSArray*)json;
                        if (TrySetServerTimeFromExchangeArray(arr, &result_time))
                        {
                            success = true;
                            completed = true;
                            return;
                        }

                        if (arr.count > 0)
                        {
                            id first = arr[0];
                            if ([first isKindOfClass:[NSDictionary class]])
                            {
                                dict = (NSDictionary*)first;
                            }
                            else if ([first isKindOfClass:[NSNumber class]] && arr.count > 1)
                            {
                                // Kraken format: [channel_id, data, channel_name, pair]
                                id second = arr[1];
                                if ([second isKindOfClass:[NSDictionary class]])
                                {
                                    dict = (NSDictionary*)second;
                                }
                                else if ([second isKindOfClass:[NSArray class]])
                                {
                                    // Kraken trade format: [channel_id, [trades...], "trade", "pair"]
                                    // Each trade: [price, volume, time, buy/sell, market/limit, misc]
                                    NSArray* trades = (NSArray*)second;
                                    if (trades.count > 0)
                                    {
                                        id first_trade = trades[0];
                                        if ([first_trade isKindOfClass:[NSArray class]])
                                        {
                                            NSArray* trade = (NSArray*)first_trade;
                                            if (trade.count >= 3)
                                            {
                                                // time is at index 2 in Kraken trade: "1772918464.039501" or "2024-03-07T12:34:56.789Z"
                                                id time_val = trade[2];
                                                if ([time_val isKindOfClass:[NSString class]])
                                                {
                                                    NSString* timeStr = (NSString*)time_val;

                                                    // Try parsing as decimal seconds first (Kraken format: "1772918464.039501")
                                                    double time_double = [timeStr doubleValue];
                                                    if (time_double > 1000000000)  // Valid Unix timestamp
                                                    {
                                                        result_time.seconds = (uint64_t)time_double;
                                                        result_time.nanoseconds = (uint64_t)((time_double - result_time.seconds) * 1e9);
                                                        success = true;
                                                        completed = true;
                                                        return;
                                                    }

                                                    // Try ISO8601 format
                                                    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
                                                    [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"];
                                                    [formatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
                                                    NSDate* date = [formatter dateFromString:timeStr];

                                                    if (date)
                                                    {
                                                        result_time.seconds = [date timeIntervalSince1970];
                                                        result_time.nanoseconds = 0;
                                                        success = true;
                                                        completed = true;
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (!dict)
                    {
                        // Not valid JSON or no dict found, try next message
                        if (messages_received < max_messages)
                        {
                            receiveNext();
                        }
                        else
                        {
                            NSString* jsonStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                            fprintf(stderr, "Received JSON: %s\n", [jsonStr UTF8String]);
                            error_message = @"Invalid JSON response from server";
                            completed = true;
                        }
                        return;
                    }

                    // Check for heartbeat or system status messages (no timestamp)
                    id event_type = dict[@"event"];
                    if (event_type && [event_type isKindOfClass:[NSString class]])
                    {
                        NSString* evt = (NSString*)event_type;
                        if ([evt isEqualToString:@"heartbeat"] || [evt isEqualToString:@"systemStatus"] ||
                            [evt isEqualToString:@"pong"] || [evt isEqualToString:@"subscriptionStatus"] ||
                            [evt isEqualToString:@"info"] || [evt isEqualToString:@"subscribed"] ||
                            [evt isEqualToString:@"bts:subscription_succeeded"])
                        {
                            // Ignore these messages and wait for next
                            if (messages_received < max_messages)
                            {
                                receiveNext();
                            }
                            else
                            {
                                error_message = @"Only heartbeat/status messages received";
                                completed = true;
                            }
                            return;
                        }
                    }

                    id ping_value = dict[@"ping"];
                    if (ping_value)
                    {
                        NSString* pong_json =
                            [NSString stringWithFormat:@"{\"pong\":%@}", [ping_value description]];
                        NSURLSessionWebSocketMessage* pong_message =
                            [[NSURLSessionWebSocketMessage alloc] initWithString:pong_json];
                        [task sendMessage:pong_message
                         completionHandler:^(NSError* _Nullable send_error) {
                             if (send_error)
                             {
                                 error_message = [send_error localizedDescription];
                                 completed = true;
                                 return;
                             }

                             if (messages_received < max_messages)
                             {
                                 receiveNext();
                             }
                             else
                             {
                                 error_message = @"Only ping messages received";
                                 completed = true;
                             }
                         }];
                        return;
                    }

                    NSDictionary* payload_dict = ExtractPayloadDictionary(dict);
                    id seconds = payload_dict[@"seconds"];
                    id nanoseconds = payload_dict[@"nanoseconds"];

                    // Try different timestamp field names for various APIs
                    NSArray* timestampFields = @[@"E", @"T", @"ts", @"time", @"time_ms", @"create_time", @"create_time_ms", @"microtimestamp", @"t", @"timestamp", @"TimeStamp", @"seconds"];

                    for (NSString* field in timestampFields)
                    {
                        if (TrySetServerTimeFromValue(payload_dict[field], field, &result_time) ||
                            (payload_dict != dict && TrySetServerTimeFromValue(dict[field], field, &result_time)))
                        {
                            success = true;
                            completed = true;
                            return;
                        }
                    }

                    if (!seconds || ![seconds isKindOfClass:[NSNumber class]])
                    {
                        // No timestamp in this message, try next
                        if (messages_received < max_messages)
                        {
                            receiveNext();
                        }
                        else
                        {
                            NSString* jsonStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                            fprintf(stderr, "Received JSON: %s\n", [jsonStr UTF8String]);
                            error_message = @"Missing timestamp field in server response";
                            completed = true;
                        }
                        return;
                    }

                    result_time.seconds = [seconds unsignedLongLongValue];
                    result_time.nanoseconds =
                        (nanoseconds && [nanoseconds isKindOfClass:[NSNumber class]])
                            ? [nanoseconds unsignedLongLongValue]
                            : 0;

                    success = true;
                    completed = true;
                }];
            };

            [task sendMessage:request_msg
                completionHandler:^(NSError* error) {
                    if (error)
                    {
                        error_message = [error localizedDescription];
                        completed = true;
                        return;
                    }

                    // Start receiving messages
                    receiveNext();
                }];
        }

        // Wait with timeout using a simple spin loop with delay
        NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:15.0];
        while (!completed && [[NSDate date] compare:deadline] == NSOrderedAscending)
        {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }

        [task cancel];

        if (!completed)
        {
            snprintf(error_buffer, error_size, "WebSocket connection timeout");
            return false;
        }

        if (!success)
        {
            const char* error_text = [error_message UTF8String];
            snprintf(error_buffer, error_size, "%s",
                     error_text ? error_text : "Unknown error");
            return false;
        }

        *server_time = result_time;
        return true;
    }
}

} // namespace WebSocketClient

int main(int argc, char* argv[])
{
    uint64_t local_seconds = 0;
    uint32_t local_nanoseconds = 0;
    uint8_t mode = 0;
    ProbeError error{};

    // Get local time from commpage
    if (!ReadUnixTimeFromCommpage(&local_seconds, &local_nanoseconds, &mode, &error))
    {
        WriteFailure(error);
        return 1;
    }

    WriteKeyValueText("time_source=", "commpage_direct");
    WriteKeyValueU64("user_timebase_mode=", mode);
    WriteKeyValueU64("local_time_sec=", local_seconds);
    WriteKeyValueU64("local_time_nsec=", local_nanoseconds);

    // Check if WebSocket URL is provided
    const char* ws_url = nullptr;
    const char* request_message = nullptr;
    if (argc > 1)
    {
        ws_url = argv[1];
    }
    if (argc > 2)
    {
        request_message = argv[2];
    }

    if (ws_url)
    {
        WriteKeyValueText("websocket_url=", ws_url);

        WebSocketClient::ServerTime server_time{};
        char error_buffer[512] = {0};

        if (!WebSocketClient::GetServerTime(
                ws_url, request_message, &server_time, error_buffer, sizeof(error_buffer)))
        {
            WriteText(STDERR_FILENO, "WebSocket error: ");
            WriteText(STDERR_FILENO, error_buffer);
            WriteText(STDERR_FILENO, "\n");
            return 1;
        }

        WriteKeyValueU64("server_time_sec=", server_time.seconds);
        WriteKeyValueU64("server_time_nsec=", server_time.nanoseconds);

        // Calculate delta: server_time - local_time
        int64_t delta_sec = static_cast<int64_t>(server_time.seconds) -
                            static_cast<int64_t>(local_seconds);
        int64_t delta_nsec = static_cast<int64_t>(server_time.nanoseconds) -
                             static_cast<int64_t>(local_nanoseconds);

        // Normalize nanoseconds
        if (delta_nsec < 0)
        {
            delta_nsec += 1000000000LL;
            delta_sec -= 1;
        }
        else if (delta_nsec >= 1000000000LL)
        {
            delta_nsec -= 1000000000LL;
            delta_sec += 1;
        }

        // Print delta (handle signed values properly)
        {
            char line[96];
            size_t used = 0;
            AppendText(line, sizeof(line), &used, "delta_sec=");
            AppendI64(line, sizeof(line), &used, delta_sec);
            AppendChar(line, sizeof(line), &used, '\n');
            WriteAll(STDOUT_FILENO, line, used < sizeof(line) ? used : sizeof(line));
        }
        {
            char line[96];
            size_t used = 0;
            AppendText(line, sizeof(line), &used, "delta_nsec=");
            AppendI64(line, sizeof(line), &used, delta_nsec);
            AppendChar(line, sizeof(line), &used, '\n');
            WriteAll(STDOUT_FILENO, line, used < sizeof(line) ? used : sizeof(line));
        }

        // Print human-readable delta
        char line[128];
        size_t used = 0;
        AppendText(line, sizeof(line), &used, "delta_human=");
        AppendI64(line, sizeof(line), &used, delta_sec);
        AppendChar(line, sizeof(line), &used, '.');
        char nsec_str[11];
        snprintf(nsec_str, sizeof(nsec_str), "%09lld", static_cast<long long>(delta_nsec));
        AppendText(line, sizeof(line), &used, nsec_str);
        AppendText(line, sizeof(line), &used, "s\n");
        WriteAll(STDOUT_FILENO, line, used < sizeof(line) ? used : sizeof(line));
    }
    else
    {
        WriteText(STDOUT_FILENO,
                  "# No WebSocket URL provided. Usage: commpage_time_probe <ws://url> [request_json]\n");
    }

    return 0;
}

#endif
