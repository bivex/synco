/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-08 01:22
 * Last Updated: 2026-03-08 02:17
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

#define TIME_WATCHDOG_CRC32_TESTING 1
#include "time_watchdog_crc32.cpp"

#include <stdexcept>

namespace
{
uint64_t AbsDiffI64(int64_t lhs, int64_t rhs)
{
    return static_cast<uint64_t>(lhs > rhs ? lhs - rhs : rhs - lhs);
}

void Expect(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

void TestIntegerUnitInference()
{
    int64_t ns = 0;
    uint64_t precision_ms = 0;
    Expect(SetRemoteTimeFromInteger(1772925226805000000ULL, &ns, &precision_ms), "ns timestamp rejected");
    Expect(ns == 1772925226805000000LL && precision_ms == 1, "ns inference incorrect");
    Expect(SetRemoteTimeFromInteger(1772925226805000ULL, &ns, &precision_ms), "us timestamp rejected");
    Expect(ns == 1772925226805000000LL && precision_ms == 1, "us inference incorrect");
    Expect(SetRemoteTimeFromInteger(1772925226805ULL, &ns, &precision_ms), "ms timestamp rejected");
    Expect(ns == 1772925226805000000LL && precision_ms == 1, "ms inference incorrect");
    Expect(SetRemoteTimeFromInteger(1772925226ULL, &ns, &precision_ms), "sec timestamp rejected");
    Expect(ns == 1772925226000000000LL && precision_ms == 1000, "sec inference incorrect");
    Expect(!SetRemoteTimeFromInteger(42ULL, &ns, &precision_ms), "tiny integer should not parse as unix time");
}

void TestTimestampStringParsing()
{
    int64_t ns = 0;
    uint64_t precision_ms = 0;
    Expect(ParseTimestampValue(@"1772925226805", &ns, &precision_ms), "numeric ms string rejected");
    Expect(ns == 1772925226805000000LL && precision_ms == 1, "numeric ms string parsing incorrect");
    Expect(ParseTimestampValue(@"2026-03-07T23:13:46Z", &ns, &precision_ms), "iso8601 string rejected");
    Expect(precision_ms == 1000, "iso8601 second precision should be coarse");
    Expect(ns == 1772925226000000000LL, "iso8601 second parsing incorrect");

    Expect(ParseTimestampValue(@(1772925226.805), &ns, &precision_ms), "fractional NSNumber timestamp rejected");
    Expect(AbsDiffI64(ns, 1772925226805000000LL) <= 1000000ULL && precision_ms == 1,
           "fractional NSNumber timestamp parsing incorrect");
}

void TestNestedJsonFieldSelection()
{
    NSData* data = [@"{\"time\":7,\"result\":{\"data\":[{\"serverTime\":1772925226805}]}}"
        dataUsingEncoding:NSUTF8StringEncoding];
    int64_t ns = 0;
    uint64_t precision_ms = 0;
    NSString* field = nil;
    Expect(TryParseRemoteTimeFromJsonBody(data, &ns, &precision_ms, &field), "nested JSON timestamp not found");
    Expect(ns == 1772925226805000000LL, "nested JSON timestamp value incorrect");
    Expect(precision_ms == 1, "nested JSON precision incorrect");
    Expect([[field description] isEqualToString:@"result.data[0].serverTime"], "nested JSON field path incorrect");
}

void TestRootArrayJsonFieldSelection()
{
    NSData* data = [@"[{\"payload\":{\"timestamp_ms\":1772925226805}}]"
        dataUsingEncoding:NSUTF8StringEncoding];
    int64_t ns = 0;
    uint64_t precision_ms = 0;
    NSString* field = nil;
    Expect(TryParseRemoteTimeFromJsonBody(data, &ns, &precision_ms, &field), "root array JSON timestamp not found");
    Expect([[field description] isEqualToString:@"$[0].payload.timestamp_ms"], "root array field path incorrect");
}

void TestMalformedJsonDoesNotParse()
{
    NSData* data = [@"not-json" dataUsingEncoding:NSUTF8StringEncoding];
    int64_t ns = 0;
    uint64_t precision_ms = 0;
    NSString* field = nil;
    Expect(!TryParseRemoteTimeFromJsonBody(data, &ns, &precision_ms, &field), "malformed JSON should not parse");
}

void TestCoarseDatePrecisionAvoidsFalsePositive()
{
    VerificationResult result{};
    result.status_code = 200;
    result.local_before_ns = 0;
    result.local_after_ns = 100000000;
    result.monotonic_before_ns = 0;
    result.monotonic_after_ns = 100000000;
    result.remote_time_ns = 1250000000;
    result.remote_time_precision_ms = 1000;

    const WatchdogEvaluation evaluation = EvaluateVerificationResult(result, 500, 5000, 1500);
    Expect(!evaluation.anomaly_detected, "coarse Date precision should suppress false remote delta positive");
    Expect(evaluation.effective_remote_threshold_ms == 1500, "effective threshold for coarse source incorrect");
}

void TestPreciseRemoteTimeAndCombinedAnomalies()
{
    VerificationResult precise{};
    precise.status_code = 200;
    precise.local_before_ns = 0;
    precise.local_after_ns = 100000000;
    precise.monotonic_before_ns = 0;
    precise.monotonic_after_ns = 100000000;
    precise.remote_time_ns = 1250000000;
    precise.remote_time_precision_ms = 1;
    WatchdogEvaluation evaluation = EvaluateVerificationResult(precise, 500, 5000, 1500);
    Expect(evaluation.anomaly_detected, "precise source should trigger remote delta anomaly");
    Expect(evaluation.anomaly_reasons == "remote_delta_exceeded", "precise remote anomaly reason incorrect");

    VerificationResult combined{};
    combined.status_code = 500;
    combined.local_before_ns = 0;
    combined.local_after_ns = 100000000;
    combined.monotonic_before_ns = 0;
    combined.monotonic_after_ns = 2200000000ULL;
    combined.remote_time_ns = 60000000;
    combined.remote_time_precision_ms = 1;
    evaluation = EvaluateVerificationResult(combined, 500, 700, 100);
    Expect(evaluation.anomaly_detected, "combined anomaly case should trigger");
    Expect(evaluation.anomaly_reasons == "http_status_out_of_range,elapsed_exceeded,clock_gap_exceeded",
           "combined anomaly reasons/order incorrect");
}

void TestNegativeThresholdsClampToZero()
{
    VerificationResult result{};
    result.status_code = 200;
    result.local_before_ns = 0;
    result.local_after_ns = 0;
    result.monotonic_before_ns = 0;
    result.monotonic_after_ns = 1000000ULL;
    result.remote_time_ns = 2000000;
    result.remote_time_precision_ms = 0;

    const WatchdogEvaluation evaluation = EvaluateVerificationResult(result, -1, -1, -1);
    Expect(evaluation.anomaly_detected, "negative thresholds should clamp instead of disabling checks");
    Expect(evaluation.effective_remote_threshold_ms == 0, "negative remote threshold should clamp to zero");
    Expect(evaluation.anomaly_reasons == "remote_delta_exceeded,elapsed_exceeded,clock_gap_exceeded",
           "negative threshold anomaly reasons incorrect");
}

void TestThreadDeltaWindowUsesDeltaMath()
{
    ThreadDeltaWindow window{};
    window.local_before_ns = 10000000;
    window.local_after_ns = 180000000;
    window.monotonic_before_ns = 20000000;
    window.monotonic_after_ns = 170000000ULL;

    const ThreadDeltaEvaluation evaluation = EvaluateThreadDeltaWindow(window);
    Expect(evaluation.wall_elapsed_ns == 170000000, "thread delta wall elapsed incorrect");
    Expect(evaluation.monotonic_elapsed_ns == 150000000ULL,
           "thread delta monotonic elapsed incorrect");
    Expect(evaluation.clock_gap_ns == 20000000ULL, "thread delta clock gap incorrect");
}

void TestThreadMetricsExtendAnomalyReasons()
{
    VerificationResult result{};
    result.status_code = 200;
    result.local_before_ns = 0;
    result.local_after_ns = 0;
    result.monotonic_before_ns = 0;
    result.monotonic_after_ns = 0;
    result.remote_time_ns = 0;
    result.remote_time_precision_ms = 1000;
    result.thread_watchdog_max_delta_ns = 900000000ULL;
    result.thread_watchdog_max_clock_gap_ns = 250000000ULL;

    const WatchdogEvaluation evaluation = EvaluateVerificationResult(result, 5000, 500, 100);
    Expect(evaluation.anomaly_detected, "thread watchdog metrics should trigger anomaly");
    Expect(evaluation.anomaly_reasons == "thread_delta_exceeded,thread_clock_gap_exceeded",
           "thread watchdog anomaly reasons incorrect");
}

void TestKilledThreadAfterReadyTriggersAnomaly()
{
    VerificationResult result{};
    result.status_code = 200;
    result.local_before_ns = 0;
    result.local_after_ns = static_cast<int64_t>(kThreadWatchdogPostReadyGraceNs + 1000000ULL);
    result.monotonic_before_ns = 0;
    result.monotonic_after_ns = kThreadWatchdogPostReadyGraceNs + 1000000ULL;
    result.remote_time_ns = result.local_after_ns / 2;
    result.remote_time_precision_ms = 1000;
    result.thread_watchdog_ready_count = 5;
    result.thread_watchdog_post_ready_stall_count = 5;

    const WatchdogEvaluation evaluation = EvaluateVerificationResult(result, 120000, 120000, 10000);
    Expect(evaluation.anomaly_detected,
           "post-ready watchdog stall should trigger anomaly even with large thresholds");
    Expect(evaluation.anomaly_reasons == "thread_watchdog_killed_after_ready",
           "post-ready watchdog stall anomaly reason incorrect");
}

void TestPostReadyStallNeedsElapsedGraceWindow()
{
    VerificationResult result{};
    result.status_code = 200;
    result.local_before_ns = 0;
    result.local_after_ns = static_cast<int64_t>(kThreadWatchdogPostReadyGraceNs - 1ULL);
    result.monotonic_before_ns = 0;
    result.monotonic_after_ns = kThreadWatchdogPostReadyGraceNs - 1ULL;
    result.remote_time_ns = result.local_after_ns / 2;
    result.remote_time_precision_ms = 1000;
    result.thread_watchdog_ready_count = 5;
    result.thread_watchdog_post_ready_stall_count = 5;

    const WatchdogEvaluation evaluation = EvaluateVerificationResult(result, 120000, 120000, 10000);
    Expect(!evaluation.anomaly_detected,
           "post-ready watchdog stall should respect elapsed grace window");
}

void TestThreadWatchdogLayoutUsesGuardGapsAndJitter()
{
    const size_t page_size = 4096;
    const ThreadWatchdogLayout first =
        ComputeThreadWatchdogLayout(page_size, 0, 0x123456789abcdef0ULL, 0x11ULL,
                                    sizeof(ThreadWatchdogControl), alignof(ThreadWatchdogControl));
    const ThreadWatchdogLayout second =
        ComputeThreadWatchdogLayout(page_size, 1, 0x123456789abcdef0ULL, 0x11ULL,
                                    sizeof(ThreadWatchdogControl), alignof(ThreadWatchdogControl));
    const ThreadWatchdogLayout changed_entropy =
        ComputeThreadWatchdogLayout(page_size, 0, 0x0fedcba987654321ULL, 0x11ULL,
                                    sizeof(ThreadWatchdogControl), alignof(ThreadWatchdogControl));
    const ThreadWatchdogLayout metrics_layout =
        ComputeThreadWatchdogLayout(page_size, 0, 0x123456789abcdef0ULL, 0x22ULL,
                                    sizeof(ThreadWatchdogMetrics), alignof(ThreadWatchdogMetrics));

    Expect(first.region_page_count > first.accessible_page_index + 2,
           "thread layout should leave trailing guard pages");
    Expect(first.accessible_page_index >= 1, "thread layout should leave front guard pages");
    Expect(first.object_offset_in_page % alignof(ThreadWatchdogControl) == 0,
           "thread layout slot offset alignment incorrect");
    Expect(first.object_offset_in_page + sizeof(ThreadWatchdogControl) <= page_size,
           "thread layout slot should fit inside one page");
    Expect(first.region_page_count != second.region_page_count ||
               first.accessible_page_index != second.accessible_page_index ||
               first.object_offset_in_page != second.object_offset_in_page,
           "different replicas should not reuse the same layout");
    Expect(first.region_page_count != changed_entropy.region_page_count ||
               first.accessible_page_index != changed_entropy.accessible_page_index ||
               first.object_offset_in_page != changed_entropy.object_offset_in_page,
           "runtime entropy should perturb thread layout");
    Expect(first.region_page_count != metrics_layout.region_page_count ||
               first.accessible_page_index != metrics_layout.accessible_page_index ||
               first.object_offset_in_page != metrics_layout.object_offset_in_page,
           "different salts/object shapes should perturb layout");
}

void TestThreadWatchdogStartOrderAndFingerprintChange()
{
    const std::vector<size_t> order = BuildThreadWatchdogStartOrder(5, 0x123456789abcdef0ULL);
    bool seen[5] = {false, false, false, false, false};
    for (size_t value : order)
    {
        Expect(value < 5, "thread start order index out of range");
        Expect(!seen[value], "thread start order should be a permutation");
        seen[value] = true;
    }

    const ThreadWatchdogMapping control_a{
        .region = (void*)0x1000,
        .region_size = 0x5000,
        .object = (void*)0x1888,
        .accessible_page_index = 2,
        .object_offset_in_page = 0x88,
    };
    const ThreadWatchdogMapping metrics_a{
        .region = (void*)0x9000,
        .region_size = 0x7000,
        .object = (void*)0x9440,
        .accessible_page_index = 1,
        .object_offset_in_page = 0x40,
    };
    const ThreadWatchdogMapping metrics_b{
        .region = (void*)0x9000,
        .region_size = 0x7000,
        .object = (void*)0x9880,
        .accessible_page_index = 3,
        .object_offset_in_page = 0x80,
    };

    const uint64_t fingerprint_a =
        BuildThreadWatchdogLayoutFingerprint(0, control_a, metrics_a, 0xabcdefULL);
    const uint64_t fingerprint_b =
        BuildThreadWatchdogLayoutFingerprint(0, control_a, metrics_b, 0xabcdefULL);
    Expect(fingerprint_a != fingerprint_b, "thread layout fingerprint should change with placement");
}
} // namespace

int main()
{
    @autoreleasepool
    {
        TestIntegerUnitInference();
        TestTimestampStringParsing();
        TestNestedJsonFieldSelection();
        TestRootArrayJsonFieldSelection();
        TestMalformedJsonDoesNotParse();
        TestCoarseDatePrecisionAvoidsFalsePositive();
        TestPreciseRemoteTimeAndCombinedAnomalies();
        TestNegativeThresholdsClampToZero();
        TestThreadDeltaWindowUsesDeltaMath();
        TestThreadMetricsExtendAnomalyReasons();
        TestKilledThreadAfterReadyTriggersAnomaly();
        TestPostReadyStallNeedsElapsedGraceWindow();
        TestThreadWatchdogLayoutUsesGuardGapsAndJitter();
        TestThreadWatchdogStartOrderAndFingerprintChange();
    }

    std::puts("time_watchdog_crc32 edge-case tests: PASS");
    return 0;
}