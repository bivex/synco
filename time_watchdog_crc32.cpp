/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-08 01:17
 * Last Updated: 2026-03-08 10:29
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
#include <algorithm>
#include <atomic>
#include <cmath>
#include <exception>
#include <memory>
#include <new>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <time.h>
#include <vector>
#include <dispatch/dispatch.h>
#include <sys/mman.h>
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
constexpr size_t kThreadWatchdogReplicaCount = 5;
constexpr uint64_t kThreadWatchdogPollIntervalNs = 250000ULL;
constexpr uint64_t kThreadWatchdogPostReadyGraceNs = kThreadWatchdogPollIntervalNs * 4ULL;
constexpr size_t kThreadWatchdogBaseRegionPages = 12;
constexpr size_t kThreadWatchdogRegionStridePages = 7;

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

struct ThreadDeltaWindow
{
    int64_t local_before_ns = 0;
    int64_t local_after_ns = 0;
    uint64_t monotonic_before_ns = 0;
    uint64_t monotonic_after_ns = 0;
};

struct ThreadDeltaEvaluation
{
    int64_t wall_elapsed_ns = 0;
    uint64_t monotonic_elapsed_ns = 0;
    uint64_t clock_gap_ns = 0;
};

ThreadDeltaEvaluation EvaluateThreadDeltaWindow(const ThreadDeltaWindow& window)
{
    ThreadDeltaEvaluation evaluation{};
    evaluation.wall_elapsed_ns = window.local_after_ns - window.local_before_ns;
    evaluation.monotonic_elapsed_ns = window.monotonic_after_ns - window.monotonic_before_ns;
    evaluation.clock_gap_ns =
        AbsI64(evaluation.wall_elapsed_ns - static_cast<int64_t>(evaluation.monotonic_elapsed_ns));
    return evaluation;
}

struct ThreadWatchdogAggregate
{
    uint64_t thread_count = 0;
    uint64_t ready_thread_count = 0;
    uint64_t sample_count = 0;
    uint64_t post_ready_stall_count = 0;
    uint64_t max_delta_ns = 0;
    uint64_t max_clock_gap_ns = 0;
    uint64_t memory_spread_bytes = 0;
    uint64_t layout_fingerprint = 0;
    bool failed = false;
};

struct ThreadWatchdogControl
{
    std::atomic<bool> keep_running {false};
    std::atomic<bool> ready {false};
    std::atomic<bool> failed {false};
    std::atomic<uint64_t> heartbeat {0};
    std::atomic<uint64_t> phase_mix {0};
};

struct ThreadWatchdogMetrics
{
    std::atomic<uint64_t> sample_count {0};
    std::atomic<uint64_t> max_delta_ns {0};
    std::atomic<uint64_t> max_clock_gap_ns {0};
};

struct ThreadWatchdogMapping
{
    void* region = MAP_FAILED;
    size_t region_size = 0;
    void* object = nullptr;
    size_t accessible_page_index = 0;
    size_t object_offset_in_page = 0;
};

struct ThreadWatchdogLayout
{
    size_t region_page_count = 0;
    size_t accessible_page_index = 0;
    size_t object_offset_in_page = 0;
};

struct ThreadWatchdogReplica
{
    size_t replica_index = 0;
    ThreadWatchdogMapping control_mapping;
    ThreadWatchdogMapping metrics_mapping;
    ThreadWatchdogControl* control = nullptr;
    ThreadWatchdogMetrics* metrics = nullptr;
    uint64_t layout_fingerprint = 0;
};

struct ThreadWatchdogRuntime
{
    std::vector<ThreadWatchdogReplica> replicas;
    std::vector<std::thread> threads;
    uint64_t runtime_entropy = 0;
};

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
    uint64_t thread_watchdog_count = 0;
    uint64_t thread_watchdog_ready_count = 0;
    uint64_t thread_watchdog_sample_count = 0;
    uint64_t thread_watchdog_post_ready_stall_count = 0;
    uint64_t thread_watchdog_max_delta_ns = 0;
    uint64_t thread_watchdog_max_clock_gap_ns = 0;
    uint64_t thread_watchdog_memory_spread_bytes = 0;
    uint64_t thread_watchdog_layout_fingerprint = 0;
    bool thread_watchdog_failed = false;
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

size_t GetSystemPageSize()
{
    const long page_size = sysconf(_SC_PAGESIZE);
    return page_size > 0 ? static_cast<size_t>(page_size) : 4096U;
}

uint64_t MixThreadWatchdogEntropy(uint64_t value)
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

size_t AlignDownSize(size_t value, size_t alignment)
{
    return alignment > 1 ? (value / alignment) * alignment : value;
}

ThreadWatchdogLayout ComputeThreadWatchdogLayout(size_t page_size,
                                                 size_t replica_index,
                                                 uint64_t runtime_entropy,
                                                 uint64_t salt,
                                                 size_t object_size,
                                                 size_t object_alignment)
{
    const uint64_t entropy =
        MixThreadWatchdogEntropy(runtime_entropy ^ salt ^
                                 ((static_cast<uint64_t>(replica_index) + 1ULL) *
                                  0x9e3779b97f4a7c15ULL));
    const size_t front_guard_pages = 1U + static_cast<size_t>(entropy & 0x3ULL);
    const size_t back_guard_pages = 2U + static_cast<size_t>((entropy >> 8) & 0x3ULL);
    const size_t jitter_pages = 2U + static_cast<size_t>((entropy >> 16) & 0x7ULL);

    ThreadWatchdogLayout layout{};
    layout.region_page_count = kThreadWatchdogBaseRegionPages +
                               (replica_index * kThreadWatchdogRegionStridePages) +
                               front_guard_pages + back_guard_pages + jitter_pages;

    const size_t usable_page_count =
        layout.region_page_count - front_guard_pages - back_guard_pages;
    layout.accessible_page_index =
        front_guard_pages + static_cast<size_t>((entropy >> 24) % usable_page_count);

    const size_t slot_alignment = object_alignment > 0 ? object_alignment : 1U;
    const size_t max_offset = page_size > object_size
                                  ? page_size - object_size
                                  : 0U;
    const size_t margin = max_offset > 512U ? 128U + static_cast<size_t>((entropy >> 32) & 0xffULL)
                                            : 0U;
    const size_t min_offset = std::min(margin, max_offset);
    const size_t usable_offset_span = max_offset > min_offset ? (max_offset - min_offset) : 0U;
    const size_t raw_offset = min_offset +
                              (usable_offset_span > 0U
                                   ? static_cast<size_t>((entropy >> 40) % (usable_offset_span + 1U))
                                   : 0U);
    layout.object_offset_in_page = AlignDownSize(raw_offset, slot_alignment);

    if (layout.object_offset_in_page > max_offset)
        layout.object_offset_in_page = AlignDownSize(max_offset, slot_alignment);

    return layout;
}

uint64_t BuildThreadWatchdogLayoutFingerprint(size_t replica_index,
                                              const ThreadWatchdogMapping& control_mapping,
                                              const ThreadWatchdogMapping& metrics_mapping,
                                              uint64_t runtime_entropy)
{
    uint64_t fingerprint = runtime_entropy ^ (static_cast<uint64_t>(replica_index) << 32);
    fingerprint = MixThreadWatchdogEntropy(
        fingerprint ^ reinterpret_cast<uintptr_t>(control_mapping.object) ^
        (static_cast<uint64_t>(control_mapping.region_size) << 7) ^
        (static_cast<uint64_t>(control_mapping.accessible_page_index) << 17) ^
        (static_cast<uint64_t>(control_mapping.object_offset_in_page) << 3));
    fingerprint = MixThreadWatchdogEntropy(
        fingerprint ^ reinterpret_cast<uintptr_t>(metrics_mapping.object) ^
        (static_cast<uint64_t>(metrics_mapping.region_size) << 9) ^
        (static_cast<uint64_t>(metrics_mapping.accessible_page_index) << 21) ^
        (static_cast<uint64_t>(metrics_mapping.object_offset_in_page) << 5));
    return fingerprint;
}

std::vector<size_t> BuildThreadWatchdogStartOrder(size_t replica_count, uint64_t runtime_entropy)
{
    std::vector<size_t> order(replica_count);
    for (size_t index = 0; index < replica_count; ++index)
        order[index] = index;

    uint64_t shuffle_state = runtime_entropy;
    for (size_t remaining = replica_count; remaining > 1; --remaining)
    {
        shuffle_state = MixThreadWatchdogEntropy(
            shuffle_state ^ (static_cast<uint64_t>(remaining) * 0x94d049bb133111ebULL));
        const size_t swap_index = static_cast<size_t>(shuffle_state % remaining);
        std::swap(order[remaining - 1], order[swap_index]);
    }

    return order;
}

void UpdateAtomicMax(std::atomic<uint64_t>* target, uint64_t candidate)
{
    uint64_t current = target->load(std::memory_order_relaxed);
    while (current < candidate &&
           !target->compare_exchange_weak(current, candidate, std::memory_order_relaxed,
                                          std::memory_order_relaxed))
    {
    }
}

bool InitializeThreadWatchdogMapping(ThreadWatchdogMapping* mapping,
                                     size_t page_size,
                                     const ThreadWatchdogLayout& layout,
                                     char* error_buffer,
                                     size_t error_buffer_size,
                                     const char* label,
                                     size_t replica_index)
{
    const size_t region_size = page_size * layout.region_page_count;
    void* region = mmap(nullptr, region_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region == MAP_FAILED)
    {
        snprintf(error_buffer, error_buffer_size,
                 "thread watchdog %s mmap failed for replica %zu", label, replica_index);
        return false;
    }

    if (mprotect(region, region_size, PROT_NONE) != 0)
    {
        snprintf(error_buffer, error_buffer_size,
                 "thread watchdog %s guard-gap setup failed for replica %zu", label,
                 replica_index);
        munmap(region, region_size);
        return false;
    }

    char* active_page = reinterpret_cast<char*>(region) + (layout.accessible_page_index * page_size);
    if (mprotect(active_page, page_size, PROT_READ | PROT_WRITE) != 0)
    {
        snprintf(error_buffer, error_buffer_size,
                 "thread watchdog %s active-page setup failed for replica %zu", label,
                 replica_index);
        munmap(region, region_size);
        return false;
    }

    mapping->region = region;
    mapping->region_size = region_size;
    mapping->object = active_page + layout.object_offset_in_page;
    mapping->accessible_page_index = layout.accessible_page_index;
    mapping->object_offset_in_page = layout.object_offset_in_page;
    return true;
}

void ThreadWatchdogWorker(ThreadWatchdogControl* control,
                          ThreadWatchdogMetrics* metrics,
                          uint64_t layout_fingerprint)
{
    ProbeError error{};
    uint8_t mode = 0;
    ThreadDeltaWindow window{};

    if (!ReadUnixTimeNsFromCommpage(&window.local_before_ns, &mode, &error))
    {
        control->failed.store(true, std::memory_order_release);
        return;
    }

    window.monotonic_before_ns = ReadMonotonicNs(&error);
    if (window.monotonic_before_ns == 0 && error.message)
    {
        control->failed.store(true, std::memory_order_release);
        return;
    }

    control->phase_mix.store(layout_fingerprint, std::memory_order_relaxed);
    control->ready.store(true, std::memory_order_release);

    while (control->keep_running.load(std::memory_order_acquire))
    {
        if (kThreadWatchdogPollIntervalNs > 0)
        {
            const struct timespec sleep_request = {
                .tv_sec = 0,
                .tv_nsec = static_cast<long>(kThreadWatchdogPollIntervalNs),
            };
            nanosleep(&sleep_request, nullptr);
        }

        error = ProbeError{};
        if (!ReadUnixTimeNsFromCommpage(&window.local_after_ns, &mode, &error))
        {
            control->failed.store(true, std::memory_order_release);
            return;
        }

        window.monotonic_after_ns = ReadMonotonicNs(&error);
        if (window.monotonic_after_ns == 0 && error.message)
        {
            control->failed.store(true, std::memory_order_release);
            return;
        }

        const ThreadDeltaEvaluation evaluation = EvaluateThreadDeltaWindow(window);
        const uint64_t heartbeat = control->heartbeat.fetch_add(1, std::memory_order_relaxed) + 1ULL;
        const uint64_t phase_mix =
            MixThreadWatchdogEntropy(layout_fingerprint ^ heartbeat ^
                                     evaluation.monotonic_elapsed_ns ^ evaluation.clock_gap_ns);
        control->phase_mix.store(phase_mix, std::memory_order_relaxed);
        UpdateAtomicMax(&metrics->max_delta_ns, evaluation.monotonic_elapsed_ns);
        UpdateAtomicMax(&metrics->max_clock_gap_ns, evaluation.clock_gap_ns);
        metrics->sample_count.fetch_add(1, std::memory_order_relaxed);

        window.local_before_ns = window.local_after_ns;
        window.monotonic_before_ns = window.monotonic_after_ns;
    }
}

void ShutdownThreadWatchdogRuntime(ThreadWatchdogRuntime* runtime)
{
    for (ThreadWatchdogReplica& replica : runtime->replicas)
    {
        if (replica.control)
            replica.control->keep_running.store(false, std::memory_order_release);
    }

    for (std::thread& thread : runtime->threads)
    {
        if (thread.joinable())
            thread.join();
    }
}

void ReleaseThreadWatchdogRuntime(ThreadWatchdogRuntime* runtime)
{
    ShutdownThreadWatchdogRuntime(runtime);

    for (ThreadWatchdogReplica& replica : runtime->replicas)
    {
        if (replica.control)
        {
            replica.control->~ThreadWatchdogControl();
            replica.control = nullptr;
        }
        if (replica.metrics)
        {
            replica.metrics->~ThreadWatchdogMetrics();
            replica.metrics = nullptr;
        }

        if (replica.control_mapping.region != MAP_FAILED)
            munmap(replica.control_mapping.region, replica.control_mapping.region_size);
        if (replica.metrics_mapping.region != MAP_FAILED)
            munmap(replica.metrics_mapping.region, replica.metrics_mapping.region_size);
    }
    runtime->replicas.clear();
    runtime->threads.clear();
    runtime->runtime_entropy = 0;
}

bool StartThreadWatchdogRuntime(ThreadWatchdogRuntime* runtime,
                                char* error_buffer,
                                size_t error_buffer_size)
{
    runtime->replicas.clear();
    runtime->threads.clear();
    runtime->replicas.reserve(kThreadWatchdogReplicaCount);
    runtime->threads.reserve(kThreadWatchdogReplicaCount);

    const size_t page_size = GetSystemPageSize();
    const uint64_t runtime_entropy =
        MixThreadWatchdogEntropy(ReadMonotonicNs(nullptr) ^ reinterpret_cast<uintptr_t>(runtime) ^
                                 reinterpret_cast<uintptr_t>(error_buffer));
    runtime->runtime_entropy = runtime_entropy;

    for (size_t index = 0; index < kThreadWatchdogReplicaCount; ++index)
    {
        const ThreadWatchdogLayout control_layout =
            ComputeThreadWatchdogLayout(page_size, index, runtime_entropy, 0x13579bdf2468ace0ULL,
                                        sizeof(ThreadWatchdogControl),
                                        alignof(ThreadWatchdogControl));
        const ThreadWatchdogLayout metrics_layout =
            ComputeThreadWatchdogLayout(page_size, index, runtime_entropy, 0xfdb97531eca86420ULL,
                                        sizeof(ThreadWatchdogMetrics),
                                        alignof(ThreadWatchdogMetrics));

        ThreadWatchdogReplica replica{};
        replica.replica_index = index;
        if (!InitializeThreadWatchdogMapping(&replica.control_mapping, page_size, control_layout,
                                             error_buffer, error_buffer_size, "control", index) ||
            !InitializeThreadWatchdogMapping(&replica.metrics_mapping, page_size, metrics_layout,
                                             error_buffer, error_buffer_size, "metrics", index))
        {
            if (replica.control_mapping.region != MAP_FAILED)
                munmap(replica.control_mapping.region, replica.control_mapping.region_size);
            if (replica.metrics_mapping.region != MAP_FAILED)
                munmap(replica.metrics_mapping.region, replica.metrics_mapping.region_size);
            ReleaseThreadWatchdogRuntime(runtime);
            return false;
        }

        replica.control = new (replica.control_mapping.object) ThreadWatchdogControl();
        replica.metrics = new (replica.metrics_mapping.object) ThreadWatchdogMetrics();
        replica.control->keep_running.store(true, std::memory_order_release);
        replica.layout_fingerprint =
            BuildThreadWatchdogLayoutFingerprint(index, replica.control_mapping,
                                                replica.metrics_mapping, runtime_entropy);
        runtime->replicas.push_back(replica);
    }

    const std::vector<size_t> start_order =
        BuildThreadWatchdogStartOrder(runtime->replicas.size(), runtime_entropy);
    for (size_t start_rank = 0; start_rank < start_order.size(); ++start_rank)
    {
        ThreadWatchdogReplica& replica = runtime->replicas[start_order[start_rank]];
        replica.control->phase_mix.store(MixThreadWatchdogEntropy(replica.layout_fingerprint ^ start_rank),
                                         std::memory_order_relaxed);
        try
        {
            runtime->threads.emplace_back(ThreadWatchdogWorker, replica.control, replica.metrics,
                                          replica.layout_fingerprint);
        }
        catch (const std::exception& exception)
        {
            snprintf(error_buffer, error_buffer_size,
                     "thread watchdog spawn failed: %s", exception.what());
            ReleaseThreadWatchdogRuntime(runtime);
            return false;
        }
    }

    const uint64_t start_ns = ReadMonotonicNs(nullptr);
    const uint64_t deadline_ns = start_ns + 500000000ULL;
    while (true)
    {
        size_t ready_count = 0;
        for (const ThreadWatchdogReplica& replica : runtime->replicas)
        {
            if (replica.control->failed.load(std::memory_order_acquire))
            {
                snprintf(error_buffer, error_buffer_size,
                         "thread watchdog worker initialization failed");
                for (ThreadWatchdogReplica& stop_replica : runtime->replicas)
                    stop_replica.control->keep_running.store(false, std::memory_order_release);
                for (std::thread& thread : runtime->threads)
                {
                    if (thread.joinable())
                        thread.join();
                }
                ReleaseThreadWatchdogRuntime(runtime);
                return false;
            }
            if (replica.control->ready.load(std::memory_order_acquire))
                ++ready_count;
        }

        if (ready_count == runtime->replicas.size())
            return true;

        if (ReadMonotonicNs(nullptr) >= deadline_ns)
        {
            snprintf(error_buffer, error_buffer_size, "thread watchdog startup timed out");
            for (ThreadWatchdogReplica& replica : runtime->replicas)
                replica.control->keep_running.store(false, std::memory_order_release);
            for (std::thread& thread : runtime->threads)
            {
                if (thread.joinable())
                    thread.join();
            }
            ReleaseThreadWatchdogRuntime(runtime);
            return false;
        }

        const struct timespec sleep_request = {.tv_sec = 0, .tv_nsec = 1000000L};
        nanosleep(&sleep_request, nullptr);
    }
}

void StopThreadWatchdogRuntime(ThreadWatchdogRuntime* runtime, ThreadWatchdogAggregate* aggregate)
{
    *aggregate = ThreadWatchdogAggregate{};
    aggregate->thread_count = runtime->replicas.size();

    uintptr_t min_address = 0;
    uintptr_t max_address = 0;

    for (ThreadWatchdogReplica& replica : runtime->replicas)
    {
        const uintptr_t control_address = reinterpret_cast<uintptr_t>(replica.control);
        const uintptr_t metrics_address = reinterpret_cast<uintptr_t>(replica.metrics);
        min_address = min_address == 0 ? control_address : std::min(min_address, control_address);
        min_address = std::min(min_address, metrics_address);
        max_address = std::max(max_address, control_address);
        max_address = std::max(max_address, metrics_address);
        replica.control->keep_running.store(false, std::memory_order_release);
    }

    for (std::thread& thread : runtime->threads)
    {
        if (thread.joinable())
            thread.join();
    }

    for (const ThreadWatchdogReplica& replica : runtime->replicas)
    {
        const bool ready = replica.control->ready.load(std::memory_order_acquire);
        const bool failed = replica.control->failed.load(std::memory_order_acquire);
        const uint64_t heartbeat = replica.control->heartbeat.load(std::memory_order_relaxed);
        const uint64_t phase_mix = replica.control->phase_mix.load(std::memory_order_relaxed);
        const uint64_t sample_count = replica.metrics->sample_count.load(std::memory_order_relaxed);

        aggregate->ready_thread_count +=
            ready ? 1ULL : 0ULL;
        aggregate->sample_count += sample_count;
        aggregate->max_delta_ns =
            std::max(aggregate->max_delta_ns, replica.metrics->max_delta_ns.load(std::memory_order_relaxed));
        aggregate->max_clock_gap_ns = std::max(
            aggregate->max_clock_gap_ns,
            replica.metrics->max_clock_gap_ns.load(std::memory_order_relaxed));
        aggregate->layout_fingerprint =
            MixThreadWatchdogEntropy(aggregate->layout_fingerprint ^ replica.layout_fingerprint);
        if (ready && !failed && heartbeat == 0 && sample_count == 0 && phase_mix == replica.layout_fingerprint)
            aggregate->post_ready_stall_count += 1ULL;
        aggregate->failed = aggregate->failed || failed;
    }

    if (max_address > min_address)
        aggregate->memory_spread_bytes = max_address - min_address;

    ReleaseThreadWatchdogRuntime(runtime);
}

void ApplyThreadWatchdogAggregate(VerificationResult* result,
                                  const ThreadWatchdogAggregate& aggregate)
{
    result->thread_watchdog_count = aggregate.thread_count;
    result->thread_watchdog_ready_count = aggregate.ready_thread_count;
    result->thread_watchdog_sample_count = aggregate.sample_count;
    result->thread_watchdog_post_ready_stall_count = aggregate.post_ready_stall_count;
    result->thread_watchdog_max_delta_ns = aggregate.max_delta_ns;
    result->thread_watchdog_max_clock_gap_ns = aggregate.max_clock_gap_ns;
    result->thread_watchdog_memory_spread_bytes = aggregate.memory_spread_bytes;
    result->thread_watchdog_layout_fingerprint = aggregate.layout_fingerprint;
    result->thread_watchdog_failed = aggregate.failed;
}

struct ThreadWatchdogScope
{
    ThreadWatchdogRuntime runtime;
    VerificationResult* result = nullptr;
    bool active = false;

    ~ThreadWatchdogScope()
    {
        if (!active || !result)
            return;

        ThreadWatchdogAggregate aggregate{};
        StopThreadWatchdogRuntime(&runtime, &aggregate);
        ApplyThreadWatchdogAggregate(result, aggregate);
    }
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
        ThreadWatchdogScope thread_watchdog_scope{};
        thread_watchdog_scope.result = result;

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

        if (!StartThreadWatchdogRuntime(&thread_watchdog_scope.runtime, error_buffer,
                                        error_buffer_size))
        {
            return false;
        }
        thread_watchdog_scope.active = true;

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
    if (result.thread_watchdog_failed)
        append_reason("thread_watchdog_failed");
    if (result.thread_watchdog_post_ready_stall_count > 0 &&
        evaluation.monotonic_elapsed_ns >= kThreadWatchdogPostReadyGraceNs)
        append_reason("thread_watchdog_killed_after_ready");
    if (result.thread_watchdog_max_delta_ns > safe_elapsed_threshold_ms * 1000000ULL)
        append_reason("thread_delta_exceeded");
    if (result.thread_watchdog_max_clock_gap_ns > safe_clock_gap_threshold_ms * 1000000ULL)
        append_reason("thread_clock_gap_exceeded");

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
    const char* thread_watchdog_failed_text = result.thread_watchdog_failed ? "1" : "0";

    const std::string canonical_payload =
        std::string("v4\n") + "verification_url=" + verification_url + "\n" +
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
        "thread_watchdog_count=" + std::to_string(result.thread_watchdog_count) + "\n" +
        "thread_watchdog_ready_count=" + std::to_string(result.thread_watchdog_ready_count) + "\n" +
        "thread_watchdog_sample_count=" + std::to_string(result.thread_watchdog_sample_count) + "\n" +
        "thread_watchdog_post_ready_stall_count=" +
        std::to_string(result.thread_watchdog_post_ready_stall_count) + "\n" +
        "thread_watchdog_max_delta_ns=" + std::to_string(result.thread_watchdog_max_delta_ns) + "\n" +
        "thread_watchdog_max_clock_gap_ns=" + std::to_string(result.thread_watchdog_max_clock_gap_ns) + "\n" +
        "thread_watchdog_memory_spread_bytes=" +
        std::to_string(result.thread_watchdog_memory_spread_bytes) + "\n" +
        "thread_watchdog_layout_fingerprint=" +
        std::to_string(result.thread_watchdog_layout_fingerprint) + "\n" +
        "thread_watchdog_failed=" + std::string(thread_watchdog_failed_text) + "\n" +
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
    WriteKeyValueText("thread_watchdog_mode=", "tricky_shot_swarm");
    WriteKeyValueU64("thread_watchdog_threads=", result.thread_watchdog_count);
    WriteKeyValueU64("thread_watchdog_ready_threads=", result.thread_watchdog_ready_count);
    WriteKeyValueU64("thread_watchdog_samples=", result.thread_watchdog_sample_count);
    WriteKeyValueU64("thread_watchdog_post_ready_stall_threads=",
                     result.thread_watchdog_post_ready_stall_count);
    WriteKeyValueU64("thread_watchdog_max_delta_ms=", result.thread_watchdog_max_delta_ns / 1000000ULL);
    WriteKeyValueU64("thread_watchdog_max_clock_gap_ms=", result.thread_watchdog_max_clock_gap_ns / 1000000ULL);
    WriteKeyValueU64("thread_watchdog_memory_spread_bytes=", result.thread_watchdog_memory_spread_bytes);
    WriteKeyValueU64("thread_watchdog_layout_fingerprint=", result.thread_watchdog_layout_fingerprint);
    WriteKeyValueText("thread_watchdog_failed=", thread_watchdog_failed_text);
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