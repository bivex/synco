/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-07 19:55
 * Last Updated: 2026-03-08 01:22
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string_view>
#include <string>

#if defined(__APPLE__)
#include <gethostuuid.h>
#include <uuid/uuid.h>
#endif

namespace
{
constexpr std::string_view kComputerIdSource = "macos:gethostuuid";

struct ProbeResult
{
    std::string source;
    std::string computer_id;
    std::string error;
};

ProbeResult ProbeComputerId()
{
#if !defined(__APPLE__)
    return {std::string(kComputerIdSource), "", "computer_id_probe is macOS-only"};
#else
    uuid_t host_uuid{};
    const timespec timeout{0, 0};

    if (gethostuuid(host_uuid, &timeout) != 0)
    {
        return {std::string(kComputerIdSource), "",
                std::string("gethostuuid failed: ") + std::strerror(errno)};
    }

    uuid_string_t uuid_string{};
    uuid_unparse_upper(host_uuid, uuid_string);
    return {std::string(kComputerIdSource), uuid_string, ""};
#endif
}
} // namespace

int main()
{
    const auto result = ProbeComputerId();

    std::cout << "computer_id_source=" << result.source << '\n';
    std::cout << "computer_id=" << result.computer_id << '\n';

    if (!result.error.empty())
    {
        std::cerr << result.error << '\n';
        return 1;
    }

    return 0;
}