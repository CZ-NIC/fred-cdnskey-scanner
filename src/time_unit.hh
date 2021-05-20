/*
 * Copyright (C) 2017-2021  CZ.NIC, z. s. p. o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef TIME_UNIT_HH_AA862C0A2A13AEFBE6D015A289BED606//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define TIME_UNIT_HH_AA862C0A2A13AEFBE6D015A289BED606

#include <chrono>
#include <iosfwd>
#include <string>

namespace TimeUnit {

template <typename Type, typename Tag> class Duration;

template <typename Rep, typename Period>
std::ostream& operator<<(std::ostream&, const std::chrono::duration<Rep, Period>&);

template <> std::ostream& operator<<(std::ostream&, const std::chrono::seconds&);
template <> std::ostream& operator<<(std::ostream&, const std::chrono::milliseconds&);
template <> std::ostream& operator<<(std::ostream&, const std::chrono::microseconds&);
template <> std::ostream& operator<<(std::ostream&, const std::chrono::nanoseconds&);

template <typename Rep, typename Period, typename Tag>
class Duration<std::chrono::duration<Rep, Period>, Tag>
{
public:
    constexpr Duration() = default;
    Duration(const Duration&) = default;
    template <typename R, typename P>
    explicit constexpr Duration(const std::chrono::duration<R, P>& src)
        : value_{src}
    { }
    template <typename R>
    explicit constexpr Duration(const R& src)
        : value_{src}
    { }
    constexpr Rep count() const { return value_.count(); }
    template <typename T>
    constexpr T as() const { return std::chrono::duration_cast<T>(value_); }
    constexpr auto get() const { return value_; }
    template <typename T>
    constexpr auto operator/(T divider) const { return Duration{value_.count() / divider}; }
    static constexpr Duration zero() { return Duration{std::chrono::duration<Rep, Period>::zero()}; }
private:
    std::chrono::duration<Rep, Period> value_;
    friend constexpr bool operator<(const Duration& lhs, const Duration& rhs) { return lhs.value_ < rhs.value_; }
    friend constexpr bool operator<=(const Duration& lhs, const Duration& rhs) { return lhs.value_ <= rhs.value_; }
    friend constexpr bool operator==(const Duration& lhs, const Duration& rhs) { return lhs.value_ == rhs.value_; }
    friend constexpr bool operator!=(const Duration& lhs, const Duration& rhs) { return lhs.value_ != rhs.value_; }
    friend constexpr bool operator>=(const Duration& lhs, const Duration& rhs) { return lhs.value_ >= rhs.value_; }
    friend constexpr bool operator>(const Duration& lhs, const Duration& rhs) { return lhs.value_ > rhs.value_; }
    friend std::ostream& operator<<(std::ostream& out, const Duration& duration) { return out << duration.value_; }
};

template <typename Tag>
using Seconds = Duration<std::chrono::seconds, Tag>;

template <typename Tag>
using Milliseconds = Duration<std::chrono::milliseconds, Tag>;

template <typename Tag>
using Microseconds = Duration<std::chrono::microseconds, Tag>;

template <typename Tag>
using Nanoseconds = Duration<std::chrono::nanoseconds, Tag>;

using Uptime = Nanoseconds<struct UptimeTag_>;

Uptime get_uptime();

}//namespace TimeUnit

#endif//TIME_UNIT_HH_AA862C0A2A13AEFBE6D015A289BED606
