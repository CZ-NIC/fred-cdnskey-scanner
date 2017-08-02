/*
 * Copyright (C) 2017  CZ.NIC, z.s.p.o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "src/time_unit.hh"

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace {

const long long nsecs_in_one_second = 1000000000LL;

}//namespace {anonymous}

namespace TimeUnit {

struct ::timespec get_clock_monotonic()
{
    struct ::timespec t;
    const int retval = ::clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    const int success = 0;
    if (retval == success)
    {
        return t;
    }
    const int c_errno = errno;
    struct ClockGetTimeFailure:std::runtime_error
    {
        ClockGetTimeFailure(const char* _desc):std::runtime_error(_desc) { }
    };
    throw ClockGetTimeFailure(std::strerror(c_errno));
}

Nanoseconds::Nanoseconds(const Seconds& sec)
    : value(nsecs_in_one_second * sec.value)
{ }

}//namespace TimeUnit

TimeUnit::Nanoseconds operator-(const struct ::timespec& a, const struct ::timespec& b)
{
    return TimeUnit::Nanoseconds((nsecs_in_one_second * (a.tv_sec - b.tv_sec)) + a.tv_nsec - b.tv_nsec);
}

struct ::timespec operator+(const struct ::timespec& a, const TimeUnit::Seconds& b)
{
    struct ::timespec sum;
    sum.tv_sec = a.tv_sec + b.value;
    sum.tv_nsec = a.tv_nsec;
    return sum;
}

struct ::timespec operator+(const struct ::timespec& a, const TimeUnit::Nanoseconds& b)
{
    struct ::timespec sum;
    sum.tv_sec = a.tv_sec + (b.value / nsecs_in_one_second);
    sum.tv_nsec = a.tv_nsec + (b.value % nsecs_in_one_second);
    if (nsecs_in_one_second <= sum.tv_nsec)
    {
        sum.tv_sec += 1;
        sum.tv_nsec -= nsecs_in_one_second;
    }
    return sum;
}

