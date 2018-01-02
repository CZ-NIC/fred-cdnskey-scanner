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

#ifndef TIME_UNIT_HH_AA862C0A2A13AEFBE6D015A289BED606//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define TIME_UNIT_HH_AA862C0A2A13AEFBE6D015A289BED606

#include <cstdint>
#include <ctime>

namespace TimeUnit {

struct Seconds
{
    explicit Seconds(std::int64_t sec):value(sec) { }
    std::int64_t value;
};

struct Nanoseconds
{
    explicit Nanoseconds(std::int64_t nsec):value(nsec) { }
    explicit Nanoseconds(const Seconds& sec);
    std::int64_t value;
};

struct ::timespec get_clock_monotonic();

}//namespace TimeUnit

TimeUnit::Nanoseconds operator-(const struct ::timespec& a, const struct ::timespec& b);

struct ::timespec operator+(const struct ::timespec& a, const TimeUnit::Seconds& b);

struct ::timespec operator+(const struct ::timespec& a, const TimeUnit::Nanoseconds& b);

#endif//TIME_UNIT_HH_AA862C0A2A13AEFBE6D015A289BED606
