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

#include "src/time_unit.hh"

#include <iomanip>
#include <iostream>
#include <sstream>


namespace TimeUnit {

Uptime get_uptime()
{
    return Uptime{std::chrono::steady_clock::now().time_since_epoch()};
}

template <>
std::ostream& operator<<<std::chrono::seconds::rep, std::chrono::seconds::period>(std::ostream& out, const std::chrono::seconds& t)
{
    const auto today = t.count() % std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours{24}).count();
    const auto hours = today / std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours{1}).count();
    const auto minutes = (today / std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes{1}).count()) % 60;
    const auto seconds = today % 60;
    std::ostringstream o;
    o << std::setw(2) << std::setfill(' ') << std::right << hours << ":"
      << std::setw(2) << std::setfill('0') << std::right << minutes << ":"
      << std::setw(2) << std::setfill('0') << std::right << seconds;
    return out << o.str();
}

template <>
std::ostream& operator<<<std::chrono::milliseconds::rep, std::chrono::milliseconds::period>(std::ostream& out, const std::chrono::milliseconds& t)
{
    const auto today = t.count() % std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours{24}).count();
    const auto hours = today / std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours{1}).count();
    const auto minutes = (today / std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::minutes{1}).count()) % 60;
    const auto seconds = (today / std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds{1}).count()) % 60;
    const auto milliseconds = today % std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds{1}).count();
    std::ostringstream o;
    o << std::setw(2) << std::setfill(' ') << std::right << hours << ":"
      << std::setw(2) << std::setfill('0') << std::right << minutes << ":"
      << std::setw(2) << std::setfill('0') << std::right << seconds << "."
      << std::setw(3) << std::setfill('0') << std::right << milliseconds;
    return out << o.str();
}

template <>
std::ostream& operator<<<std::chrono::microseconds::rep, std::chrono::microseconds::period>(std::ostream& out, const std::chrono::microseconds& t)
{
    const auto today = t.count() % std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::hours{24}).count();
    const auto hours = today / std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::hours{1}).count();
    const auto minutes = (today / std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::minutes{1}).count()) % 60;
    const auto seconds = (today / std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds{1}).count()) % 60;
    const auto microseconds = today % std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds{1}).count();
    std::ostringstream o;
    o << std::setw(2) << std::setfill(' ') << std::right << hours << ":"
      << std::setw(2) << std::setfill('0') << std::right << minutes << ":"
      << std::setw(2) << std::setfill('0') << std::right << seconds << "."
      << std::setw(6) << std::setfill('0') << std::right << microseconds;
    return out << o.str();
}

template <>
std::ostream& operator<<<std::chrono::nanoseconds::rep, std::chrono::nanoseconds::period>(std::ostream& out, const std::chrono::nanoseconds& t)
{
    const auto today = t.count() % std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::hours{24}).count();
    const auto hours = today / std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::hours{1}).count();
    const auto minutes = (today / std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::minutes{1}).count()) % 60;
    const auto seconds = (today / std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds{1}).count()) % 60;
    const auto nanoseconds = today % std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds{1}).count();
    std::ostringstream o;
    o << std::setw(2) << std::setfill(' ') << std::right << hours << ":"
      << std::setw(2) << std::setfill('0') << std::right << minutes << ":"
      << std::setw(2) << std::setfill('0') << std::right << seconds << "."
      << std::setw(9) << std::setfill('0') << std::right << nanoseconds;
    return out << o.str();
}

}//namespace TimeUnit
