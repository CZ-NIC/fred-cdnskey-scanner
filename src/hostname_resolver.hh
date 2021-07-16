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

#ifndef HOSTNAME_RESOLVER_HH_0C273EEF65B9F6F9FD6A9F48B3CE9AA5//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define HOSTNAME_RESOLVER_HH_0C273EEF65B9F6F9FD6A9F48B3CE9AA5

#include "src/getdns/context.hh"

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <list>
#include <map>
#include <set>
#include <string>

struct HostnameResolver
{
    using Result = std::map<std::string, std::set<boost::asio::ip::address>>;
    static Result get_result(
            const std::set<std::string>& hostnames,
            GetDns::Context::Timeout query_timeout,
            const std::list<boost::asio::ip::address>& resolvers,
            std::chrono::nanoseconds assigned_time);
};

#endif//HOSTNAME_RESOLVER_HH_0C273EEF65B9F6F9FD6A9F48B3CE9AA5
