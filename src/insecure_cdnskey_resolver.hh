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

#ifndef INSECURE_CDNSKEY_RESOLVER_HH_E7501EBD49F1AFA724581AA72FFD4314//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define INSECURE_CDNSKEY_RESOLVER_HH_E7501EBD49F1AFA724581AA72FFD4314


#include "src/getdns/context.hh"

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <set>
#include <string>
#include <vector>

struct Insecure
{
    std::string domain;
    std::set<std::string> nameservers;
    boost::asio::ip::address address;
};

using VectorOfInsecures = std::vector<Insecure>;

struct InsecureCdnskeyResolver
{
    static void resolve(
            const VectorOfInsecures& to_resolve,
            GetDns::Context::Timeout query_timeout,
            std::chrono::nanoseconds assigned_time);
};

#endif//INSECURE_CDNSKEY_RESOLVER_HH_E7501EBD49F1AFA724581AA72FFD4314
