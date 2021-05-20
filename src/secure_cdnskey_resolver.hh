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

#ifndef SECURE_CDNSKEY_RESOLVER_HH_FFBD7215A0403402C6A3E7BDD107973D//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define SECURE_CDNSKEY_RESOLVER_HH_FFBD7215A0403402C6A3E7BDD107973D

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <list>
#include <string>
#include <set>


using Domains = std::set<std::string>;

struct SecureCdnskeyResolver
{
    static void resolve(
            const Domains& to_resolve,
            GetDns::Context::Timeout query_timeout,
            const std::list<boost::asio::ip::address>& resolvers,
            GetDns::Data::TrustAnchorList trust_anchors,
            std::chrono::nanoseconds assigned_time);
};

#endif//SECURE_CDNSKEY_RESOLVER_HH_FFBD7215A0403402C6A3E7BDD107973D
