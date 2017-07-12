/*
 * Copyright (C) 2017  CZ.NIC, z.s.p.o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SECURE_CDNSKEY_RESOLVER_HH_FFBD7215A0403402C6A3E7BDD107973D//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define SECURE_CDNSKEY_RESOLVER_HH_FFBD7215A0403402C6A3E7BDD107973D

#include "src/time_unit.hh"

#include "src/getdns/data.hh"
#include "src/getdns/transport.hh"

#include <string>
#include <set>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>

typedef std::set<std::string> Domains;

class SecureCdnskeyResolver
{
public:
    static void resolve(
            const Domains& _to_resolve,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const std::list<boost::asio::ip::address>& _resolvers,
            const std::list<GetDns::Data::TrustAnchor>& _trust_anchors,
            const TimeUnit::Nanoseconds& _assigned_time_nsec);
private:
    class Query;
};

#endif//SECURE_CDNSKEY_RESOLVER_HH_FFBD7215A0403402C6A3E7BDD107973D
