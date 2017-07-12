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

#ifndef INSECURE_CDNSKEY_RESOLVER_HH_E7501EBD49F1AFA724581AA72FFD4314//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define INSECURE_CDNSKEY_RESOLVER_HH_E7501EBD49F1AFA724581AA72FFD4314

#include "src/time_unit.hh"

#include "src/getdns/transport.hh"

#include <string>
#include <set>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>

struct Insecure
{
    std::string domain;
    std::set<std::string> nameservers;
    boost::asio::ip::address address;
};

typedef std::vector<Insecure> VectorOfInsecures;

struct InsecureCdnskeyResolver
{
    static void resolve(
            const VectorOfInsecures& _to_resolve,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const TimeUnit::Nanoseconds& _assigned_time_nsec);
};

#endif//INSECURE_CDNSKEY_RESOLVER_HH_E7501EBD49F1AFA724581AA72FFD4314
