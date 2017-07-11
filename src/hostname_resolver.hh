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

#ifndef HOSTNAME_RESOLVER_HH_0C273EEF65B9F6F9FD6A9F48B3CE9AA5//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define HOSTNAME_RESOLVER_HH_0C273EEF65B9F6F9FD6A9F48B3CE9AA5

#include "src/time_unit.hh"

#include "src/getdns/transport.hh"

#include <map>
#include <set>
#include <string>

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>

class HostnameResolver
{
public:
    typedef std::map< std::string, std::set<boost::asio::ip::address> > Result;
    static Result get_result(
            const std::set<std::string>& _hostnames,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const std::list<boost::asio::ip::address>& _resolvers,
            const TimeUnit::Nanoseconds& _assigned_time_nsec);
private:
    class Query;
    class QueryGenerator;
    class ChildProcess;
};

#endif//HOSTNAME_RESOLVER_HH_0C273EEF65B9F6F9FD6A9F48B3CE9AA5
