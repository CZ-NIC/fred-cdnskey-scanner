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

#ifndef CONTEXT_HH_0C2292206DE22FFE81940C3E7D4DE456//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define CONTEXT_HH_0C2292206DE22FFE81940C3E7D4DE456

#include "src/getdns/data.hh"
#include "src/getdns/transport.hh"
#include "src/getdns/extensions_set.hh"

#include "src/event/base.hh"

#include "src/time_unit.hh"

#include <getdns/getdns.h>

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <list>
#include <string>


namespace GetDns {

class Context
{
public:
    Context(Context&& src);
    Context(const Context&) = delete;
    Context& operator=(Context&& src);
    Context& operator=(const Context&) = delete;
    struct InitialSettings
    {
        template <typename T> struct Item { };
        using None = Item<struct None_>;
        using FromOs = Item<struct FromOs_>;
    };
    explicit Context(InitialSettings::FromOs);
    explicit Context(InitialSettings::None);
    explicit Context(::getdns_context* ptr);
    ~Context();
    template <typename ...Ts>
    Context& set_dns_transport_list(TransportsList<Ts...> transport_list);
    Context& set_upstream_recursive_servers(const std::list<boost::asio::ip::address>& servers);
    Context& set_follow_redirects(bool yes);
    using Timeout = TimeUnit::Milliseconds<struct TimeoutTag_>;
    Context& set_timeout(Timeout value);
    Context& set_dnssec_trust_anchors(Data::TrustAnchorList anchors);
    Context& set_libevent_base(Event::Base& event_base);
    operator ::getdns_context*();
private:
    Context& set_dns_transport_list(std::size_t count, ::getdns_transport_list_t* transports);
    ::getdns_context* ptr_;
};

template <typename ...Ts>
Context& Context::set_dns_transport_list(TransportsList<Ts...> protocols)
{
    auto transport_list = make_transports_list(protocols);
    return this->set_dns_transport_list(transport_list.size(), transport_list.data());
}

}//namespace GetDns

#endif//CONTEXT_HH_0C2292206DE22FFE81940C3E7D4DE456
