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

#ifndef CONTEXT_HH_0C2292206DE22FFE81940C3E7D4DE456//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define CONTEXT_HH_0C2292206DE22FFE81940C3E7D4DE456

#include "src/event/base.hh"
#include "src/getdns/data.hh"
#include "src/getdns/transport.hh"
#include "src/getdns/extensions.hh"

#include <getdns/getdns.h>

#include <list>
#include <string>

#include <boost/asio/ip/address.hpp>

namespace GetDns
{

class Context
{
public:
    struct InitialSettings
    {
        enum Enum
        {
            none,
            from_os,
        };
    };
    Context(Event::Base& _event_base, InitialSettings::Enum _initial_settings);
    ~Context();
    ::getdns_transaction_t add_request_for_address_resolving(
            const std::string& _hostname,
            void* _user_data_ptr,
            ::getdns_callback_t _on_event,
            Extensions _extensions);
    ::getdns_transaction_t add_request_for_cdnskey_resolving(
            const std::string& _domain,
            void* _user_data_ptr,
            ::getdns_callback_t _on_event,
            Extensions _extensions);
    Context& set_dns_transport_list(const TransportList& _transport_list);
    Context& set_upstream_recursive_servers(const std::list<boost::asio::ip::address>& _servers);
    Context& set_follow_redirects(bool _yes);
    Context& set_timeout(std::uint64_t _value_ms);
    Context& set_dnssec_trust_anchors(const std::list<Data::TrustAnchor>& _anchors);
    ::getdns_context* release_context();
private:
    struct FreeOnExit
    {
        FreeOnExit(InitialSettings::Enum _initial_settings);
        ~FreeOnExit();
        ::getdns_context* context_ptr;
    } free_on_exit_;
};

}//namespace GetDns

#endif//CONTEXT_HH_0C2292206DE22FFE81940C3E7D4DE456
