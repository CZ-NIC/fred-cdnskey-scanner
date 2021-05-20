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

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"
#include "src/getdns/exception.hh"

#include <getdns/getdns_ext_libevent.h>

#include <algorithm>
#include <array>
#include <type_traits>
#include <vector>

namespace GetDns {

Context::Context(Context&& src)
    : ptr_{nullptr}
{
    std::swap(src.ptr_, ptr_);
}

Context& Context::operator=(Context&& src)
{
    std::swap(src.ptr_, ptr_);
    return *this;
}

namespace {

::getdns_context* create_context(int set_from_os)
{
    ::getdns_context* context_ptr = nullptr;
    MUST_BE_GOOD(::getdns_context_create(&context_ptr, set_from_os));
    return context_ptr;
}

}//namespace GetDns::{anonymous}

Context::Context(InitialSettings::FromOs)
    : Context{create_context(1)}
{ }

Context::Context(InitialSettings::None)
    : Context{create_context(0)}
{ }

Context::Context(::getdns_context* ptr)
    : ptr_{ptr}
{ }

Context::~Context()
{
    ::getdns_context_destroy(ptr_);
    ptr_ = nullptr;
}

Context& Context::set_dns_transport_list(std::size_t count, ::getdns_transport_list_t* transports)
{
    MUST_BE_GOOD(::getdns_context_set_dns_transport_list(ptr_, count, transports));
    return *this;
}

Context& Context::set_upstream_recursive_servers(const std::list<boost::asio::ip::address>& servers)
{
    if (!servers.empty())
    {
        ::getdns_list* getdns_list_ptr = nullptr;
        Data::List list{getdns_list_ptr = ::getdns_list_create()};
        for (auto&& address : servers)
        {
            Data::Dict item{[](::getdns_dict** ptr) { *ptr = ::getdns_dict_create(); }};
            if (address.is_v4())
            {
                const Data::BinData ipv4{"IPv4"};
                item.set("address_type", *ipv4);
                const auto bytes = address.to_v4().to_bytes();
                const Data::BinData address_data{reinterpret_cast<const void*>(bytes.data()), bytes.size()};
                item.set("address_data", *address_data);
            }
            else if (address.is_v6())
            {
                const Data::BinData ipv6{"IPv6"};
                item.set("address_type", *ipv6);
                const auto bytes = address.to_v6().to_bytes();
                const Data::BinData address_data{reinterpret_cast<const void*>(bytes.data()), bytes.size()};
                item.set("address_data", *address_data);
            }
            list.push_back(*item);
        }
        MUST_BE_GOOD(::getdns_context_set_upstream_recursive_servers(ptr_, getdns_list_ptr));
    }
    MUST_BE_GOOD(::getdns_context_set_resolution_type(ptr_, ::GETDNS_RESOLUTION_STUB));
    return *this;
}

Context& Context::set_follow_redirects(bool yes)
{
    MUST_BE_GOOD(::getdns_context_set_follow_redirects(ptr_, yes ? ::GETDNS_REDIRECTS_FOLLOW : ::GETDNS_REDIRECTS_DO_NOT_FOLLOW));
    return *this;
}

Context& Context::set_timeout(Timeout value)
{
    MUST_BE_GOOD(::getdns_context_set_timeout(ptr_, value.count()));
    return *this;
}

Context& Context::set_dnssec_trust_anchors(Data::TrustAnchorList anchors)
{
    MUST_BE_GOOD(::getdns_context_set_dnssec_trust_anchors(ptr_, anchors));
    return *this;
}

Context& Context::set_libevent_base(Event::Base& event_base)
{
    MUST_BE_GOOD(::getdns_extension_set_libevent_base(ptr_, event_base));
    return *this;
}

Context::operator ::getdns_context*()
{
    return ptr_;
}

}//namespace GetDns
