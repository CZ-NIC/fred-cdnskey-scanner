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

#ifndef TRANSPORT_HH_7C85D5BE63ECB56E0176E62068801E57//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define TRANSPORT_HH_7C85D5BE63ECB56E0176E62068801E57

#include "src/util/is_unique.hh"

#include <getdns/getdns.h>

#include <array>


namespace GetDns {

struct TransportProtocol
{
    template <typename> struct Item;
    using Udp = Item<struct Udp_>;
    using Tcp = Item<struct Tcp_>;
    using Tls = Item<struct Tls_>;
};

template <typename...> struct TransportsList;

template <typename ...Ts>
struct TransportsList<TransportProtocol::Item<Ts>...>
{
    static_assert(Util::IsUnique<Ts...>::value);
};

template <typename> constexpr ::getdns_transport_list_t to_transport_protocol() noexcept;
template <> constexpr ::getdns_transport_list_t to_transport_protocol<TransportProtocol::Udp>() noexcept { return ::GETDNS_TRANSPORT_UDP; }
template <> constexpr ::getdns_transport_list_t to_transport_protocol<TransportProtocol::Tcp>() noexcept { return ::GETDNS_TRANSPORT_TCP; }
template <> constexpr ::getdns_transport_list_t to_transport_protocol<TransportProtocol::Tls>() noexcept { return ::GETDNS_TRANSPORT_TLS; }


template <typename ...Ts>
decltype(auto) make_transports_list(TransportsList<TransportProtocol::Item<Ts>...>)
{
    return std::array<::getdns_transport_list_t, sizeof...(Ts)>{to_transport_protocol<TransportProtocol::Item<Ts>>()...};
}

}//namespace GetDns

#endif//TRANSPORT_HH_7C85D5BE63ECB56E0176E62068801E57
