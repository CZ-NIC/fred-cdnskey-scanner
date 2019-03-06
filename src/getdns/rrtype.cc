/*
 * Copyright (C) 2017-2018  CZ.NIC, z. s. p. o.
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
#include "src/getdns/rrtype.hh"

#include <getdns/getdns.h>

namespace GetDns {

namespace {

template <RrType, typename>
struct FromTo;

template <typename T>
struct FromTo<RrType::a, T>
{
    static const T value = GETDNS_RRTYPE_A;
};

template <typename T>
struct FromTo<RrType::aaaa, T>
{
    static const T value = GETDNS_RRTYPE_AAAA;
};

template <typename T>
struct FromTo<RrType::cdnskey, T>
{
    static const T value = GETDNS_RRTYPE_CDNSKEY;
};

}//namespace GetDns::{anonymous}

template <RrType type>
    template <typename T>
    T From<type>::to()
{
    return FromTo<type, T>::value;
}

template int From<RrType::a>::to<int>();
template int From<RrType::aaaa>::to<int>();
template int From<RrType::cdnskey>::to<int>();

}//namespace GetDns
