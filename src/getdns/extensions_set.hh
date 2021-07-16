/*
 * Copyright (C) 2021  CZ.NIC, z. s. p. o.
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

#ifndef EXTENSIONS_SET_HH_8A409CA603281B3792E1A4F3BF9CD68C//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define EXTENSIONS_SET_HH_8A409CA603281B3792E1A4F3BF9CD68C

#include "src/getdns/data.hh"

#include "src/util/is_unique.hh"


namespace GetDns {

struct Extension
{
    template <typename> struct Item;
    using DnssecReturnStatus = Item<struct DnssecReturnStatus_>;
    using DnssecReturnOnlySecure = Item<struct DnssecReturnOnlySecure_>;
    using DnssecReturnValidationChain = Item<struct DnssecReturnValidationChain_>;
    using ReturnBothV4AndV6 = Item<struct ReturnBothV4AndV6_>;
    using AddOptParameters = Item<struct AddOptParameters_>;
    using AddWarningForBadDns = Item<struct AddWarningForBadDns_>;
    using SpecifyClass = Item<struct SpecifyClass_>;
    using ReturnCallReporting = Item<struct ReturnCallReporting_>;
};

template <typename...> struct ExtensionsSet;

template <typename ...Es>
struct ExtensionsSet<Extension::Item<Es>...>
{
    static_assert(Util::IsUnique<Es...>::value);
};

template <typename E>
const char* extension_name() noexcept;

template <> const char* extension_name<Extension::AddOptParameters>() noexcept;
template <> const char* extension_name<Extension::AddWarningForBadDns>() noexcept;
template <> const char* extension_name<Extension::DnssecReturnOnlySecure>() noexcept;
template <> const char* extension_name<Extension::DnssecReturnStatus>() noexcept;
template <> const char* extension_name<Extension::DnssecReturnValidationChain>() noexcept;
template <> const char* extension_name<Extension::ReturnBothV4AndV6>() noexcept;
template <> const char* extension_name<Extension::ReturnCallReporting>() noexcept;
template <> const char* extension_name<Extension::SpecifyClass>() noexcept;

constexpr void add_extensions(const Data::Dict&, ExtensionsSet<>) { }

template <typename E, typename ...Es>
void add_extensions(Data::Dict& dict, ExtensionsSet<Extension::Item<E>, Extension::Item<Es>...>)
{
    dict.set(extension_name<Extension::Item<E>>(), *Data::Integer{GETDNS_EXTENSION_TRUE});
    add_extensions(dict, ExtensionsSet<Extension::Item<Es>...>{});
}

template <typename ...Es>
Data::Dict make_extensions(ExtensionsSet<Extension::Item<Es>...> extensions)
{
    Data::Dict dict{::getdns_dict_create()};
    add_extensions(dict, extensions);
    return dict;
}

}//namespace GetDns

#endif//EXTENSIONS_SET_HH_8A409CA603281B3792E1A4F3BF9CD68C
