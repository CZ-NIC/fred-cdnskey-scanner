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

#include "src/getdns/extensions_set.hh"


namespace GetDns {

template <>
const char* extension_name<Extension::AddOptParameters>() noexcept
{
    return "add_opt_parameters";
}

template <>
const char* extension_name<Extension::AddWarningForBadDns>() noexcept
{
    return "add_warning_for_bad_dns";
}

template <>
const char* extension_name<Extension::DnssecReturnOnlySecure>() noexcept
{
    return "dnssec_return_only_secure";
}

template <>
const char* extension_name<Extension::DnssecReturnStatus>() noexcept
{
    return "dnssec_return_status";
}

template <>
const char* extension_name<Extension::DnssecReturnValidationChain>() noexcept
{
    return "dnssec_return_validation_chain";
}

template <>
const char* extension_name<Extension::ReturnBothV4AndV6>() noexcept
{
    return "return_both_v4_and_v6";
}

template <>
const char* extension_name<Extension::ReturnCallReporting>() noexcept
{
    return "return_call_reporting";
}

template <>
const char* extension_name<Extension::SpecifyClass>() noexcept
{
    return "specify_class";
}

}//namespace GetDns
