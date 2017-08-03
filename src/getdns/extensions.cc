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

#include "src/getdns/extensions.hh"

namespace GetDns
{

Extensions::Extensions()
    : dnssec_return_status(false),
      dnssec_return_only_secure(false),
      dnssec_return_validation_chain(false),
      return_both_v4_and_v6(false),
      add_warning_for_bad_dns(false),
      return_call_reporting(false)
{
}

Data::Dict Extensions::into_dictionary()const
{
    Data::Dict retval;
    if (dnssec_return_status)
    {
        Data::set_item_of(retval, "dnssec_return_status", static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    }
    if (dnssec_return_only_secure)
    {
        Data::set_item_of(retval, "dnssec_return_only_secure", static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    }
    if (dnssec_return_validation_chain)
    {
        Data::set_item_of(retval, "dnssec_return_validation_chain", static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    }
    if (return_both_v4_and_v6)
    {
        Data::set_item_of(retval, "return_both_v4_and_v6", static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    }
    if (add_warning_for_bad_dns)
    {
        Data::set_item_of(retval, "add_warning_for_bad_dns", static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    }
    if (return_call_reporting)
    {
        Data::set_item_of(retval, "return_call_reporting", static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    }
    return retval;
}

}//namespace GetDns
