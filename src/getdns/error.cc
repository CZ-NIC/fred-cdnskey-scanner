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

#include "src/getdns/error.hh"

#include <getdns/getdns_extra.h>

namespace GetDns
{

Error::Error(getdns_return_t _error_code)
    : error_code_(_error_code)
{ }

const char* Error::what()const throw()
{
    const char* const error_str = getdns_get_errorstr_by_id(static_cast<uint16_t>(error_code_));
    return error_str != NULL ? error_str : "Unknown error";
}

}//namespace GetDns
