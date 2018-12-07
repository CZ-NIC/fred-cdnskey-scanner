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
#include "src/getdns/error.hh"

#include <getdns/getdns_extra.h>

#include <cstdint>
#include <sstream>

namespace GetDns {

namespace {

std::string to_msg(::getdns_return_t error_code, const char* file, int line)
{
    std::ostringstream msg;
    msg << "at " << file << ":" << line << " occurred ";
    auto const error_str = ::getdns_get_errorstr_by_id(static_cast<std::uint16_t>(error_code));
    return msg.str() + (error_str != nullptr ? error_str : "Unknown error");
}

}

Error::Error(::getdns_return_t _error_code, const char* _file, int _line)
    : msg_(to_msg(_error_code, _file, _line))
{ }

const char* Error::what()const noexcept
{
    return msg_.c_str();
}

}//namespace GetDns
