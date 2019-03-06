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
#ifndef RRTYPE_HH_E166A7B8C8ACD76E10A65109C8AD1BFB//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define RRTYPE_HH_E166A7B8C8ACD76E10A65109C8AD1BFB

namespace GetDns
{

enum class RrType
{
    a,
    aaaa,
    cdnskey
};

template <RrType type>
struct From
{
    template <typename T>
    static T to();
};

}//namespace GetDns

#endif//RRTYPE_HH_E166A7B8C8ACD76E10A65109C8AD1BFB
