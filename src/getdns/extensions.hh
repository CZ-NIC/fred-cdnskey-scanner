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

#ifndef EXTENSIONS_HH_8A409CA603281B3792E1A4F3BF9CD68C//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define EXTENSIONS_HH_8A409CA603281B3792E1A4F3BF9CD68C

#include "src/getdns/data.hh"

namespace GetDns
{

struct Extensions
{
    Extensions();
    Data::Dict into_dictionary()const;
    bool dnssec_return_status:1;
    bool dnssec_return_only_secure:1;
    bool dnssec_return_validation_chain:1;
    bool return_both_v4_and_v6:1;
    bool add_warning_for_bad_dns:1;
    bool return_call_reporting:1;
};

}//namespace GetDns

#endif//EXTENSIONS_HH_8A409CA603281B3792E1A4F3BF9CD68C
