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

#ifndef REQUEST_HH_0B8A434704E299D520248E7FE40604DF//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define REQUEST_HH_0B8A434704E299D520248E7FE40604DF

#include "src/event/base.hh"

#include "src/getdns/data.hh"
#include "src/getdns/context.hh"

#include <getdns/getdns.h>

namespace GetDns
{

class Request
{
public:
    virtual ~Request() { }
    virtual Context& get_context() = 0;
    virtual void join(Event::Base& _event_base) = 0;
    virtual void on_complete(const Data::Dict& _answer, ::getdns_transaction_t _transaction_id) = 0;
    virtual void on_cancel(::getdns_transaction_t _transaction_id) = 0;
    virtual void on_timeout(::getdns_transaction_t _transaction_id) = 0;
    virtual void on_error(::getdns_transaction_t _transaction_id) = 0;
    virtual ::getdns_transaction_t get_request_id()const = 0;
};

}//namespace GetDns

#endif//REQUEST_HH_0B8A434704E299D520248E7FE40604DF
