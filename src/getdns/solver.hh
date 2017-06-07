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

#ifndef SOLVER_HH_3439EE166EAD8E6EF02E3D57784D4800//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define SOLVER_HH_3439EE166EAD8E6EF02E3D57784D4800

#include "src/getdns/solver_fwd.hh"
#include "src/getdns/request.hh"
#include "src/getdns/transport.hh"
#include "src/getdns/extensions.hh"
#include "src/event/base.hh"

#include <getdns/getdns.h>

#include <map>
#include <list>
#include <string>

#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>

namespace GetDns
{

typedef boost::shared_ptr<Request> RequestPtr;

class Solver
{
public:
    Solver();
    ~Solver();
    ::getdns_transaction_t add_request_for_address_resolving(
            const std::string& _hostname,
            const RequestPtr& _request,
            const boost::optional<TransportList>& _transport_list,
            Extensions _extensions);
    ::getdns_transaction_t add_request_for_cdnskey_resolving(
            const std::string& _domain,
            const RequestPtr& _request,
            const boost::optional<TransportList>& _transport_list,
            Extensions _extensions,
            const boost::asio::ip::address& _nameserver);
    void do_one_step();
    std::size_t get_number_of_unresolved_requests()const;
    typedef std::list<RequestPtr> ListOfRequestPtr;
    ListOfRequestPtr pop_finished_requests();
private:
    void clean_finished_requests();
    Event::Base event_base_;
    typedef std::map< ::getdns_transaction_t, RequestPtr > RequestId;
    RequestId active_requests_;
    ListOfRequestPtr finished_requests_;
    static void getdns_callback_function(
            ::getdns_context*,
            ::getdns_callback_type_t,
            ::getdns_dict*,
            void*,
            ::getdns_transaction_t);
};

}//namespace GetDns

#endif//SOLVER_HH_3439EE166EAD8E6EF02E3D57784D4800
