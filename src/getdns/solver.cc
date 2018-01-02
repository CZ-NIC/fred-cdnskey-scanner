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

#include "src/getdns/solver.hh"
#include "src/getdns/data.hh"
#include "src/getdns/exception.hh"

#include <iostream>

namespace GetDns
{

Solver::Solver()
{ }

Solver::~Solver()
{
}

::getdns_transaction_t Solver::add_request_for_address_resolving(
        const std::string& _hostname,
        const RequestPtr& _request,
        Extensions _extensions)
{
    _request->join(event_base_);
    const ::getdns_transaction_t transaction_id =
            _request->get_context().add_request_for_address_resolving(_hostname, this, getdns_callback_function, _extensions);
    active_requests_.insert(std::make_pair(transaction_id, _request));
    return transaction_id;
}

::getdns_transaction_t Solver::add_request_for_cdnskey_resolving(
        const std::string& _domain,
        const RequestPtr& _request,
        Extensions _extensions)
{
    _request->join(event_base_);
    const ::getdns_transaction_t transaction_id =
            _request->get_context().add_request_for_cdnskey_resolving(_domain, this, getdns_callback_function, _extensions);
    active_requests_.insert(std::make_pair(transaction_id, _request));
    return transaction_id;
}

void Solver::do_one_step()
{
    const Event::Base::Result loop_status = event_base_.loop();
    switch (loop_status)
    {
    case Event::Base::Result::success:
    case Event::Base::Result::no_events:
        return;
    }
    struct UnexpectedResult:Exception
    {
        const char* what()const noexcept override { return "event_base_loop returned unexpected value"; }
    };
    throw UnexpectedResult();
}

std::size_t Solver::get_number_of_unresolved_requests()const
{
    return active_requests_.size();
}

Solver::ListOfRequestPtr Solver::pop_finished_requests()
{
    const ListOfRequestPtr result = finished_requests_;
    finished_requests_.clear();
    return result;
}

Event::Base& Solver::get_event_base()
{
    return event_base_;
}

void Solver::getdns_callback_function(
        ::getdns_context*,
        ::getdns_callback_type_t _callback_type,
        ::getdns_dict* _response,
        void* _user_data_ptr,
        ::getdns_transaction_t _transaction_id)
{
    try
    {
        const Data::Dict answer(_response);
        Solver* const solver_instance_ptr = reinterpret_cast<Solver*>(_user_data_ptr);
        const RequestId::iterator request_itr = solver_instance_ptr->active_requests_.find(_transaction_id);
        if (request_itr == solver_instance_ptr->active_requests_.end())
        {
            return;
        }

        try
        {
            switch (_callback_type)
            {
                case GETDNS_CALLBACK_CANCEL:
                    request_itr->second->on_cancel(_transaction_id);
                    break;
                case GETDNS_CALLBACK_TIMEOUT:
                    request_itr->second->on_timeout(_transaction_id);
                    break;
                case GETDNS_CALLBACK_ERROR:
                    request_itr->second->on_error(_transaction_id);
                    break;
                case GETDNS_CALLBACK_COMPLETE:
                    request_itr->second->on_complete(answer, _transaction_id);
                    break;
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "std::exception caught: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "unexpected exception caught" << std::endl;
        }
        solver_instance_ptr->finished_requests_.push_back(request_itr->second);
        solver_instance_ptr->active_requests_.erase(request_itr);
    }
    catch (const std::exception& e)
    {
        std::cerr << "std::exception caught: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "unexpected exception caught" << std::endl;
    }
}

}//namespace GetDns
