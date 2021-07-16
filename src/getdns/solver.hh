/*
 * Copyright (C) 2017-2021  CZ.NIC, z. s. p. o.
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

#ifndef SOLVER_HH_3439EE166EAD8E6EF02E3D57784D4800//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define SOLVER_HH_3439EE166EAD8E6EF02E3D57784D4800

#include "src/event/base.hh"

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"

#include <boost/optional.hpp>

#include <getdns/getdns.h>

#include <iostream>
#include <list>
#include <map>
#include <utility>

namespace GetDns {

template <typename Query>
class Solver
{
public:
    explicit Solver() noexcept;
    ~Solver() = default;

    using ListOfQueries = std::list<Query>;

    ::getdns_transaction_t add_request(Query query);
    Solver& do_one_step();
    std::size_t get_number_of_unresolved_requests() const noexcept;
    ListOfQueries pop_finished_requests();
    Event::Base& get_event_base();
private:
    using QueryByTransactionId = std::map<::getdns_transaction_t, Query>;

    static void getdns_callback_function(
            ::getdns_context*,
            ::getdns_callback_type_t,
            ::getdns_dict*,
            void*,
            ::getdns_transaction_t) noexcept;
    Event::Base event_base_;
    QueryByTransactionId active_requests_;
    ListOfQueries finished_requests_;
};

template <typename Query>
Solver<Query>::Solver() noexcept
    : event_base_{}
{ }

template <typename Query>
::getdns_transaction_t Solver<Query>::add_request(Query query)
{
    const auto transaction_id = query.start_transaction(event_base_, getdns_callback_function, this);
    active_requests_.insert(std::make_pair(transaction_id, std::move(query)));
    return transaction_id;
}

template <typename Query>
Solver<Query>& Solver<Query>::do_one_step()
{
    switch (event_base_(Event::Loop::Once{}))
    {
        case Event::Base::Result::success:
        case Event::Base::Result::no_events:
            return *this;
    }
    struct UnexpectedResult : Exception
    {
        const char* what()const noexcept override { return "event_base_loop returned unexpected value"; }
    };
    throw UnexpectedResult();
}

template <typename Query>
std::size_t Solver<Query>::get_number_of_unresolved_requests() const noexcept
{
    return active_requests_.size();
}

template <typename Query>
typename Solver<Query>::ListOfQueries Solver<Query>::pop_finished_requests()
{
    ListOfQueries result;
    std::swap(result, finished_requests_);
    return result;
}

template <typename Query>
Event::Base& Solver<Query>::get_event_base()
{
    return event_base_;
}

template <typename Query>
void Solver<Query>::getdns_callback_function(
        ::getdns_context*,
        ::getdns_callback_type_t callback_type,
        ::getdns_dict* response,
        void* user_data_ptr,
        ::getdns_transaction_t transaction_id) noexcept
{
    try
    {
        Data::Dict answer{response};
        Solver* const solver_instance_ptr = reinterpret_cast<Solver*>(user_data_ptr);
        const auto request_itr = solver_instance_ptr->active_requests_.find(transaction_id);
        if (request_itr == solver_instance_ptr->active_requests_.end())
        {
            std::cerr << "transaction " << transaction_id << " not found" << std::endl;
            return;
        }
        try
        {
            [](::getdns_callback_type_t callback_type, ::getdns_dict* response, Query& query, ::getdns_transaction_t transaction_id)
            {
                switch (callback_type)
                {
                    case ::GETDNS_CALLBACK_CANCEL:
                        query.on_cancel(transaction_id);
                        return;
                    case ::GETDNS_CALLBACK_TIMEOUT:
                        query.on_timeout(transaction_id);
                        return;
                    case ::GETDNS_CALLBACK_ERROR:
                        query.on_error(transaction_id);
                        return;
                    case ::GETDNS_CALLBACK_COMPLETE:
                        query.on_complete(Data::DictRef{response}, transaction_id);
                        return;
                }
                struct UnexpectedCallbackType : Exception
                {
                    const char* what() const noexcept override { return "unexpected callback type"; }
                };
                throw UnexpectedCallbackType{};
            }(callback_type, response, request_itr->second, transaction_id);
        }
        catch (const std::exception& e)
        {
            std::cerr << "std::exception caught: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "unexpected exception caught" << std::endl;
        }
        solver_instance_ptr->finished_requests_.push_back(std::move(request_itr->second));
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

#endif//SOLVER_HH_3439EE166EAD8E6EF02E3D57784D4800
