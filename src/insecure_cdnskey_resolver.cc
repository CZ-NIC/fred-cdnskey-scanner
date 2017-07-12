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

#include "src/insecure_cdnskey_resolver.hh"
#include "src/time_unit.hh"

#include "src/getdns/data.hh"
#include "src/getdns/context.hh"
#include "src/getdns/request.hh"
#include "src/getdns/solver.hh"

#include <stdint.h>

#include <iostream>
#include <string>
#include <set>

namespace {

const int max_number_of_unresolved_queries = 200;

struct Cdnskey
{
    ::uint16_t flags;
    ::uint8_t protocol;
    ::uint8_t algorithm;
    std::string public_key;
    friend std::ostream& operator<<(std::ostream& out, const Cdnskey& value)
    {
        out << ::uint32_t(value.flags)
            << " " << ::uint32_t(value.protocol)
            << " " << ::uint32_t(value.algorithm)
            << " " << GetDns::Data::base64_encode(value.public_key);
        return out;
    }
};

typedef std::set<std::string> Nameservers;

}//namespace {anonymous}

class InsecureCdnskeyResolver::Query:public GetDns::Request
{
public:
    Query(const Insecure& _task,
          const TimeUnit::Seconds& _timeout_sec,
          const boost::optional<GetDns::TransportList>& _transport_list,
          const boost::asio::ip::address& _nameserver)
        : task_(_task),
          timeout_sec_(_timeout_sec),
          transport_list_(_transport_list),
          nameserver_(_nameserver),
          context_ptr_(NULL),
          status_(Status::none)
    { }
    ~Query()
    {
        if (context_ptr_ != NULL)
        {
            delete context_ptr_;
            context_ptr_ = NULL;
        }
    }
    struct Status
    {
        enum Enum
        {
            none,
            in_progress,
            completed,
            cancelled,
            timed_out,
            failed
        };
    };
    Status::Enum get_status()const
    {
        return status_;
    }
    typedef std::vector<Cdnskey> Result;
    const Result& get_result()const
    {
        if (this->get_status() == Status::completed)
        {
            return result_;
        }
        struct NoResultAvailable:std::runtime_error
        {
            NoResultAvailable():std::runtime_error("Request is not completed yet") { }
        };
        throw NoResultAvailable();
    }
    const Insecure& get_task()const
    {
        return task_;
    }
private:
    GetDns::Context& get_context()
    {
        if (context_ptr_ != NULL)
        {
            return *context_ptr_;
        }
        struct NullDereferenceException:std::runtime_error
        {
            NullDereferenceException():std::runtime_error("Dereferenced context_ptr_ is NULL") { }
        };
        throw NullDereferenceException();
    }
    void join(Event::Base& _event_base)
    {
        if (context_ptr_ != NULL)
        {
            delete context_ptr_;
            context_ptr_ = NULL;
        }
        context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::none);
        context_ptr_->set_timeout(timeout_sec_.value * 1000);
        if (transport_list_)
        {
            context_ptr_->set_dns_transport_list(*transport_list_);
        }
        std::list<boost::asio::ip::address> nameservers;
        nameservers.push_back(nameserver_);
        context_ptr_->set_upstream_recursive_servers(nameservers);
        status_ = Status::in_progress;
    }
    void on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t)
    {
//        std::cerr << _answer << std::endl;
        status_ = Status::completed;
        result_.clear();
        const GetDns::Data::Value replies_tree = GetDns::Data::get<GetDns::Data::List>(_answer, "replies_tree");
        if (!GetDns::Data::Is(replies_tree).of<GetDns::Data::List>().type)
        {
            return;
        }
        const GetDns::Data::List replies = GetDns::Data::From(replies_tree).get_value_of<GetDns::Data::List>();
        for (std::size_t reply_idx = 0; reply_idx < replies.get_number_of_items(); ++reply_idx)
        {
            const GetDns::Data::Value reply_value = GetDns::Data::get<GetDns::Data::Dict>(replies, reply_idx);
            if (!GetDns::Data::Is(reply_value).of<GetDns::Data::Dict>().type)
            {
                continue;
            }
            const GetDns::Data::Dict reply = GetDns::Data::From(reply_value).get_value_of<GetDns::Data::Dict>();
    //        std::cout << "reply[" << reply_idx << "]:\n" << reply << std::endl;
            const GetDns::Data::Value answer_value = GetDns::Data::get<GetDns::Data::List>(reply, "answer");
            if (!GetDns::Data::Is(answer_value).of<GetDns::Data::List>().type)
            {
                continue;
            }
            const GetDns::Data::List answers = GetDns::Data::From(answer_value).get_value_of<GetDns::Data::List>();
            for (std::size_t answer_idx = 0; answer_idx < answers.get_number_of_items(); ++answer_idx)
            {
                const GetDns::Data::Value answer_value = GetDns::Data::get<GetDns::Data::Dict>(answers, answer_idx);
                if (!GetDns::Data::Is(answer_value).of<GetDns::Data::Dict>().type)
                {
                    continue;
                }
                const GetDns::Data::Dict answer = GetDns::Data::From(answer_value).get_value_of<GetDns::Data::Dict>();
                const GetDns::Data::Value rdata_value = GetDns::Data::get<GetDns::Data::Dict>(answer, "rdata");
                if (!GetDns::Data::Is(rdata_value).of<GetDns::Data::Dict>().type)
                {
                    continue;
                }
                const GetDns::Data::Dict rdata = GetDns::Data::From(rdata_value).get_value_of<GetDns::Data::Dict>();

                Cdnskey cdnskey;
                {
                    const GetDns::Data::Value algorithm_value = GetDns::Data::get< ::uint32_t >(rdata, "algorithm");
                    if (!GetDns::Data::Is(algorithm_value).of< ::uint32_t >().type)
                    {
                        continue;
                    }
                    cdnskey.algorithm = GetDns::Data::From(algorithm_value).get_value_of< ::uint32_t >();
                }
                {
                    const GetDns::Data::Value flags_value = GetDns::Data::get< ::uint32_t >(rdata, "flags");
                    if (!GetDns::Data::Is(flags_value).of< ::uint32_t >().type)
                    {
                        continue;
                    }
                    cdnskey.flags = GetDns::Data::From(flags_value).get_value_of< ::uint32_t >();
                }
                {
                    const GetDns::Data::Value protocol_value = GetDns::Data::get< ::uint32_t >(rdata, "protocol");
                    if (!GetDns::Data::Is(protocol_value).of< ::uint32_t >().type)
                    {
                        continue;
                    }
                    cdnskey.protocol = GetDns::Data::From(protocol_value).get_value_of< ::uint32_t >();
                }
                {
                    const GetDns::Data::Value public_key_value = GetDns::Data::get<std::string>(rdata, "public_key");
                    if (!GetDns::Data::Is(public_key_value).of<std::string>().type)
                    {
                        continue;
                    }
                    cdnskey.public_key = GetDns::Data::From(public_key_value).get_value_of<std::string>();
                }
                result_.push_back(cdnskey);
            }
        }
    }
    void on_cancel(::getdns_transaction_t)
    {
        status_ = Status::cancelled;
    }
    void on_timeout(::getdns_transaction_t)
    {
        status_ = Status::timed_out;
    }
    void on_error(::getdns_transaction_t)
    {
        status_ = Status::failed;
    }
    const Insecure task_;
    const TimeUnit::Seconds timeout_sec_;
    const boost::optional<GetDns::TransportList> transport_list_;
    const boost::asio::ip::address nameserver_;
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
};

void InsecureCdnskeyResolver::resolve(
        const VectorOfInsecures& _to_resolve,
        const TimeUnit::Seconds& _query_timeout_sec,
        const boost::optional<GetDns::TransportList>& _transport_list,
        const TimeUnit::Nanoseconds& _assigned_time_nsec)
{
    if (_to_resolve.empty())
    {
        return;
    }
    GetDns::Solver solver;
    class Timer:public Event::Timeout
    {
    public:
        Timer(GetDns::Solver& _solver,
              const VectorOfInsecures& _to_resolve,
              const TimeUnit::Seconds& _query_timeout_sec,
              const boost::optional<GetDns::TransportList>& _transport_list,
              const TimeUnit::Nanoseconds& _assigned_time_nsec)
            : Event::Timeout(_solver.get_event_base()),
              solver_(_solver),
              to_resolve_(_to_resolve),
              item_to_resolve_ptr_(_to_resolve.begin()),
              remaining_queries_(_to_resolve.size()),
              query_timeout_sec_(_query_timeout_sec),
              transport_list_(_transport_list),
              time_end_(TimeUnit::get_clock_monotonic() + _assigned_time_nsec)
        {
            this->Timeout::set(0);
            while (0 < (remaining_queries_ + solver_.get_number_of_unresolved_requests()))
            {
                _solver.do_one_step();
                const GetDns::Solver::ListOfRequestPtr finished_requests = solver_.pop_finished_requests();
                for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                     request_ptr_itr != finished_requests.end(); ++request_ptr_itr)
                {
                    const GetDns::Request* const request_ptr = request_ptr_itr->get();
                    const Query* const query_ptr = dynamic_cast<const Query*>(request_ptr);
                    if (query_ptr != NULL)
                    {
                        const Insecure to_resolve = query_ptr->get_task();
                        const Nameservers& nameservers = to_resolve.query.nameservers;
                        if (query_ptr->get_status() == Query::Status::completed)
                        {
                            const Query::Result result = query_ptr->get_result();
                            if (result.empty())
                            {
                                for (Nameservers::const_iterator nameserver_itr = nameservers.begin();
                                     nameserver_itr != nameservers.end(); ++nameserver_itr)
                                {
                                    std::cout << "insecure-empty " << *nameserver_itr << " "
                                              << to_resolve.answer.address << " "
                                              << to_resolve.query.domain << std::endl;
                                }
                            }
                            else
                            {
                                for (Query::Result::const_iterator key_itr = result.begin(); key_itr != result.end(); ++key_itr)
                                {
                                    for (Nameservers::const_iterator nameserver_itr = nameservers.begin();
                                         nameserver_itr != nameservers.end(); ++nameserver_itr)
                                    {
                                        std::cout << "insecure " << *nameserver_itr << " "
                                                  << to_resolve.answer.address << " "
                                                  << to_resolve.query.domain << " "
                                                  << *key_itr << std::endl;
                                    }
                                }
                            }
                        }
                        else
                        {
                            for (Nameservers::const_iterator nameserver_itr = nameservers.begin();
                                 nameserver_itr != nameservers.end(); ++nameserver_itr)
                            {
                                std::cout << "unresolved " << *nameserver_itr << " "
                                          << to_resolve.answer.address << " "
                                          << to_resolve.query.domain << std::endl;
                            }
                        }
                    }
                }
                if (remaining_queries_ <= 0)
                {
                    this->Event::Timeout::remove();
                }
            }
            std::cerr << "insecure CDNSKEY records resolved" << std::endl;
        }
        ~Timer() { }
    private:
        Event::OnTimeout& on_timeout_occurrence()
        {
            if (solver_.get_number_of_unresolved_requests() < max_number_of_unresolved_queries)
            {
                GetDns::RequestPtr request_ptr(
                        new Query(*item_to_resolve_ptr_,
                                  query_timeout_sec_,
                                  transport_list_,
                                  item_to_resolve_ptr_->answer.address));
                solver_.add_request_for_cdnskey_resolving(
                        item_to_resolve_ptr_->query.domain,
                        request_ptr,
                        extensions_);
                this->set_time_of_next_query();
                if (item_to_resolve_ptr_ != to_resolve_.end())
                {
                    ++item_to_resolve_ptr_;
                    --remaining_queries_;
                }
            }
            else if (0 < remaining_queries_)
            {
                this->set_time_of_next_query();
            }
            return *this;
        }
        Timer& set_time_of_next_query()
        {
            const struct ::timespec now = TimeUnit::get_clock_monotonic();
            const TimeUnit::Nanoseconds remaining_time_nsec = time_end_ - now;
            if (remaining_time_nsec.value <= 0)
            {
                this->Timeout::set(0);
            }
            else
            {
                const ::uint64_t the_one_query_time_usec = remaining_time_nsec.value / (1000 * remaining_queries_);
                this->Timeout::set(the_one_query_time_usec);
            }
            return *this;
        }
        GetDns::Solver& solver_;
        const VectorOfInsecures& to_resolve_;
        VectorOfInsecures::const_iterator item_to_resolve_ptr_;
        std::size_t remaining_queries_;
        const TimeUnit::Seconds query_timeout_sec_;
        const boost::optional<GetDns::TransportList>& transport_list_;
        const struct ::timespec time_end_;
        GetDns::Extensions extensions_;
    } timer(solver,
            _to_resolve,
            _query_timeout_sec,
            _transport_list,
            _assigned_time_nsec);
}
