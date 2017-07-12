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

#include "src/time_unit.hh"
#include "src/secure_cdnskey_resolver.hh"

#include "src/getdns/request.hh"
#include "src/getdns/solver.hh"
#include "src/getdns/data.hh"
#include "src/getdns/transport.hh"

#include <stdint.h>

#include <iostream>
#include <list>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>

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

class SecureCdnskeyResolver::Query:public GetDns::Request
{
public:
    Query(const std::string& _domain,
          const TimeUnit::Seconds& _timeout_sec,
          const boost::optional<GetDns::TransportList>& _transport_list,
          const std::list<boost::asio::ip::address>& _resolvers,
          const std::list<GetDns::Data::TrustAnchor>& _trust_anchors)
        : domain_(_domain),
          timeout_sec_(_timeout_sec),
          transport_list_(_transport_list),
          resolvers_(_resolvers),
          trust_anchors_(_trust_anchors),
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
            untrustworthy_answer,
            cancelled,
            timed_out,
            failed
        };
    };
    Status::Enum get_status()const
    {
        return status_;
    }
    struct Result
    {
        struct Trustiness
        {
            enum Enum
            {
                insecure,
                secure,
                bogus
            };
            friend std::ostream& operator<<(std::ostream& out, Enum value)
            {
                switch (value)
                {
                    case insecure: return out << "insecure";
                    case secure: return out << "secure";
                    case bogus: return out << "bogus";
                }
                return out << "unknown";
            }
        };
        Trustiness::Enum trustiness;
        std::vector<Cdnskey> cdnskeys;
    };
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
    const std::string& get_domain()const
    {
        return domain_;
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
        context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::from_os);
        if (!resolvers_.empty())
        {
            context_ptr_->set_upstream_recursive_servers(resolvers_);
        }
        context_ptr_->set_timeout(timeout_sec_.value * 1000);
        if (transport_list_)
        {
            context_ptr_->set_dns_transport_list(*transport_list_);
        }
        if (!trust_anchors_.empty())
        {
            context_ptr_->set_dnssec_trust_anchors(trust_anchors_);
        }
        status_ = Status::in_progress;
    }
    void on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t)
    {
        //std::cerr << _answer << std::endl;
        status_ = Status::untrustworthy_answer;
        result_.cdnskeys.clear();
        const GetDns::Data::Value answer_status = GetDns::Data::get< ::uint32_t >(_answer, "status");
        if (!GetDns::Data::Is(answer_status).of< ::uint32_t >().type)
        {
            return;
        }
        const ::uint32_t answer_status_value = GetDns::Data::From(answer_status).get_value_of< ::uint32_t >();
        if (answer_status_value != GETDNS_RESPSTATUS_GOOD)
        {
            return;
        }
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
                result_.cdnskeys.push_back(cdnskey);
            }
        }
        status_ = Status::completed;
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
    const std::string domain_;
    const TimeUnit::Seconds timeout_sec_;
    const boost::optional<GetDns::TransportList> transport_list_;
    const std::list<boost::asio::ip::address> resolvers_;
    const std::list<GetDns::Data::TrustAnchor> trust_anchors_;
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
};

void SecureCdnskeyResolver::resolve(
        const Domains& _to_resolve,
        const TimeUnit::Seconds& _query_timeout_sec,
        const boost::optional<GetDns::TransportList>& _transport_list,
        const std::list<boost::asio::ip::address>& _resolvers,
        const std::list<GetDns::Data::TrustAnchor>& _trust_anchors,
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
              const Domains& _to_resolve,
              const TimeUnit::Seconds& _query_timeout_sec,
              const boost::optional<GetDns::TransportList>& _transport_list,
              const std::list<boost::asio::ip::address>& _resolvers,
              const std::list<GetDns::Data::TrustAnchor>& _trust_anchors,
              const TimeUnit::Nanoseconds& _assigned_time_nsec)
            : Event::Timeout(_solver.get_event_base()),
              solver_(_solver),
              to_resolve_(_to_resolve),
              item_to_resolve_ptr_(_to_resolve.begin()),
              remaining_queries_(_to_resolve.size()),
              query_timeout_sec_(_query_timeout_sec),
              transport_list_(_transport_list),
              resolvers_(_resolvers),
              trust_anchors_(_trust_anchors),
              time_end_(TimeUnit::get_clock_monotonic() + _assigned_time_nsec)
        {
            this->Timeout::set(0);
            extensions_.dnssec_return_only_secure = true;
            while (0 < (remaining_queries_ + solver_.get_number_of_unresolved_requests()))
            {
                solver_.do_one_step();
                const GetDns::Solver::ListOfRequestPtr finished_requests = _solver.pop_finished_requests();
                for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                     request_ptr_itr != finished_requests.end(); ++request_ptr_itr)
                {
                    const GetDns::Request* const request_ptr = request_ptr_itr->get();
                    const Query* const query_ptr = dynamic_cast<const Query*>(request_ptr);
                    if (query_ptr != NULL)
                    {
                        const std::string to_resolve = query_ptr->get_domain();
                        switch (query_ptr->get_status())
                        {
                            case Query::Status::completed:
                            {
                                const Query::Result result = query_ptr->get_result();
                                if (result.cdnskeys.empty())
                                {
                                    std::cout << "secure-empty " << to_resolve << std::endl;
                                }
                                else
                                {
                                    for (std::vector<Cdnskey>::const_iterator key_itr = result.cdnskeys.begin();
                                         key_itr != result.cdnskeys.end(); ++key_itr)
                                    {
                                        std::cout << "secure " << to_resolve << " " << *key_itr << std::endl;
                                    }
                                }
                                break;
                            }
                            case Query::Status::untrustworthy_answer:
                            {
                                std::cout << "untrustworthy " << to_resolve << std::endl;
                                break;
                            }
                            case Query::Status::cancelled:
                            case Query::Status::failed:
                            case Query::Status::none:
                            case Query::Status::in_progress:
                            case Query::Status::timed_out:
                            {
                                std::cout << "unknown " << to_resolve << std::endl;
                                break;
                            }
                        }
                    }
                }
                if (remaining_queries_ <= 0)
                {
                    this->Event::Timeout::remove();
                }
            }
            std::cerr << "secure CDNSKEY records resolved" << std::endl;
        }
        ~Timer() { }
    private:
        Event::OnTimeout& on_timeout_occurrence()
        {
            if (solver_.get_number_of_unresolved_requests() < max_number_of_unresolved_queries)
            {
                const std::string domain = *item_to_resolve_ptr_;
                const GetDns::RequestPtr query_ptr(new Query(
                        domain,
                        query_timeout_sec_,
                        transport_list_,
                        resolvers_,
                        trust_anchors_));
                solver_.add_request_for_cdnskey_resolving(domain, query_ptr, extensions_);
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
        const Domains& to_resolve_;
        Domains::const_iterator item_to_resolve_ptr_;
        std::size_t remaining_queries_;
        const TimeUnit::Seconds query_timeout_sec_;
        const boost::optional<GetDns::TransportList>& transport_list_;
        const std::list<boost::asio::ip::address>& resolvers_;
        const std::list<GetDns::Data::TrustAnchor>& trust_anchors_;
        const struct ::timespec time_end_;
        GetDns::Extensions extensions_;
    } timer(solver,
            _to_resolve,
            _query_timeout_sec,
            _transport_list,
            _resolvers,
            _trust_anchors,
            _assigned_time_nsec);
}
