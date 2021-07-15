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

#include "src/secure_cdnskey_resolver.hh"
#include "src/time_unit.hh"

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"
#include "src/getdns/exception.hh"
#include "src/getdns/extensions_set.hh"
#include "src/getdns/solver.hh"

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>

#include "src/util/pipe.hh"
#include "src/util/fork.hh"

#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <iostream>
#include <list>
#include <stdexcept>
#include <vector>

namespace {

constexpr auto max_number_of_unresolved_queries = 200;

struct Cdnskey
{
    std::uint16_t flags;
    std::uint8_t protocol;
    std::uint8_t algorithm;
    std::string public_key;
    friend std::ostream& operator<<(std::ostream& out, const Cdnskey& value)
    {
        out << std::uint32_t(value.flags) << " "
            << std::uint32_t(value.protocol) << " "
            << std::uint32_t(value.algorithm) << " "
            << value.public_key;
        return out;
    }
};

using Nameservers = std::set<std::string>;

class Query
{
public:
    Query(const std::string& domain,
          GetDns::Context context)
        : hostname_{[&]() { char* const str = new char[domain.length() + 1]; std::memcpy(str, domain.c_str(), domain.length() + 1); return str; }()},
          context_{std::move(context)},
          extensions_{make_extensions(GetDns::ExtensionsSet<GetDns::Extension::DnssecReturnOnlySecure>{})},
          status_{Status::none},
          result_{}
    { }
    Query(const Query&) = delete;
    Query(Query&& src) noexcept
        : hostname_{nullptr},
          context_{std::move(src.context_)},
          extensions_{std::move(src.extensions_)},
          status_{src.status_},
          result_{std::move(src.result_)}
    {
        std::swap(src.hostname_, hostname_);
    }
    ~Query() noexcept
    {
        delete[] hostname_;
    }
    Query& operator=(const Query&) = delete;
    Query& operator=(Query&& src) noexcept
    {
        std::swap(src.hostname_, hostname_);
        std::swap(src.context_, context_);
        std::swap(src.extensions_, extensions_);
        status_ = src.status_;
        std::swap(src.result_, result_);
        return *this;
    }
    ::getdns_transaction_t start_transaction(Event::Base& event_base, ::getdns_callback_t callback_fnc, void* user_data)
    {
        context_.set_libevent_base(event_base);
        ::getdns_transaction_t transaction_id;
        MUST_BE_GOOD(::getdns_general(context_, hostname_, std::uint16_t{GETDNS_RRTYPE_CDNSKEY}, *extensions_, user_data, &transaction_id, callback_fnc));
        status_ = Status::in_progress;
        return transaction_id;
    }
    enum class Status
    {
        none,
        in_progress,
        completed,
        untrustworthy_answer,
        cancelled,
        timed_out,
        failed
    };
    Status get_status()const
    {
        return status_;
    }
    struct Result
    {
        std::vector<Cdnskey> cdnskeys;
    };
    const Result& get_result()const
    {
        if (this->get_status() == Status::completed)
        {
            return result_;
        }
        struct NoResultAvailable : std::runtime_error
        {
            NoResultAvailable() : std::runtime_error{"Request is not completed yet"} { }
        };
        throw NoResultAvailable{};
    }
    const char* get_domain()const
    {
        return hostname_;
    }
    void on_complete(GetDns::Data::DictRef answer, ::getdns_transaction_t)
    {
        status_ = Status::untrustworthy_answer;
        result_.cdnskeys.clear();
        const auto answer_status = static_cast<std::uint32_t>(answer.get<GetDns::Data::IntegerRef>("status"));
        switch (answer_status)
        {
            case GETDNS_RESPSTATUS_GOOD:
                break;
            case GETDNS_RESPSTATUS_NO_NAME:
                status_ = Status::completed;
                return;
            case GETDNS_RESPSTATUS_ALL_TIMEOUT:
                status_ = Status::timed_out;
                return;
            case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
                status_ = Status::untrustworthy_answer;
                return;
            case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
                status_ = Status::untrustworthy_answer;
                return;
            default:
                status_ = Status::failed;
                return;
        }
        const auto replies = answer.get<GetDns::Data::ListRef>("replies_tree");
        for (std::size_t reply_idx = 0; reply_idx < replies.length(); ++reply_idx)
        {
            const auto reply = replies.get<GetDns::Data::DictRef>(reply_idx);
            const auto answers = reply.get<GetDns::Data::ListRef>("answer");
            const auto number_of_answers = answers.length();
            for (std::size_t answer_idx = 0; answer_idx < number_of_answers; ++answer_idx)
            {
                try
                {
                    const auto answer = answers.get<GetDns::Data::DictRef>(answer_idx);
                    if ((static_cast<std::uint32_t>(answer.get<GetDns::Data::IntegerRef>("type")) == GETDNS_RRTYPE_CDNSKEY) &&
                        (static_cast<std::uint32_t>(answer.get<GetDns::Data::IntegerRef>("class")) == GETDNS_RRCLASS_IN))
                    {
                        const auto rdata = answer.get<GetDns::Data::DictRef>("rdata");
                        Cdnskey cdnskey;
                        cdnskey.algorithm = rdata.get<GetDns::Data::IntegerRef>("algorithm");
                        cdnskey.flags = rdata.get<GetDns::Data::IntegerRef>("flags");
                        cdnskey.protocol = rdata.get<GetDns::Data::IntegerRef>("protocol");
                        cdnskey.public_key = GetDns::base64_encode(rdata.get<GetDns::Data::BinDataRef>("public_key"));
                        result_.cdnskeys.push_back(std::move(cdnskey));
                    }
                }
                catch (const ::GetDns::NoSuchDictName& e)
                {
                    std::cerr << "resolve " << hostname_ << ": " << e.what() << std::endl;
                }
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
private:
    const char* hostname_;
    GetDns::Context context_;
    GetDns::Data::Dict extensions_;
    Status status_;
    Result result_;
};

template <typename ...Ts>
class QueryGenerator : public Event::OnTimeout<QueryGenerator<Ts...>>
{
public:
    using Solver = GetDns::Solver<Query>;
    using OnTimeout = Event::OnTimeout<QueryGenerator>;
    QueryGenerator(
            Solver& solver,
            const Domains& to_resolve,
            GetDns::Context::Timeout query_timeout,
            const std::list<boost::asio::ip::address>& resolvers,
            const GetDns::Data::TrustAnchorList& trust_anchors,
            std::chrono::nanoseconds assigned_time)
        : OnTimeout{solver.get_event_base()},
          solver_{solver},
          to_resolve_{to_resolve},
          to_resolve_itr_{to_resolve_.begin()},
          remaining_queries_{to_resolve_.size()},
          query_timeout_{query_timeout},
          resolvers_{resolvers},
          trust_anchors_{trust_anchors},
          time_end_{TimeUnit::get_uptime().get() + assigned_time}
    {
        this->OnTimeout::set(std::chrono::microseconds{0});
        while (0 < (remaining_queries_ + solver_.get_number_of_unresolved_requests()))
        {
            solver_.do_one_step();
            const auto finished_requests = solver_.pop_finished_requests();
            for (auto&& query : finished_requests)
            {
                const char* const to_resolve = query.get_domain();
                switch (query.get_status())
                {
                    case Query::Status::completed:
                    {
                        const Query::Result result = query.get_result();
                        if (result.cdnskeys.empty())
                        {
                            std::cout << "secure-empty " << to_resolve << std::endl;
                        }
                        else
                        {
                            for (auto&& key : result.cdnskeys)
                            {
                                std::cout << "secure " << to_resolve << " " << key << std::endl;
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
            if (remaining_queries_ <= 0)
            {
                this->OnTimeout::remove();
            }
        }
    }
    QueryGenerator& on_timeout_occurrence()
    {
        if (solver_.get_number_of_unresolved_requests() < max_number_of_unresolved_queries)
        {
            const auto make_context = [&]()
            {
                auto context = GetDns::Context{GetDns::Context::InitialSettings::FromOs{}};
                context.set_timeout(query_timeout_)
                       .set_dns_transport_list(GetDns::TransportsList<Ts...>{});
                if (!trust_anchors_.empty())
                {
                    context.set_dnssec_trust_anchors(trust_anchors_);
                }
                if (!resolvers_.empty())
                {
                    context.set_upstream_recursive_servers(resolvers_);
                }
                return context;
            };
            solver_.add_request(Query{*to_resolve_itr_, make_context()});
            this->set_time_of_next_query();
            if (to_resolve_itr_ != to_resolve_.end())
            {
                ++to_resolve_itr_;
                --remaining_queries_;
            }
        }
        else if (0 < remaining_queries_)
        {
            this->set_time_of_next_query();
        }
        return *this;
    }
private:
    QueryGenerator& set_time_of_next_query()
    {
        const auto now = TimeUnit::get_uptime();
        using Time = TimeUnit::Nanoseconds<struct TimeTag_>;
        const auto remaining_time = Time{time_end_ - now.get()};
        static constexpr auto min_timeout = Time{std::chrono::microseconds{10000}};//smaller value exhausts file descriptors :-(
        if (remaining_time <= Time::zero())
        {
            this->OnTimeout::set(min_timeout.template as<std::chrono::microseconds>());
        }
        else
        {
            const auto one_query_time = remaining_time / remaining_queries_;
            this->OnTimeout::set((one_query_time < min_timeout ? min_timeout
                                                               : one_query_time).template as<std::chrono::microseconds>());
        }
        return *this;
    }
    Solver& solver_;
    const Domains& to_resolve_;
    Domains::const_iterator to_resolve_itr_;
    std::size_t remaining_queries_;
    GetDns::Context::Timeout query_timeout_;
    const std::list<boost::asio::ip::address>& resolvers_;
    const GetDns::Data::TrustAnchorList& trust_anchors_;
    std::chrono::nanoseconds time_end_;
};

class Answer
{
public:
    Answer(Event::Base& loop,
           Domains& answered,
           const Util::ImReader& source,
           std::chrono::seconds max_idle)
        : source_{source},
          answered_{answered},
          event_ptr_{::event_new(loop,
                                 source_.get_descriptor(),
                                 monitored_events_ | EV_PERSIST,
                                 callback_routine,
                                 this)},
          max_idle_{max_idle},
          source_stream_closed_{false},
          timed_out_{false}
    {
        this->monitor_events_on_source_stream();
        while (true)
        {
            loop(Event::Loop::Once{});
            if (timed_out_)
            {
                return;
            }
            if (content_.empty())
            {
                if (source_stream_closed_)
                {
                    return;
                }
                continue;
            }
            const char* line_begin = content_.c_str();
            while (*line_begin != '\0')
            {
                const char* line_end = line_begin;
                while ((*line_end != '\0') && (*line_end != '\n'))
                {
                    ++line_end;
                }
                const bool line_end_reached = (*line_end == '\n') || source_stream_closed_;
                if (!line_end_reached)
                {
                    break;
                }
                this->line_received(line_begin, line_end);
                const bool data_end_reached = (*line_end == '\0') && source_stream_closed_;
                if (data_end_reached)
                {
                    return;
                }
                line_begin = line_end + 1;
            }
            content_ = line_begin;
        }
    }
    ~Answer()
    {
        this->remove();
    }
    bool timed_out()const
    {
        return timed_out_;
    }
private:
    static const char* skip_to(const char* begin, const char* end, char stop)
    {
        const char* position_of_stop_character = std::find(begin, end, stop);
        const bool end_reached = position_of_stop_character == end;
        if (!end_reached)
        {
            return position_of_stop_character;
        }
        throw std::runtime_error("stop character not found");
    }
    void line_received(const char* _line_begin, const char* _line_end)
    {
        const int number_of_known_prefixes = 4;
        const char* const known_prefixes[number_of_known_prefixes] =
            {
                "secure",
                "secure-empty",
                "untrustworthy",
                "unknown"
            };
        const std::ptrdiff_t secure_prefix_idx = 0;
        const char* const* end_of_known_prefixes = known_prefixes + number_of_known_prefixes;
        const char* domain_begin = nullptr;
        const char* const* known_prefix_ptr = known_prefixes;
        while (known_prefix_ptr < end_of_known_prefixes)
        {
            const char* const prefix = *known_prefix_ptr;
            const ::size_t prefix_len = std::strlen(prefix);
            const int string_equal = 0;
            const bool prefix_candidate_found = std::strncmp(_line_begin, prefix, prefix_len) == string_equal;
            const bool prefix_found = prefix_candidate_found && (_line_begin[prefix_len] == ' ');
            if (prefix_found)
            {
                domain_begin = _line_begin + prefix_len + 1;
                break;
            }
            ++known_prefix_ptr;
        }
        if (domain_begin == nullptr)
        {
            throw std::runtime_error("invalid data received");
        }
        try
        {
            const bool cdnskey_record_found = (known_prefix_ptr - known_prefixes) == secure_prefix_idx;
            const char* const domain_end = cdnskey_record_found ? skip_to(domain_begin, _line_end, ' ')
                                                                : _line_end;
            const std::string domain(domain_begin, domain_end - domain_begin);
            answered_.insert(domain);
            std::cout << std::string(_line_begin, _line_end - _line_begin) << std::endl;
            return;
        }
        catch (...)
        {
            throw std::runtime_error("invalid data received");
        }
    }
    Answer& monitor_events_on_source_stream()
    {
        struct ::timeval timeout;
        timeout.tv_sec = max_idle_.count();
        timeout.tv_usec = 0;
        const int success = 0;
        const int retval = ::event_add(event_ptr_, &timeout);
        if (retval == success)
        {
            return *this;
        }
        struct EventAddFailure:std::runtime_error
        {
            EventAddFailure():std::runtime_error("event_add failed") { }
        };
        throw EventAddFailure();
    }
    Answer& remove()
    {
        if (event_ptr_ != nullptr)
        {
            ::event_del(event_ptr_);
            ::event_free(event_ptr_);
            event_ptr_ = nullptr;
        }
        return *this;
    }
    void on_event(short _events)
    {
        const bool timed_out = (_events & EV_TIMEOUT) == EV_TIMEOUT;
        if (timed_out)
        {
            this->on_timeout();
        }
        const bool ready_for_reading = (_events & EV_READ) == EV_READ;
        if (ready_for_reading)
        {
            this->on_read();
        }
    }
    void on_timeout()
    {
        timed_out_ = true;
    }
    void on_read()
    {
        char buffer[0x10000];
        while (true)
        {
            static constexpr ::ssize_t failure = -1;
            const auto read_retval = ::read(source_.get_descriptor(), buffer, sizeof(buffer));
            const bool read_failed = (read_retval == failure);
            if (!read_failed)
            {
                const bool end_reached = (read_retval == 0);
                if (end_reached)
                {
                    source_stream_closed_ = true;
                }
                else
                {
                    const auto data_length = static_cast<std::size_t>(read_retval);
                    content_.append(buffer, data_length);
                    const bool all_available_data_already_read = data_length < sizeof(buffer);
                    if (!all_available_data_already_read)
                    {
                        continue;
                    }
                }
                return;
            }
            const int c_errno = errno;
            const bool data_unavailable = (c_errno == EAGAIN) || (c_errno == EWOULDBLOCK);
            if (data_unavailable)
            {
                return;
            }
            const bool operation_was_interrupted_by_a_signal = c_errno == EINTR;
            if (operation_was_interrupted_by_a_signal)
            {
                return;
            }
            struct ReadFailed:std::runtime_error
            {
                ReadFailed(int error_code):std::runtime_error(std::string("read() failed: ") + std::strerror(error_code)) { }
            };
            throw ReadFailed(c_errno);
        }
    }
    static void callback_routine(evutil_socket_t _fd, short _events, void* _user_data_ptr)
    {
        auto const event_ptr = static_cast<Answer*>(_user_data_ptr);
        if ((event_ptr != nullptr) && (event_ptr->source_.get_descriptor() == _fd))
        {
            try
            {
                event_ptr->on_event(_events);
            }
            catch (const std::exception& e)
            {
                std::cerr << "Answer::on_event failed: " << e.what() << std::endl;
            }
            catch (...)
            {
                std::cerr << "Answer::on_event caught an unexpected exception" << std::endl;
            }
        }
    }
    const Util::ImReader& source_;
    Domains& answered_;
    struct ::event* event_ptr_;
    std::chrono::seconds max_idle_;
    std::string content_;
    bool source_stream_closed_;
    bool timed_out_;
    static constexpr auto monitored_events_ = short{EV_READ};
};

template <typename ...Ts>
class ChildProcess
{
public:
    ChildProcess(
            const Domains& to_resolve,
            GetDns::Context::Timeout query_timeout,
            const std::list<boost::asio::ip::address>& resolvers,
            const GetDns::Data::TrustAnchorList& trust_anchors,
            std::chrono::nanoseconds assigned_time,
            const Domains& answered,
            Util::Pipe& pipe_to_parent)
        : to_resolve_{to_resolve},
          query_timeout_{query_timeout},
          resolvers_{resolvers},
          trust_anchors_{std::move(trust_anchors)},
          assigned_time_{assigned_time},
          answered_{answered},
          pipe_to_parent_{pipe_to_parent}
    { }
    int operator()()const
    {
        Util::ImWriter to_parent{pipe_to_parent_, Util::ImWriter::Stream::stdout};
        GetDns::Solver<Query> solver;
        if (answered_.empty())
        {
            const QueryGenerator<Ts...> resolve{
                    solver,
                    to_resolve_,
                    query_timeout_,
                    resolvers_,
                    trust_anchors_,
                    assigned_time_};
        }
        else
        {
            Domains to_resolve;
            for (auto&& task : to_resolve_)
            {
                const bool resolved = answered_.find(task) != answered_.end();
                if (!resolved)
                {
                    to_resolve.insert(task);
                }
            }
            const QueryGenerator<Ts...> resolve{
                    solver,
                    to_resolve,
                    query_timeout_,
                    resolvers_,
                    trust_anchors_,
                    std::chrono::nanoseconds{static_cast<std::int64_t>(assigned_time_.count() * double(to_resolve.size()) / to_resolve_.size())}};
        }
        return EXIT_SUCCESS;
    }
private:
    const Domains& to_resolve_;
    GetDns::Context::Timeout query_timeout_;
    const std::list<boost::asio::ip::address>& resolvers_;
    GetDns::Data::TrustAnchorList trust_anchors_;
    std::chrono::nanoseconds assigned_time_;
    const Domains& answered_;
    Util::Pipe& pipe_to_parent_;
};

}//namespace {anonymous}

void SecureCdnskeyResolver::resolve(
        const Domains& to_resolve,
        GetDns::Context::Timeout query_timeout,
        const std::list<boost::asio::ip::address>& resolvers,
        GetDns::Data::TrustAnchorList trust_anchors,
        std::chrono::nanoseconds assigned_time)
{
    if (to_resolve.empty())
    {
        return;
    }
    Domains answered;
    while (answered.size() < to_resolve.size())
    {
        Util::Pipe pipe;
        Util::Fork parent{
                ChildProcess<GetDns::TransportProtocol::Udp, GetDns::TransportProtocol::Tcp>{
                        to_resolve,
                        query_timeout,
                        resolvers,
                        trust_anchors,
                        assigned_time,
                        answered,
                        pipe}};
        Util::ImReader from_child{pipe};
        from_child.set_nonblocking();
        Event::Base monitor;
        const double query_distance_sec = (assigned_time.count() / double(to_resolve.size())) / 1000000000LL;
        const auto answer_timeout = std::chrono::seconds{static_cast<std::int64_t>(query_distance_sec + 5)} + query_timeout.as<std::chrono::seconds>();
        const Answer answer{monitor, answered, from_child, answer_timeout};
        try
        {
            const Util::Fork::ChildResultStatus child_result_status = parent.get_child_result_status();
            if (child_result_status.exited())
            {
                if (child_result_status.get_exit_status() == EXIT_SUCCESS)
                {
                    std::cerr << "secure CDNSKEY records resolved" << std::endl;
                    if (answered.size() < to_resolve.size())
                    {
                        throw std::runtime_error("secure CDNSKEY resolver did not complete it's job");
                    }
                    return;
                }
                std::cerr << "child process failed" << std::endl;
            }
            else if (child_result_status.signaled())
            {
                std::cerr << "child process terminated by signal " << child_result_status.get_signal_number() << std::endl;
            }
            else
            {
                std::cerr << "child process done" << std::endl;
            }
        }
        catch (const Util::Fork::ChildIsStillRunning&)
        {
            const Util::Fork::ChildResultStatus child_result_status = parent.kill_child();
            if (child_result_status.signaled())
            {
                std::cerr << "child process was terminated because of blocking" << std::endl;
            }
        }
    }
}
