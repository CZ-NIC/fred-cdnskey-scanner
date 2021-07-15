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

#include "src/hostname_resolver.hh"

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"
#include "src/getdns/exception.hh"
#include "src/getdns/extensions_set.hh"
#include "src/getdns/solver.hh"

#include "src/time_unit.hh"

#include "src/util/fork.hh"
#include "src/util/pipe.hh"

#include <cstring>
#include <iostream>
#include <list>


namespace {

constexpr int max_number_of_unresolved_queries = 200;

class Query
{
public:
    Query(const std::string& hostname,
          GetDns::Context context)
        : hostname_{[&]() { char* const str = new char[hostname.length() + 1]; std::memcpy(str, hostname.c_str(), hostname.length() + 1); return str; }()},
          context_{std::move(context)},
          extensions_{make_extensions(GetDns::ExtensionsSet<GetDns::Extension::ReturnBothV4AndV6>{})},
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
        MUST_BE_GOOD(::getdns_address(context_, hostname_, *extensions_, user_data, &transaction_id, callback_fnc));
        status_ = Status::in_progress;
        return transaction_id;
    }
    enum class Status
    {
        none,
        in_progress,
        completed,
        cancelled,
        timed_out,
        failed
    };
    Status get_status() const
    {
        return status_;
    }
    using Result = std::set<boost::asio::ip::address>;
    const Result& get_result() const
    {
        if (this->get_status() == Status::completed)
        {
            return result_;
        }
        struct NoResultAvailable : std::runtime_error
        {
            NoResultAvailable() : std::runtime_error("Request is not completed yet") { }
        };
        throw NoResultAvailable();
    }
    const char* get_hostname() const
    {
        return hostname_;
    }
    void on_complete(GetDns::Data::DictRef answer, ::getdns_transaction_t)
    {
        status_ = Status::completed;
        result_.clear();
        const auto addresses = answer.get<GetDns::Data::ListRef>("just_address_answers");
        const std::size_t number_of_addresses = addresses.length();
        for (std::size_t idx = 0; idx < number_of_addresses; ++idx)
        {
            const auto address_data = addresses.get<GetDns::Data::DictRef>(idx).get<GetDns::Data::BinDataRef>("address_data");
            result_.insert(address_data.as<boost::asio::ip::address>());
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
            std::set<std::string> hostnames,
            GetDns::Context::Timeout query_timeout,
            std::list<boost::asio::ip::address> resolvers,
            std::chrono::nanoseconds assigned_time)
        : OnTimeout{solver.get_event_base()},
          solver_{solver},
          hostnames_{std::move(hostnames)},
          hostname_ptr_{hostnames_.begin()},
          remaining_queries_{hostnames_.size()},
          query_timeout_{query_timeout},
          resolvers_{std::move(resolvers)},
          time_end_{TimeUnit::get_uptime().get() + assigned_time}
    {
        this->OnTimeout::set(std::chrono::microseconds{0});
        while (0 < (remaining_queries_ + solver_.get_number_of_unresolved_requests()))
        {
            solver_.do_one_step();
            const Solver::ListOfQueries finished_requests = solver_.pop_finished_requests();
            for (auto&& query : finished_requests)
            {
                const char* const nameserver = query.get_hostname();
                switch (query.get_status())
                {
                    case Query::Status::completed:
                    {
                        const Query::Result addresses = query.get_result();
                        if (addresses.empty())
                        {
                            std::cout << "unresolved-ip " << nameserver << std::endl;
                        }
                        else
                        {
                            for (auto&& addr : addresses)
                            {
                                std::cout << "resolved " << nameserver << " " << addr << std::endl;
                            }
                        }
                        break;
                    }
                    case Query::Status::timed_out:
                    case Query::Status::cancelled:
                    case Query::Status::failed:
                    case Query::Status::in_progress:
                    case Query::Status::none:
                        std::cout << "unresolved-ip " << nameserver << std::endl;
                        break;
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
                       .set_upstream_recursive_servers(resolvers_)
                       .set_dns_transport_list(GetDns::TransportsList<Ts...>{});
                return context;
            };
            solver_.add_request(Query{*hostname_ptr_, make_context()});
            this->set_time_of_next_query();
            if (hostname_ptr_ != hostnames_.end())
            {
                ++hostname_ptr_;
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
        static constexpr auto min_timeout = Time{std::chrono::microseconds{4000}};//smaller value exhausts file descriptors :-(
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
    std::set<std::string> hostnames_;
    std::set<std::string>::const_iterator hostname_ptr_;
    std::size_t remaining_queries_;
    GetDns::Context::Timeout query_timeout_;
    std::list<boost::asio::ip::address> resolvers_;
    std::chrono::nanoseconds time_end_;
};

class Answer
{
public:
    Answer(Event::Base& loop,
           HostnameResolver::Result& resolved,
           std::set<std::string>& unresolved,
           const Util::ImReader& source,
           std::chrono::seconds max_idle)
        : source_{source},
          resolved_{resolved},
          unresolved_{unresolved},
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
    void line_received(const char* _line_begin, const char* _line_end)
    {
        const int string_equal = 0;
        const char* const prefix = _line_begin;
        if (std::strncmp(prefix, "resolved ", std::strlen("resolved ")) == string_equal)
        {
            const char* const hostname_begin = prefix + std::strlen("resolved ");
            const char* hostname_end = hostname_begin;
            while ((hostname_end < _line_end) && (*hostname_end != ' '))
            {
                ++hostname_end;
            }
            const std::string hostname(hostname_begin, hostname_end - hostname_begin);
            const char* const address_begin = hostname_end + 1;
            if (_line_end <= address_begin)
            {
                throw std::runtime_error("invalid data received");
            }
            const std::string address(address_begin, _line_end - address_begin);
            resolved_[hostname].insert(boost::asio::ip::address::from_string(address));
            return;
        }
        if (std::strncmp(prefix, "unresolved-ip ", std::strlen("unresolved-ip ")) == string_equal)
        {
            const char* const hostname_begin = prefix + std::strlen("unresolved-ip ");
            const std::string hostname(hostname_begin, _line_end - hostname_begin);
            unresolved_.insert(hostname);
            std::cout << std::string(_line_begin, _line_end - _line_begin) << std::endl;
            return;
        }
        throw std::runtime_error("invalid data received");
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
    HostnameResolver::Result& resolved_;
    std::set<std::string>& unresolved_;
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
            const std::set<std::string>& hostnames,
            GetDns::Context::Timeout query_timeout,
            const std::list<boost::asio::ip::address>& resolvers,
            std::chrono::nanoseconds assigned_time,
            const HostnameResolver::Result& resolved,
            const std::set<std::string>& unresolved,
            Util::Pipe& pipe_to_parent)
        : hostnames_{hostnames},
          query_timeout_{query_timeout},
          resolvers_{resolvers},
          assigned_time_{assigned_time},
          resolved_{resolved},
          unresolved_{unresolved},
          pipe_to_parent_{pipe_to_parent}
    { }
    int operator()()const
    {
        Util::ImWriter to_parent(pipe_to_parent_, Util::ImWriter::Stream::stdout);
        GetDns::Solver<Query> solver;
        if (resolved_.empty() && unresolved_.empty())
        {
            const QueryGenerator<Ts...> resolve{
                    solver,
                    hostnames_,
                    query_timeout_,
                    resolvers_,
                    assigned_time_};
        }
        else
        {
            std::set<std::string> hostnames;
            HostnameResolver::Result::const_iterator resolved_itr = resolved_.begin();
            std::set<std::string>::const_iterator unresolved_itr = unresolved_.begin();
            for (const auto& hostname : hostnames_)
            {
                if ((resolved_itr != resolved_.end()) && (hostname == resolved_itr->first))
                {
                    ++resolved_itr;
                }
                else if ((unresolved_itr != unresolved_.end()) && (hostname == *unresolved_itr))
                {
                    ++unresolved_itr;
                }
                else
                {
                    hostnames.insert(hostname);
                }
            }
            const QueryGenerator<Ts...> resolve{
                    solver,
                    hostnames,
                    query_timeout_,
                    resolvers_,
                    std::chrono::nanoseconds{static_cast<std::int64_t>(assigned_time_.count() * double(hostnames.size()) / hostnames_.size())}};
        }
        return EXIT_SUCCESS;
    }
private:
    const std::set<std::string>& hostnames_;
    GetDns::Context::Timeout query_timeout_;
    const std::list<boost::asio::ip::address>& resolvers_;
    std::chrono::nanoseconds assigned_time_;
    const HostnameResolver::Result& resolved_;
    const std::set<std::string>& unresolved_;
    Util::Pipe& pipe_to_parent_;
};

}//namespace {anonymous}

HostnameResolver::Result HostnameResolver::get_result(
        const std::set<std::string>& hostnames,
        GetDns::Context::Timeout query_timeout,
        const std::list<boost::asio::ip::address>& resolvers,
        std::chrono::nanoseconds assigned_time)
{
    Result resolved;
    std::set<std::string> unresolved;
    if (hostnames.empty())
    {
        return resolved;
    }
    while ((resolved.size() + unresolved.size()) < hostnames.size())
    {
        Util::Pipe pipe;
        Util::Fork parent{
                ChildProcess<GetDns::TransportProtocol::Udp, GetDns::TransportProtocol::Tcp>{
                        hostnames,
                        query_timeout,
                        resolvers,
                        assigned_time,
                        resolved,
                        unresolved,
                        pipe}};
        Util::ImReader from_child{pipe};
        from_child.set_nonblocking();
        Event::Base monitor;
        const auto query_distance_sec = (assigned_time.count() / double(hostnames.size())) / 1000000000LL;
        const auto answer_timeout = std::chrono::seconds{static_cast<std::int64_t>(query_distance_sec + 5)} + query_timeout.as<std::chrono::seconds>();
        const auto answer = Answer{monitor, resolved, unresolved, from_child, answer_timeout};
        try
        {
            const Util::Fork::ChildResultStatus child_result_status = parent.get_child_result_status();
            if (child_result_status.exited())
            {
                if (child_result_status.get_exit_status() == EXIT_SUCCESS)
                {
                    std::cerr << "hostnames A and AAAA records resolved" << std::endl;
                    if ((resolved.size() + unresolved.size()) < hostnames.size())
                    {
                        throw std::runtime_error("hostname resolver did not complete it's job");
                    }
                    return resolved;
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
    return resolved;
}
