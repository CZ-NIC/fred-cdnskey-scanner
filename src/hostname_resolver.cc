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

#include "src/hostname_resolver.hh"

#include "src/getdns/request.hh"
#include "src/getdns/solver.hh"

#include "src/util/pipe.hh"
#include "src/util/fork.hh"

#include <iostream>
#include <list>

namespace {

class Query:public GetDns::Request
{
public:
    Query(const std::string& _hostname,
          const TimeUnit::Seconds& _timeout_sec,
          const boost::optional<GetDns::TransportList>& _transport_list,
          const std::list<boost::asio::ip::address>& _resolvers)
        : hostname_(_hostname),
          timeout_sec_(_timeout_sec),
          transport_list_(_transport_list),
          resolvers_(_resolvers),
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
    typedef std::set<boost::asio::ip::address> Result;
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
    const std::string& get_hostname()const
    {
        return hostname_;
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
        if (transport_list_)
        {
            context_ptr_->set_dns_transport_list(*transport_list_);
        }
        if (!resolvers_.empty())
        {
            context_ptr_->set_upstream_recursive_servers(resolvers_);
        }
        context_ptr_->set_timeout(timeout_sec_.value * 1000);
        status_ = Status::in_progress;
    }
    void on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t)
    {
        status_ = Status::completed;
        result_.clear();
        const GetDns::Data::Value just_address_answers = GetDns::Data::get<GetDns::Data::List>(_answer, "just_address_answers");
        if (!GetDns::Data::Is(just_address_answers).of<GetDns::Data::List>().type)
        {
            return;
        }
        const GetDns::Data::List addresses = GetDns::Data::From(just_address_answers).get_value_of<GetDns::Data::List>();
        const std::size_t number_of_addresses = addresses.get_number_of_items();
        for (std::size_t idx = 0; idx < number_of_addresses; ++idx)
        {
            const GetDns::Data::Value address_item = GetDns::Data::get<GetDns::Data::Dict>(addresses, idx);
            if (!GetDns::Data::Is(address_item).of<GetDns::Data::Dict>().type)
            {
                continue;
            }
            const GetDns::Data::Dict address = GetDns::Data::From(address_item).get_value_of<GetDns::Data::Dict>();
            const GetDns::Data::Value address_data = GetDns::Data::get<boost::asio::ip::address>(address, "address_data");
            if (!GetDns::Data::Is(address_data).of<boost::asio::ip::address>().type)
            {
                continue;
            }
            result_.insert(GetDns::Data::From(address_data).get_value_of<boost::asio::ip::address>());
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
    const std::string hostname_;
    const TimeUnit::Seconds timeout_sec_;
    const boost::optional<GetDns::TransportList> transport_list_;
    const std::list<boost::asio::ip::address> resolvers_;
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
};

class QueryGenerator:public Event::Timeout
{
public:
    QueryGenerator(
            GetDns::Solver& _solver,
            const std::set<std::string>& _hostnames,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const std::list<boost::asio::ip::address>& _resolvers,
            const TimeUnit::Nanoseconds& _assigned_time_nsec)
        : Event::Timeout(_solver.get_event_base()),
          solver_(_solver),
          hostnames_(_hostnames),
          hostname_ptr_(_hostnames.begin()),
          remaining_queries_(_hostnames.size()),
          query_timeout_sec_(_query_timeout_sec),
          transport_list_(_transport_list),
          resolvers_(_resolvers),
          time_end_(TimeUnit::get_clock_monotonic() + _assigned_time_nsec)
    {
        this->Event::Timeout::set(0);
        while (0 < (remaining_queries_ + solver_.get_number_of_unresolved_requests()))
        {
            solver_.do_one_step();
            const GetDns::Solver::ListOfRequestPtr finished_requests = solver_.pop_finished_requests();
            for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                 request_ptr_itr != finished_requests.end(); ++request_ptr_itr)
            {
                const GetDns::Request* const request_ptr = request_ptr_itr->get();
                const Query* const query_ptr = dynamic_cast<const Query*>(request_ptr);
                if (query_ptr != NULL)
                {
                    const std::string nameserver = query_ptr->get_hostname();
                    switch (query_ptr->get_status())
                    {
                        case Query::Status::completed:
                        {
                            const Query::Result addresses = query_ptr->get_result();
                            if (addresses.empty())
                            {
                                std::cout << "unresolved-ip " << nameserver << std::endl;
                            }
                            else
                            {
                                for (Query::Result::const_iterator addr_itr = addresses.begin();
                                     addr_itr != addresses.end(); ++addr_itr)
                                {
                                    std::cout << "resolved " << nameserver << " " << *addr_itr << std::endl;
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
            }
            if (remaining_queries_ <= 0)
            {
                this->Event::Timeout::remove();
            }
        }
        std::cerr << "hostnames resolved" << std::endl;
    }
    ~QueryGenerator() { }
private:
    Event::OnTimeout& on_timeout_occurrence()
    {
        const int max_number_of_unresolved_queries = 200;
        if (solver_.get_number_of_unresolved_requests() < max_number_of_unresolved_queries)
        {
            GetDns::RequestPtr request_ptr(
                    new Query(
                            *hostname_ptr_,
                            query_timeout_sec_,
                            transport_list_,
                            resolvers_));
            solver_.add_request_for_address_resolving(
                    *hostname_ptr_,
                    request_ptr,
                    extensions_);
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
    QueryGenerator& set_time_of_next_query()
    {
        const struct ::timespec now = TimeUnit::get_clock_monotonic();
        const TimeUnit::Nanoseconds remaining_time_nsec = time_end_ - now;
        const ::uint64_t min_timeout_usec = 4000;//smaller value exhausts file descriptors :-(
        if (remaining_time_nsec.value <= 0)
        {
            this->Event::Timeout::set(min_timeout_usec);
        }
        else
        {
            const ::uint64_t the_one_query_time_usec = remaining_time_nsec.value / (1000 * remaining_queries_);
            this->Event::Timeout::set(the_one_query_time_usec < min_timeout_usec
                                      ? min_timeout_usec
                                      : the_one_query_time_usec);
        }
        return *this;
    }
    GetDns::Solver& solver_;
    const std::set<std::string>& hostnames_;
    std::set<std::string>::const_iterator hostname_ptr_;
    std::size_t remaining_queries_;
    const TimeUnit::Seconds query_timeout_sec_;
    const boost::optional<GetDns::TransportList>& transport_list_;
    const std::list<boost::asio::ip::address>& resolvers_;
    const struct ::timespec time_end_;
    GetDns::Extensions extensions_;
};

class Answer
{
public:
    Answer(Event::Base& _base,
           HostnameResolver::Result& _resolved,
           std::set<std::string>& _unresolved,
           const Util::ImReader& _source,
           const TimeUnit::Seconds& _max_idle_sec)
        : source_(_source),
          resolved_(_resolved),
          unresolved_(_unresolved),
          event_ptr_(::event_new(_base.get_base(),
                                 source_.get_descriptor(),
                                 monitored_events_ | EV_PERSIST,
                                 callback_routine,
                                 this)),
          max_idle_sec_(_max_idle_sec),
          source_stream_closed_(false),
          timed_out_(false)
    {
        this->monitor_events_on_source_stream();
        while (true)
        {
            _base.loop();
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
        timeout.tv_sec = max_idle_sec_.value;
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
        if (event_ptr_ != NULL)
        {
            ::event_del(event_ptr_);
            ::event_free(event_ptr_);
            event_ptr_ = NULL;
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
            static const ::ssize_t failure = -1;
            const ::ssize_t read_retval = ::read(source_.get_descriptor(), buffer, sizeof(buffer));
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
                    const std::size_t data_length = static_cast<std::size_t>(read_retval);
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
        Answer* const event_ptr = static_cast<Answer*>(_user_data_ptr);
        if ((event_ptr != NULL) && (event_ptr->source_.get_descriptor() == _fd))
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
    const TimeUnit::Seconds max_idle_sec_;
    std::string content_;
    bool source_stream_closed_;
    bool timed_out_;
    static const short monitored_events_ = EV_READ;
};

class ChildProcess
{
public:
    ChildProcess(
            const std::set<std::string>& _hostnames,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const std::list<boost::asio::ip::address>& _resolvers,
            const TimeUnit::Nanoseconds& _assigned_time_nsec,
            const HostnameResolver::Result& _resolved,
            const std::set<std::string>& _unresolved,
            Util::Pipe& _pipe_to_parent)
        : hostnames_(_hostnames),
          query_timeout_sec_(_query_timeout_sec),
          transport_list_(_transport_list),
          resolvers_(_resolvers),
          assigned_time_nsec_(_assigned_time_nsec),
          resolved_(_resolved),
          unresolved_(_unresolved),
          pipe_to_parent_(_pipe_to_parent)
    { }
    int operator()()const
    {
        Util::ImWriter to_parent(pipe_to_parent_, Util::ImWriter::stdout);
        GetDns::Solver solver;
        if (resolved_.empty() && unresolved_.empty())
        {
            const QueryGenerator resolve(
                    solver,
                    hostnames_,
                    query_timeout_sec_,
                    transport_list_,
                    resolvers_,
                    assigned_time_nsec_);
        }
        else
        {
            std::set<std::string> hostnames;
            HostnameResolver::Result::const_iterator resolved_itr = resolved_.begin();
            std::set<std::string>::const_iterator unresolved_itr = unresolved_.begin();
            for (std::set<std::string>::const_iterator hostname_itr = hostnames_.begin();
                 hostname_itr != hostnames_.end(); ++hostname_itr)
            {
                const std::string hostname = *hostname_itr;
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
            const QueryGenerator resolve(
                    solver,
                    hostnames,
                    query_timeout_sec_,
                    transport_list_,
                    resolvers_,
                    TimeUnit::Nanoseconds(assigned_time_nsec_.value * double(hostnames.size()) / hostnames_.size()));
        }
        return EXIT_SUCCESS;
    }
private:
    const std::set<std::string>& hostnames_;
    const TimeUnit::Seconds& query_timeout_sec_;
    const boost::optional<GetDns::TransportList>& transport_list_;
    const std::list<boost::asio::ip::address>& resolvers_;
    const TimeUnit::Nanoseconds& assigned_time_nsec_;
    const HostnameResolver::Result& resolved_;
    const std::set<std::string>& unresolved_;
    Util::Pipe& pipe_to_parent_;
};

}//namespace {anonymous}

HostnameResolver::Result HostnameResolver::get_result(
        const std::set<std::string>& _hostnames,
        const TimeUnit::Seconds& _query_timeout_sec,
        const boost::optional<GetDns::TransportList>& _transport_list,
        const std::list<boost::asio::ip::address>& _resolvers,
        const TimeUnit::Nanoseconds& _assigned_time_nsec)
{
    Result resolved;
    std::set<std::string> unresolved;
    if (_hostnames.empty())
    {
        return resolved;
    }
    while ((resolved.size() + unresolved.size()) < _hostnames.size())
    {
        Util::Pipe pipe;
        Util::Fork parent(
                ChildProcess(
                        _hostnames,
                        _query_timeout_sec,
                        _transport_list,
                        _resolvers,
                        _assigned_time_nsec,
                        resolved,
                        unresolved,
                        pipe));
        Util::ImReader from_child(pipe);
        from_child.set_nonblocking();
        Event::Base monitor;
        const double query_distance_sec = (_assigned_time_nsec.value / double(_hostnames.size())) / 1000000000LL;
        const TimeUnit::Seconds answer_timeout_sec(query_distance_sec + _query_timeout_sec.value + 5);
        const Answer answer(monitor, resolved, unresolved, from_child, answer_timeout_sec);
        try
        {
            const Util::Fork::ChildResultStatus child_result_status = parent.get_child_result_status();
            if (child_result_status.exited())
            {
                if (child_result_status.get_exit_status() == EXIT_SUCCESS)
                {
                    std::cerr << "child process successfully done" << std::endl;
                    if ((resolved.size() + unresolved.size()) < _hostnames.size())
                    {
                        throw std::runtime_error("hostname resolver doesn't completed its job");
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
