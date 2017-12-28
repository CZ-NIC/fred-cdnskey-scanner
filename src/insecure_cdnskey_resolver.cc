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

#include "src/insecure_cdnskey_resolver.hh"
#include "src/time_unit.hh"

#include "src/getdns/data.hh"
#include "src/getdns/context.hh"
#include "src/getdns/request.hh"
#include "src/getdns/solver.hh"

#include "src/util/pipe.hh"
#include "src/util/fork.hh"

#include <cstdint>

#include <cstddef>

#include <algorithm>
#include <iostream>
#include <string>
#include <set>

namespace {

const int max_number_of_unresolved_queries = 200;

struct Cdnskey
{
    std::uint16_t flags;
    std::uint8_t protocol;
    std::uint8_t algorithm;
    GetDns::Data::Binary public_key;
    friend std::ostream& operator<<(std::ostream& out, const Cdnskey& value)
    {
        out << std::uint32_t(value.flags)
            << " " << std::uint32_t(value.protocol)
            << " " << std::uint32_t(value.algorithm)
            << " " << GetDns::Data::base64_encode(value.public_key);
        return out;
    }
};

typedef std::set<std::string> Nameservers;

class Query:public GetDns::Request
{
public:
    Query(const Insecure& _task,
          const TimeUnit::Seconds& _timeout_sec,
          const boost::optional<GetDns::TransportList>& _transport_list)
        : task_(_task),
          timeout_sec_(_timeout_sec),
          transport_list_(_transport_list),
          context_ptr_(nullptr),
          status_(Status::none)
    { }
    ~Query()
    {
        if (context_ptr_ != nullptr)
        {
            delete context_ptr_;
            context_ptr_ = nullptr;
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
        if (context_ptr_ != nullptr)
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
        if (context_ptr_ != nullptr)
        {
            delete context_ptr_;
            context_ptr_ = nullptr;
        }
        context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::none);
        context_ptr_->set_timeout(timeout_sec_.value * 1000);
        if (transport_list_)
        {
            context_ptr_->set_dns_transport_list(*transport_list_);
        }
        std::list<boost::asio::ip::address> nameservers;
        nameservers.push_back(task_.address);
        context_ptr_->set_upstream_recursive_servers(nameservers);
        status_ = Status::in_progress;
    }
    void on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t)
    {
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
                    const GetDns::Data::Value algorithm_value = GetDns::Data::get<std::uint32_t>(rdata, "algorithm");
                    if (!GetDns::Data::Is(algorithm_value).of<std::uint32_t>().type)
                    {
                        continue;
                    }
                    cdnskey.algorithm = GetDns::Data::From(algorithm_value).get_value_of<std::uint32_t>();
                }
                {
                    const GetDns::Data::Value flags_value = GetDns::Data::get<std::uint32_t>(rdata, "flags");
                    if (!GetDns::Data::Is(flags_value).of<std::uint32_t>().type)
                    {
                        continue;
                    }
                    cdnskey.flags = GetDns::Data::From(flags_value).get_value_of<std::uint32_t>();
                }
                {
                    const GetDns::Data::Value protocol_value = GetDns::Data::get<std::uint32_t>(rdata, "protocol");
                    if (!GetDns::Data::Is(protocol_value).of<std::uint32_t>().type)
                    {
                        continue;
                    }
                    cdnskey.protocol = GetDns::Data::From(protocol_value).get_value_of<std::uint32_t>();
                }
                {
                    const GetDns::Data::Value public_key_value = GetDns::Data::get<GetDns::Data::Binary>(rdata, "public_key");
                    if (!GetDns::Data::Is(public_key_value).of<GetDns::Data::Binary>().type)
                    {
                        continue;
                    }
                    cdnskey.public_key = GetDns::Data::From(public_key_value).get_value_of<GetDns::Data::Binary>();
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
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
};

class QueryGenerator:public Event::Timeout
{
public:
    QueryGenerator(
            GetDns::Solver& _solver,
            const VectorOfInsecures& _to_resolve,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const TimeUnit::Nanoseconds& _assigned_time_nsec)
        : Event::Timeout(_solver.get_event_base()),
          solver_(_solver),
          to_resolve_(_to_resolve),
          to_resolve_itr_(_to_resolve.begin()),
          remaining_queries_(_to_resolve.size()),
          query_timeout_sec_(_query_timeout_sec),
          transport_list_(_transport_list),
          time_end_(TimeUnit::get_clock_monotonic() + _assigned_time_nsec)
    {
        this->Event::Timeout::set(0);
        while (0 < (remaining_queries_ + solver_.get_number_of_unresolved_requests()))
        {
            _solver.do_one_step();
            const GetDns::Solver::ListOfRequestPtr finished_requests = solver_.pop_finished_requests();
            for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                 request_ptr_itr != finished_requests.end(); ++request_ptr_itr)
            {
                const GetDns::Request* const request_ptr = request_ptr_itr->get();
                const Query* const query_ptr = dynamic_cast<const Query*>(request_ptr);
                if (query_ptr != nullptr)
                {
                    const Insecure to_resolve = query_ptr->get_task();
                    const Nameservers& nameservers = to_resolve.nameservers;
                    if (query_ptr->get_status() == Query::Status::completed)
                    {
                        const Query::Result result = query_ptr->get_result();
                        if (result.empty())
                        {
                            for (Nameservers::const_iterator nameserver_itr = nameservers.begin();
                                 nameserver_itr != nameservers.end(); ++nameserver_itr)
                            {
                                std::cout << "insecure-empty " << *nameserver_itr << " "
                                          << to_resolve.address << " "
                                          << to_resolve.domain << std::endl;
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
                                              << to_resolve.address << " "
                                              << to_resolve.domain << " "
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
                                      << to_resolve.address << " "
                                      << to_resolve.domain << std::endl;
                        }
                    }
                }
            }
            if (remaining_queries_ <= 0)
            {
                this->Event::Timeout::remove();
            }
        }
    }
    ~QueryGenerator() { }
private:
    Event::OnTimeout& on_timeout_occurrence()
    {
        if (solver_.get_number_of_unresolved_requests() < max_number_of_unresolved_queries)
        {
            GetDns::RequestPtr request_ptr(
                    new Query(*to_resolve_itr_, query_timeout_sec_, transport_list_));
            solver_.add_request_for_cdnskey_resolving(
                    to_resolve_itr_->domain,
                    request_ptr,
                    extensions_);
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
    QueryGenerator& set_time_of_next_query()
    {
        const struct ::timespec now = TimeUnit::get_clock_monotonic();
        const TimeUnit::Nanoseconds remaining_time_nsec = time_end_ - now;
        const std::uint64_t min_timeout_usec = 1000;//smaller value exhausts file descriptors :-(
        if (remaining_time_nsec.value <= 0)
        {
            this->Event::Timeout::set(min_timeout_usec);
        }
        else
        {
            const std::uint64_t the_one_query_time_usec = remaining_time_nsec.value / (1000 * remaining_queries_);
            this->Event::Timeout::set(the_one_query_time_usec < min_timeout_usec
                                      ? min_timeout_usec
                                      : the_one_query_time_usec);
        }
        return *this;
    }
    GetDns::Solver& solver_;
    const VectorOfInsecures& to_resolve_;
    VectorOfInsecures::const_iterator to_resolve_itr_;
    std::size_t remaining_queries_;
    const TimeUnit::Seconds query_timeout_sec_;
    const boost::optional<GetDns::TransportList>& transport_list_;
    const struct ::timespec time_end_;
    GetDns::Extensions extensions_;
};

struct QueryDone
{
    QueryDone(const std::string& _domain,
              const boost::asio::ip::address& _address_of_nameserver)
        : domain(_domain),
          address_of_nameserver(_address_of_nameserver)
    { }
    explicit QueryDone(const Insecure& _query)
        : domain(_query.domain),
          address_of_nameserver(_query.address)
    { }
    const std::string domain;
    const boost::asio::ip::address address_of_nameserver;
    friend bool operator<(const QueryDone& _a, const QueryDone& _b)
    {
        return (_a.domain < _b.domain) ||
               ((_a.domain == _b.domain) && (_a.address_of_nameserver < _b.address_of_nameserver));
    }
};

typedef std::set<QueryDone> AnsweredQueries;

class Answer
{
public:
    Answer(Event::Base& _base,
           AnsweredQueries& _answered,
           const Util::ImReader& _source,
           const TimeUnit::Seconds& _max_idle_sec)
        : source_(_source),
          answered_(_answered),
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
        const int number_of_known_prefixes = 3;
        const char* const known_prefixes[number_of_known_prefixes] =
            {
                "insecure",
                "insecure-empty",
                "unresolved"
            };
        const std::ptrdiff_t insecure_prefix_idx = 0;
        const char* const* end_of_known_prefixes = known_prefixes + number_of_known_prefixes;
        const char* nameserver_begin = nullptr;
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
                nameserver_begin = _line_begin + prefix_len + 1;
                break;
            }
            ++known_prefix_ptr;
        }
        if (nameserver_begin == nullptr)
        {
            throw std::runtime_error("invalid data received");
        }
        try
        {
            const char* const nameserver_end = skip_to(nameserver_begin, _line_end, ' ');
            const char* const address_begin = nameserver_end + 1;
            const char* const address_end = skip_to(address_begin, _line_end, ' ');
            const std::string address_str(address_begin, address_end - address_begin);
            boost::asio::ip::address address(boost::asio::ip::address::from_string(address_str));
            const char* const domain_begin = address_end + 1;
            const bool cdnskey_record_found = (known_prefix_ptr - known_prefixes) == insecure_prefix_idx;
            const char* const domain_end = cdnskey_record_found ? skip_to(domain_begin, _line_end, ' ')
                                                                : _line_end;
            const std::string domain(domain_begin, domain_end - domain_begin);
            const QueryDone query_done(domain, address);
            answered_.insert(query_done);
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
    AnsweredQueries& answered_;
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
            const VectorOfInsecures& _to_resolve,
            const TimeUnit::Seconds& _query_timeout_sec,
            const boost::optional<GetDns::TransportList>& _transport_list,
            const TimeUnit::Nanoseconds& _assigned_time_nsec,
            const AnsweredQueries& _answered,
            Util::Pipe& _pipe_to_parent)
        : to_resolve_(_to_resolve),
          query_timeout_sec_(_query_timeout_sec),
          transport_list_(_transport_list),
          assigned_time_nsec_(_assigned_time_nsec),
          answered_(_answered),
          pipe_to_parent_(_pipe_to_parent)
    { }
    int operator()()const
    {
        Util::ImWriter to_parent(pipe_to_parent_, Util::ImWriter::Stream::stdout);
        GetDns::Solver solver;
        if (answered_.empty())
        {
            const QueryGenerator resolve(
                    solver,
                    to_resolve_,
                    query_timeout_sec_,
                    transport_list_,
                    assigned_time_nsec_);
        }
        else
        {
            VectorOfInsecures to_resolve;
            to_resolve.reserve(to_resolve_.size() - answered_.size());
            for (VectorOfInsecures::const_iterator to_resolve_itr = to_resolve_.begin();
                 to_resolve_itr != to_resolve_.end(); ++to_resolve_itr)
            {
                const bool resolved = answered_.find(QueryDone(*to_resolve_itr)) != answered_.end();
                if (!resolved)
                {
                    to_resolve.push_back(*to_resolve_itr);
                }
            }
            const QueryGenerator resolve(
                    solver,
                    to_resolve,
                    query_timeout_sec_,
                    transport_list_,
                    TimeUnit::Nanoseconds(assigned_time_nsec_.value * double(to_resolve.size()) / to_resolve_.size()));
        }
        return EXIT_SUCCESS;
    }
private:
    const VectorOfInsecures& to_resolve_;
    const TimeUnit::Seconds& query_timeout_sec_;
    const boost::optional<GetDns::TransportList>& transport_list_;
    const TimeUnit::Nanoseconds& assigned_time_nsec_;
    const AnsweredQueries& answered_;
    Util::Pipe& pipe_to_parent_;
};

}//namespace {anonymous}

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
    std::set<QueryDone> answered;
    while (answered.size() < _to_resolve.size())
    {
        Util::Pipe pipe;
        Util::Fork parent(
                ChildProcess(
                        _to_resolve,
                        _query_timeout_sec,
                        _transport_list,
                        _assigned_time_nsec,
                        answered,
                        pipe));
        Util::ImReader from_child(pipe);
        from_child.set_nonblocking();
        Event::Base monitor;
        const double query_distance_sec = (_assigned_time_nsec.value / double(_to_resolve.size())) / 1000000000LL;
        const TimeUnit::Seconds answer_timeout_sec(query_distance_sec + _query_timeout_sec.value + 5);
        const Answer answer(monitor, answered, from_child, answer_timeout_sec);
        try
        {
            const Util::Fork::ChildResultStatus child_result_status = parent.get_child_result_status();
            if (child_result_status.exited())
            {
                if (child_result_status.get_exit_status() == EXIT_SUCCESS)
                {
                    std::cerr << "insecure CDNSKEY records resolved" << std::endl;
                    if (answered.size() < _to_resolve.size())
                    {
                        throw std::runtime_error("insecure CDNSKEY resolver doesn't completed its job");
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
