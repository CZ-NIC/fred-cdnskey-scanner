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

#include "src/getdns/data.hh"
#include "src/getdns/context.hh"
#include "src/getdns/solver.hh"
#include "src/getdns/exception.hh"
#include "src/getdns/error.hh"

#include <string>
#include <set>
#include <map>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <cstdlib>

#include <boost/asio/ip/address.hpp>

class DomainsToScanning
{
public:
    DomainsToScanning(std::istream& _data_source);
    ~DomainsToScanning();
    typedef std::set<std::string> Nameservers;
    typedef std::set<std::string> Domains;
    Nameservers get_nameservers()const;
    Domains get_domains_of(const std::string& _nameserver)const;
private:
    DomainsToScanning& append_data(const char* _data_chunk, std::streamsize _data_chunk_length);
    void data_finished();
    typedef std::map<std::string, Domains> DomainsOfNamserver;
    DomainsOfNamserver domains_of_namserver_;
    std::string nameserver_;
    Domains domains_;
    std::string rest_of_data_;
    bool data_starts_at_new_line_;
};

class ResolveHostname:public GetDns::Request
{
public:
    ResolveHostname();
    ~ResolveHostname();
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
    Status::Enum get_status()const;
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
        struct IpAddress
        {
            boost::asio::ip::address value;
            Trustiness::Enum trustiness;
            friend bool operator<(const IpAddress& a, const IpAddress& b)
            {
                return (a.value < b.value) ||
                       ((a.value == b.value) && (a.trustiness < b.trustiness));
            }
        };
        typedef std::set<IpAddress> IpAddresses;
        std::string canonical_name;
        IpAddresses addresses;
    };
    Result get_result()const;
private:
    GetDns::Context& get_context();
    void join(Event::Base& _event_base);
    void on_complete(const GetDns::Data::Dict& _answer, getdns_transaction_t _transaction_id);
    void on_cancel(getdns_transaction_t _transaction_id);
    void on_timeout(getdns_transaction_t _transaction_id);
    void on_error(getdns_transaction_t _transaction_id);
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
};

class ResolveCdnskey:public GetDns::Request
{
public:
    ResolveCdnskey();
    ~ResolveCdnskey();
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
    Status::Enum get_status()const;
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
    };
    Result get_result()const;
private:
    GetDns::Context& get_context();
    void join(Event::Base& _event_base);
    void on_complete(const GetDns::Data::Dict& _answer, getdns_transaction_t _transaction_id);
    void on_cancel(getdns_transaction_t _transaction_id);
    void on_timeout(getdns_transaction_t _transaction_id);
    void on_error(getdns_transaction_t _transaction_id);
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
};

int main(int, char* argv[])
{
    try
    {
        const DomainsToScanning domains_to_scanning(std::cin);
        const DomainsToScanning::Nameservers nameservers = domains_to_scanning.get_nameservers();
        for (DomainsToScanning::Nameservers::const_iterator nameserver_itr = nameservers.begin();
             nameserver_itr != nameservers.end(); ++nameserver_itr)
        {
            std::cout << *nameserver_itr;
            const DomainsToScanning::Domains domains = domains_to_scanning.get_domains_of(*nameserver_itr);
            for (DomainsToScanning::Domains::const_iterator domain_itr = domains.begin();
                 domain_itr != domains.end(); ++domain_itr)
            {
                std::cout << " " << *domain_itr;
            }
            std::cout << std::endl;
        }
        return EXIT_SUCCESS;
        GetDns::Solver solver;
        GetDns::TransportList tcp_only;
        tcp_only.push_back(GetDns::Transport::tcp);
        GetDns::Extensions extensions;
        for (char** arg_ptr = argv + 1; *arg_ptr != NULL; ++arg_ptr)
        {
#if 0
            const std::string hostname = *arg_ptr;
            solver.add_request_for_address_resolving(
                    hostname,
                    GetDns::RequestPtr(new ResolveHostname),
                    tcp_only,
                    extensions);
#else
            const std::string domain = *arg_ptr;
            solver.add_request_for_cdnskey_resolving(
                    domain,
                    GetDns::RequestPtr(new ResolveCdnskey),
                    tcp_only,
                    extensions,
                    boost::asio::ip::address::from_string("172.16.1.181"));
#endif
        }
        while (0 < solver.get_number_of_unresolved_requests())
        {
            solver.do_one_step();
            const GetDns::Solver::ListOfRequestPtr finished_requests = solver.pop_finished_requests();
            for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr =
                    finished_requests.begin(); request_ptr_itr != finished_requests.end(); ++ request_ptr_itr)
            {
                const GetDns::Request* const request_ptr = request_ptr_itr->get();
                const ResolveHostname* const hostname_resolver_ptr =
                        dynamic_cast<const ResolveHostname*>(request_ptr);
                if (hostname_resolver_ptr != NULL)
                {
                    if (hostname_resolver_ptr->get_status() == ResolveHostname::Status::completed)
                    {
                        const ResolveHostname::Result result = hostname_resolver_ptr->get_result();
                        std::cout << "canonical_name = " << result.canonical_name << std::endl;
                        for (ResolveHostname::Result::IpAddresses::const_iterator address_itr = result.addresses.begin();
                                address_itr != result.addresses.end(); ++address_itr)
                        {
                            std::cout << address_itr->value.to_string() << std::endl;
                        }
                    }
                }
                std::cout << std::endl;
            }
        }
        return EXIT_SUCCESS;
    }
    catch (const Event::Exception& e)
    {
        std::cerr << "caught Event::Exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (const GetDns::Error& e)
    {
        std::cerr << "caught GetDns::Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (const GetDns::Exception& e)
    {
        std::cerr << "caught GetDns::Exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (const std::exception& e)
    {
        std::cerr << "caught std::exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (...)
    {
        std::cerr << "caught an unexpected exception" << std::endl;
        return EXIT_FAILURE;
    }
}

DomainsToScanning::DomainsToScanning(std::istream& _data_source)
    : data_starts_at_new_line_(true)
{
    while (!_data_source.eof())
    {
        const bool stdin_is_broken = !std::cin;
        if (stdin_is_broken)
        {
            throw std::runtime_error("stream is broken");
        }
        char data_chunk[0x10000];
        _data_source.read(data_chunk, sizeof(data_chunk));
        const std::streamsize data_chunk_length = _data_source.gcount();
        this->append_data(data_chunk, data_chunk_length);
    }
    this->data_finished();
}

DomainsToScanning::~DomainsToScanning()
{
}

DomainsToScanning& DomainsToScanning::append_data(const char* _data_chunk, std::streamsize _data_chunk_length)
{
    const char* const data_end = _data_chunk + _data_chunk_length;
    const char* item_begin = _data_chunk;
    const char* current_pos = _data_chunk;
    while (current_pos < data_end)
    {
        static const char item_delimiter = ' ';
        static const char line_delimiter = '\n';
        const bool item_end_reached = *current_pos == item_delimiter;
        const bool line_end_reached = *current_pos == line_delimiter;
        const bool some_delimiter_reached = item_end_reached || line_end_reached;
        if (!some_delimiter_reached)
        {
            ++current_pos;
            continue;
        }
        const std::size_t item_length = current_pos - item_begin;
        const std::string item = rest_of_data_ + std::string(item_begin, item_length);
        const bool item_is_nameserver = data_starts_at_new_line_;
        if (item_is_nameserver)
        {
            nameserver_ = item;
            data_starts_at_new_line_ = false;
        }
        else
        {
            domains_.insert(item);
        }
        if (line_end_reached)
        {
            if (!nameserver_.empty() && !domains_.empty())
            {
                domains_of_namserver_.insert(std::make_pair(nameserver_, domains_));
            }
            nameserver_.clear();
            domains_.clear();
            data_starts_at_new_line_ = true;
        }
        ++current_pos;
        item_begin = current_pos;
        rest_of_data_.clear();
    }
    const std::size_t rest_of_data_length = current_pos - item_begin;
    rest_of_data_.append(item_begin, rest_of_data_length);
    return *this;
}

void DomainsToScanning::data_finished()
{
    const std::string item = rest_of_data_;
    const bool item_is_nameserver = data_starts_at_new_line_;
    if (item_is_nameserver)
    {
        nameserver_ = item;
    }
    else
    {
        domains_.insert(item);
    }
    if (!nameserver_.empty())
    {
        domains_of_namserver_.insert(std::make_pair(nameserver_, domains_));
        nameserver_.clear();
        domains_.clear();
    }
}

DomainsToScanning::Nameservers DomainsToScanning::get_nameservers()const
{
    Nameservers nameservers;
    for (DomainsOfNamserver::const_iterator nameserver_itr = domains_of_namserver_.begin();
         nameserver_itr != domains_of_namserver_.end(); ++nameserver_itr)
    {
        nameservers.insert(nameserver_itr->first);
    }
    return nameservers;
}

DomainsToScanning::Domains DomainsToScanning::get_domains_of(const std::string& _nameserver)const
{
    DomainsOfNamserver::const_iterator nameserver_itr = domains_of_namserver_.find(_nameserver);
    const bool nameserver_found = nameserver_itr != domains_of_namserver_.end();
    if (!nameserver_found)
    {
        throw std::runtime_error("nameserver not found");
    }
    return nameserver_itr->second;
}

ResolveHostname::ResolveHostname()
    : context_ptr_(NULL),
      status_(Status::none)
{
}

ResolveHostname::~ResolveHostname()
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
}

ResolveHostname::Status::Enum ResolveHostname::get_status()const
{
    return status_;
}

ResolveHostname::Result ResolveHostname::get_result()const
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

GetDns::Context& ResolveHostname::get_context()
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

void ResolveHostname::join(Event::Base& _event_base)
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
    context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::from_os);
//    std::list<boost::asio::ip::address> my_dns;
//    my_dns.push_back(boost::asio::ip::address::from_string("172.16.1.181"));
//    my_dns.push_back(boost::asio::ip::address::from_string("8.8.8.8"));
//    context_ptr_->set_upstream_recursive_servers(my_dns);
    context_ptr_->set_timeout(1000);
    status_ = Status::in_progress;
}

void ResolveHostname::on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t)
{
    std::cout << _answer << std::endl;
    status_ = Status::completed;
    result_.addresses.clear();
    result_.canonical_name.clear();
    const GetDns::Data::Value canonical_name = GetDns::Data::get<GetDns::Data::Fqdn>(_answer, "canonical_name");
    if (!GetDns::Data::Is(canonical_name).of<GetDns::Data::Fqdn>().type)
    {
        return;
    }
    result_.canonical_name = GetDns::Data::From(canonical_name).get_value_of<GetDns::Data::Fqdn>().value;
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
        Result::IpAddress ip_address;
        ip_address.value = GetDns::Data::From(address_data).get_value_of<boost::asio::ip::address>();
        ip_address.trustiness = Result::Trustiness::insecure;
        result_.addresses.insert(ip_address);
    }
}

void ResolveHostname::on_cancel(::getdns_transaction_t)
{
    status_ = Status::cancelled;
}

void ResolveHostname::on_timeout(::getdns_transaction_t)
{
    status_ = Status::timed_out;
}

void ResolveHostname::on_error(::getdns_transaction_t)
{
    status_ = Status::failed;
}

ResolveCdnskey::ResolveCdnskey()
    : context_ptr_(NULL),
      status_(Status::none)
{
}

ResolveCdnskey::~ResolveCdnskey()
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
}

ResolveCdnskey::Status::Enum ResolveCdnskey::get_status()const
{
    return status_;
}

ResolveCdnskey::Result ResolveCdnskey::get_result()const
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

GetDns::Context& ResolveCdnskey::get_context()
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

void ResolveCdnskey::join(Event::Base& _event_base)
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
    context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::from_os);
//    std::list<boost::asio::ip::address> my_dns;
//    my_dns.push_back(boost::asio::ip::address::from_string("172.16.1.181"));
//    my_dns.push_back(boost::asio::ip::address::from_string("8.8.8.8"));
//    context_ptr_->set_upstream_recursive_servers(my_dns);
    context_ptr_->set_timeout(1000);
    status_ = Status::in_progress;
}

void ResolveCdnskey::on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t)
{
    std::cout << _answer << std::endl;
    status_ = Status::completed;
}

void ResolveCdnskey::on_cancel(::getdns_transaction_t)
{
    status_ = Status::cancelled;
}

void ResolveCdnskey::on_timeout(::getdns_transaction_t)
{
    status_ = Status::timed_out;
}

void ResolveCdnskey::on_error(::getdns_transaction_t)
{
    status_ = Status::failed;
}
