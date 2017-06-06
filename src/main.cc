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
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <cstdlib>

#include <boost/asio/ip/address.hpp>

class ResolveHostname:public GetDns::Request
{
public:
    explicit ResolveHostname();
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

int main(int, char* argv[])
{
    try
    {
        GetDns::Solver solver;
        GetDns::TransportList tcp_first;
        tcp_first.push_back(GetDns::Transport::tcp);
        tcp_first.push_back(GetDns::Transport::udp);
        for (char** arg_ptr = argv + 1; *arg_ptr != NULL; ++arg_ptr)
        {
            const std::string hostname = *arg_ptr;
            solver.add_request_for_address_resolving(
                    hostname,
                    GetDns::RequestPtr(new ResolveHostname),
                    tcp_first);
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
    context_ptr_ = new GetDns::Context(_event_base);
    std::list<boost::asio::ip::address> my_dns;
    my_dns.push_back(boost::asio::ip::address::from_string("172.16.1.181"));
//    my_dns.push_back(boost::asio::ip::address::from_string("8.8.8.8"));
    context_ptr_->set_upstream_recursive_servers(my_dns);
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
