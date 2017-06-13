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

#include <algorithm>
#include <string>
#include <set>
#include <map>
#include <vector>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <cstdlib>
#include <cstring>

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

typedef std::set<std::string> Nameservers;
typedef std::set<std::string> Domains;

class DomainsToScanning
{
public:
    DomainsToScanning(std::istream& _data_source);
    ~DomainsToScanning();
    Nameservers get_nameservers()const;
    const Domains& get_signed_domains()const;
    Domains get_unsigned_domains_of(const std::string& _nameserver)const;
private:
    DomainsToScanning& append_data(const char* _data_chunk, std::streamsize _data_chunk_length);
    void data_finished();
    typedef std::map<std::string, Domains> DomainsOfNamserver;
    DomainsOfNamserver unsigned_domains_of_namserver_;
    std::string nameserver_;
    Domains signed_domains_;
    Domains unsigned_domains_;
    std::string rest_of_data_;
    bool data_starts_at_new_line_;
};

struct DomainNameserverAddress
{
    std::string domain;
    std::string nameserver;
    boost::asio::ip::address address;
};

typedef std::vector<DomainNameserverAddress> VectorOfDomainNameserverAddress;
void prepare_task(const DomainsToScanning& input, GetDns::Solver& solver, VectorOfDomainNameserverAddress& result);

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
    const Result& get_result()const;
    ::getdns_transaction_t get_request_id()const;
private:
    GetDns::Context& get_context();
    void join(Event::Base& _event_base);
    void on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t _transaction_id);
    void on_cancel(::getdns_transaction_t _transaction_id);
    void on_timeout(::getdns_transaction_t _transaction_id);
    void on_error(::getdns_transaction_t _transaction_id);
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
    boost::optional< ::getdns_transaction_t > request_id_;
};

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

class ResolveCdnskeyUnsigned:public GetDns::Request
{
public:
    ResolveCdnskeyUnsigned(
            const boost::optional<GetDns::TransportList>& _transport_list,
            const boost::asio::ip::address& _nameserver);
    ~ResolveCdnskeyUnsigned();
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
        Trustiness::Enum trustiness;
        Cdnskey cdnskey;
    };
    const Result& get_result()const;
    ::getdns_transaction_t get_request_id()const;
private:
    GetDns::Context& get_context();
    void join(Event::Base& _event_base);
    void on_complete(const GetDns::Data::Dict& _answer, getdns_transaction_t _transaction_id);
    void on_cancel(getdns_transaction_t _transaction_id);
    void on_timeout(getdns_transaction_t _transaction_id);
    void on_error(getdns_transaction_t _transaction_id);
    const boost::optional<GetDns::TransportList> transport_list_;
    const boost::asio::ip::address nameserver_;
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
    boost::optional< ::getdns_transaction_t > request_id_;
};

class ResolveCdnskeySigned:public GetDns::Request
{
public:
    ResolveCdnskeySigned(
            const boost::optional<GetDns::TransportList>& _transport_list,
            const GetDns::Data::List& _trust_anchors);
    ~ResolveCdnskeySigned();
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
        Trustiness::Enum trustiness;
        Cdnskey cdnskey;
    };
    const Result& get_result()const;
    ::getdns_transaction_t get_request_id()const;
private:
    GetDns::Context& get_context();
    void join(Event::Base& _event_base);
    void on_complete(const GetDns::Data::Dict& _answer, getdns_transaction_t _transaction_id);
    void on_cancel(getdns_transaction_t _transaction_id);
    void on_timeout(getdns_transaction_t _transaction_id);
    void on_error(getdns_transaction_t _transaction_id);
    const boost::optional<GetDns::TransportList> transport_list_;
    GetDns::Data::List trust_anchors_;
    GetDns::Context* context_ptr_;
    Status::Enum status_;
    Result result_;
    boost::optional< ::getdns_transaction_t > request_id_;
};

const int max_number_of_unresolved_queries = 2;

namespace {

template <class T>
T split(const std::string& src, const std::string& delimiters, void(*append)(const std::string& item, T& container));

void append_ip_address(const std::string& item, std::vector<boost::asio::ip::address>& addresses);
void append_trust_anchor(const std::string& item, GetDns::Data::List& anchors);

}//namespace {anonymous}

int main(int, char* argv[])
{
    std::string hostname_resolvers_opt;
    std::string cdnskey_resolvers_opt;
    std::string dnssec_trust_anchors_opt;
    for (char** arg_ptr = argv + 1; *arg_ptr != NULL; ++arg_ptr)
    {
        const int are_the_same = 0;
        if (std::strcmp(*arg_ptr, "--hostname_resolvers") == are_the_same)
        {
            if (!hostname_resolvers_opt.empty())
            {
                std::cerr << "hostname_resolvers option can be used once only" << std::endl;
                return EXIT_FAILURE;
            }
            ++arg_ptr;
            if (*arg_ptr == NULL)
            {
                std::cerr << "no argument for hostname_resolvers option" << std::endl;
                return EXIT_FAILURE;
            }
            hostname_resolvers_opt = *arg_ptr;
            if (hostname_resolvers_opt.empty())
            {
                std::cerr << "hostname_resolvers argument can not be empty" << std::endl;
                return EXIT_FAILURE;
            }
        }
        else if (std::strcmp(*arg_ptr, "--cdnskey_resolvers") == are_the_same)
        {
            if (!cdnskey_resolvers_opt.empty())
            {
                std::cerr << "cdnskey_resolvers option can be used once only" << std::endl;
                return EXIT_FAILURE;
            }
            ++arg_ptr;
            if (*arg_ptr == NULL)
            {
                std::cerr << "no argument for cdnskey_resolvers option" << std::endl;
                return EXIT_FAILURE;
            }
            cdnskey_resolvers_opt = *arg_ptr;
            if (cdnskey_resolvers_opt.empty())
            {
                std::cerr << "cdnskey_resolvers argument can not be empty" << std::endl;
                return EXIT_FAILURE;
            }
        }
        else if (std::strcmp(*arg_ptr, "--dnssec_trust_anchors") == are_the_same)
        {
            if (!dnssec_trust_anchors_opt.empty())
            {
                std::cerr << "dnssec_trust_anchors option can be used once only" << std::endl;
                return EXIT_FAILURE;
            }
            ++arg_ptr;
            if (*arg_ptr == NULL)
            {
                std::cerr << "no argument for dnssec_trust_anchors option" << std::endl;
                return EXIT_FAILURE;
            }
            dnssec_trust_anchors_opt = *arg_ptr;
            if (dnssec_trust_anchors_opt.empty())
            {
                std::cerr << "dnssec_trust_anchors argument can not be empty" << std::endl;
                return EXIT_FAILURE;
            }
        }
        else if (std::strcmp(*arg_ptr, "--help") == are_the_same)
        {
            std::cerr << "bla bla" << std::endl;
            return EXIT_SUCCESS;
        }
        else
        {
            std::cerr << "unknown option \"" << (*arg_ptr) << "\"" << std::endl;
            return EXIT_FAILURE;
        }
    }
    if (!hostname_resolvers_opt.empty())
    {
        const std::vector<boost::asio::ip::address> addresses = split(hostname_resolvers_opt, ",", append_ip_address);
        for (std::vector<boost::asio::ip::address>::const_iterator addr_itr = addresses.begin(); addr_itr != addresses.end(); ++addr_itr)
        {
            std::cout << "addr: " << *addr_itr << std::endl;
        }
    }
    if (!cdnskey_resolvers_opt.empty())
    {
        const std::vector<boost::asio::ip::address> addresses = split(cdnskey_resolvers_opt, ",", append_ip_address);
        for (std::vector<boost::asio::ip::address>::const_iterator addr_itr = addresses.begin(); addr_itr != addresses.end(); ++addr_itr)
        {
            std::cout << "addr: " << *addr_itr << std::endl;
        }
    }
    if (!dnssec_trust_anchors_opt.empty())
    {
        const GetDns::Data::List anchors = split(dnssec_trust_anchors_opt, ",", append_trust_anchor);
    }
    return EXIT_SUCCESS;
    try
    {
        const DomainsToScanning domains_to_scanning(std::cin);
        GetDns::Solver solver;
        GetDns::TransportList tcp_only;
        tcp_only.push_back(GetDns::Transport::tcp);
        {
            VectorOfDomainNameserverAddress to_resolve;
            prepare_task(domains_to_scanning, solver, to_resolve);
            typedef std::map< ::getdns_transaction_t, DomainNameserverAddress > Tasks;
            struct Process
            {
                static void resolved_cdnskey(
                        GetDns::Solver& _solver,
                        std::size_t _max_number_of_unresolved_queries,
                        Tasks& _tasks)
                {
                    while (_max_number_of_unresolved_queries < _solver.get_number_of_unresolved_requests())
                    {
                        _solver.do_one_step();
                        const GetDns::Solver::ListOfRequestPtr finished_requests = _solver.pop_finished_requests();
                        for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                             request_ptr_itr != finished_requests.end(); ++ request_ptr_itr)
                        {
                            const GetDns::Request* const request_ptr = request_ptr_itr->get();
                            const ResolveCdnskeyUnsigned* const cdnskey_resolver_ptr =
                                    dynamic_cast<const ResolveCdnskeyUnsigned*>(request_ptr);
                            if (cdnskey_resolver_ptr != NULL)
                            {
                                if (cdnskey_resolver_ptr->get_status() == ResolveCdnskeyUnsigned::Status::completed)
                                {
                                    const ResolveCdnskeyUnsigned::Result result = cdnskey_resolver_ptr->get_result();
                                    const DomainNameserverAddress to_resolve = _tasks[cdnskey_resolver_ptr->get_request_id()];
                                    std::cout << to_resolve.nameserver << " "
                                              << to_resolve.address << " "
                                              << to_resolve.domain << " "
                                              << result.cdnskey << std::endl;
                                }
                                _tasks.erase(cdnskey_resolver_ptr->get_request_id());
                            }
                        }
                    }
                }
            };
            GetDns::Extensions extensions;
            Tasks tasks;
            for (VectorOfDomainNameserverAddress::const_iterator item_itr = to_resolve.begin();
                 item_itr != to_resolve.end(); ++item_itr)
            {
                const ::getdns_transaction_t task_id = solver.add_request_for_cdnskey_resolving(
                        item_itr->domain,
                        GetDns::RequestPtr(new ResolveCdnskeyUnsigned(tcp_only, item_itr->address)),
                        extensions);
                tasks.insert(std::make_pair(task_id, *item_itr));
                Process::resolved_cdnskey(solver, max_number_of_unresolved_queries, tasks);
            }
            Process::resolved_cdnskey(solver, 0, tasks);
        }
        {
            const Domains to_resolve = domains_to_scanning.get_signed_domains();
            typedef std::map< ::getdns_transaction_t, std::string > Tasks;
            struct Process
            {
                static void resolved_cdnskey(
                        GetDns::Solver& _solver,
                        std::size_t _max_number_of_unresolved_queries,
                        Tasks& _tasks)
                {
                    while (_max_number_of_unresolved_queries < _solver.get_number_of_unresolved_requests())
                    {
                        _solver.do_one_step();
                        const GetDns::Solver::ListOfRequestPtr finished_requests = _solver.pop_finished_requests();
                        for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                             request_ptr_itr != finished_requests.end(); ++ request_ptr_itr)
                        {
                            const GetDns::Request* const request_ptr = request_ptr_itr->get();
                            const ResolveCdnskeySigned* const cdnskey_resolver_ptr =
                                    dynamic_cast<const ResolveCdnskeySigned*>(request_ptr);
                            if (cdnskey_resolver_ptr != NULL)
                            {
                                if (cdnskey_resolver_ptr->get_status() == ResolveCdnskeySigned::Status::completed)
                                {
                                    const ResolveCdnskeySigned::Result result = cdnskey_resolver_ptr->get_result();
                                    const std::string to_resolve = _tasks[cdnskey_resolver_ptr->get_request_id()];
                                    std::cout << to_resolve << " "
                                              << result.cdnskey << std::endl;
                                }
                                _tasks.erase(cdnskey_resolver_ptr->get_request_id());
                            }
                        }
                    }
                }
            };
            Tasks tasks;
            GetDns::Data::List anchors;
            const std::string public_key_bin = GetDns::Data::base64_decode(
                    "AwEAAdAjHYjqJ6ovPqU+mVFrrvIaqPiQfmNRbv4LX/A0xqcgLZjVC4Mw"
                    "1bNgU+yvE4J3ICiYk2nKRdYY+9OmKdkb1o7Pl6K7uCq2PiIBFOtj610B"
                    "+eS7xvhOp9JnXXKcCg/tgkMCAPZ89RczNmQBJtFzjgytjNPNgl2a2ApO"
                    "KXOVE5xFL6YcWW0p8rPdCnNE2HUQwIJTnxkWf/cLY4gY21TWKIfsE024"
                    "qXE+8jxbHIFpDzAG5VrnNE0yS2p24ad45IlhHHJI1K076lKOAXRpv7S7"
                    "HE0JbTx3SxFcNrwRdX3WM/pkFxgBzrTk1bpcWWUbLX3mb5nZPv9v0RQ4"
                    "qYoo11axAU8=");
            const GetDns::Data::Dict anchor =
                    GetDns::Data::Dict::get_trust_anchor(".", 257, 3, 8, public_key_bin);
            GetDns::Data::set_item_of(anchors, ::size_t(0), const_cast<const GetDns::Data::Dict&>(anchor).get_base_ptr());
            std::cout << "anchor:\n" << anchor << std::endl;
            GetDns::Extensions extensions;
            extensions.dnssec_return_status = true;
//            extensions.dnssec_return_validation_chain = true;
//            extensions.dnssec_return_only_secure = true;
            for (Domains::const_iterator item_itr = to_resolve.begin(); item_itr != to_resolve.end(); ++item_itr)
            {
                const ::getdns_transaction_t task_id = solver.add_request_for_cdnskey_resolving(
                        *item_itr,
                        GetDns::RequestPtr(new ResolveCdnskeySigned(tcp_only, anchors)),
                        extensions);
                tasks.insert(std::make_pair(task_id, *item_itr));
                Process::resolved_cdnskey(solver, max_number_of_unresolved_queries, tasks);
            }
            Process::resolved_cdnskey(solver, 0, tasks);
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

namespace {

struct DnsRecord
{
    enum SecurityLevel
    {
        should_be_signed,
        should_not_be_signed,
    };
};

const char prefix_of_signed_domains[] = "S:";
const char prefix_of_unsigned_domains[] = "U:";

DnsRecord::SecurityLevel get_dnsrecord_security_level(const std::string& _prefixed_domain)
{
    const int are_the_same = 0;
    if (_prefixed_domain.compare(0, std::strlen(prefix_of_signed_domains), prefix_of_signed_domains) == are_the_same)
    {
        return DnsRecord::should_be_signed;
    }
    return DnsRecord::should_not_be_signed;
}

std::string remove_dnsrecord_security_level_prefix(const std::string& _prefixed_domain)
{
    const int are_the_same = 0;
    if (_prefixed_domain.compare(0, std::strlen(prefix_of_signed_domains), prefix_of_signed_domains) == are_the_same)
    {
        return _prefixed_domain.substr(std::strlen(prefix_of_signed_domains), std::string::npos);
    }
    if (_prefixed_domain.compare(0, std::strlen(prefix_of_unsigned_domains), prefix_of_unsigned_domains) == are_the_same)
    {
        return _prefixed_domain.substr(std::strlen(prefix_of_unsigned_domains), std::string::npos);
    }
    return _prefixed_domain;
}

}//namespace {anonymous}

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
            const DnsRecord::SecurityLevel requested_security_level = get_dnsrecord_security_level(item);
            if (requested_security_level == DnsRecord::should_be_signed)
            {
                signed_domains_.insert(remove_dnsrecord_security_level_prefix(item));
            }
            else
            {
                unsigned_domains_.insert(remove_dnsrecord_security_level_prefix(item));
            }
        }
        if (line_end_reached)
        {
            if (!nameserver_.empty())
            {
                if (!unsigned_domains_.empty())
                {
                    unsigned_domains_of_namserver_.insert(std::make_pair(nameserver_, unsigned_domains_));
                }
            }
            nameserver_.clear();
            unsigned_domains_.clear();
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
        const DnsRecord::SecurityLevel requested_security_level = get_dnsrecord_security_level(item);
        if (requested_security_level == DnsRecord::should_be_signed)
        {
            signed_domains_.insert(remove_dnsrecord_security_level_prefix(item));
        }
        else
        {
            unsigned_domains_.insert(remove_dnsrecord_security_level_prefix(item));
        }
    }
    if (!nameserver_.empty())
    {
        if (!unsigned_domains_.empty())
        {
            unsigned_domains_of_namserver_.insert(std::make_pair(nameserver_, unsigned_domains_));
        }
        nameserver_.clear();
        unsigned_domains_.clear();
    }
}

struct DomainNameserver
{
    friend bool operator<(const DomainNameserver& a, const DomainNameserver& b)
    {
        return a.domain < b.domain;
    }
    std::string domain;
    std::string nameserver;
};

void prepare_task(const DomainsToScanning& input, GetDns::Solver& solver, VectorOfDomainNameserverAddress& result)
{
    typedef std::set<boost::asio::ip::address> IpAddresses;
    typedef std::map<std::string, IpAddresses> IpAddressesOfNameservers;
    typedef std::map< boost::asio::ip::address, std::set<DomainNameserver> > IpAddressesToDomainNameserver;
    typedef std::map< ::getdns_transaction_t, std::string > Tasks;
    struct Process
    {
        static void resolved_hostname(
                GetDns::Solver& _solver,
                std::size_t _max_number_of_unresolved_queries,
                Tasks& _tasks,
                IpAddressesOfNameservers& _resolved_data)
        {
            while (_max_number_of_unresolved_queries < _solver.get_number_of_unresolved_requests())
            {
                _solver.do_one_step();
                const GetDns::Solver::ListOfRequestPtr finished_requests = _solver.pop_finished_requests();
                for (GetDns::Solver::ListOfRequestPtr::const_iterator request_ptr_itr = finished_requests.begin();
                     request_ptr_itr != finished_requests.end(); ++ request_ptr_itr)
                {
                    const GetDns::Request* const request_ptr = request_ptr_itr->get();
                    const ResolveHostname* const hostname_resolver_ptr = dynamic_cast<const ResolveHostname*>(request_ptr);
                    if (hostname_resolver_ptr != NULL)
                    {
                        IpAddresses addresses;
                        if (hostname_resolver_ptr->get_status() == ResolveHostname::Status::completed)
                        {
                            const ResolveHostname::Result result = hostname_resolver_ptr->get_result();
                            for (ResolveHostname::Result::IpAddresses::const_iterator address_itr = result.addresses.begin();
                                    address_itr != result.addresses.end(); ++address_itr)
                            {
                                addresses.insert(address_itr->value);
                            }
                        }
                        const std::string nameserver = _tasks[hostname_resolver_ptr->get_request_id()];
                        _resolved_data.insert(std::make_pair(nameserver, addresses));
                        _tasks.erase(hostname_resolver_ptr->get_request_id());
                    }
                }
            }
        }
    };
    GetDns::TransportList tcp_only;
    tcp_only.push_back(GetDns::Transport::tcp);
    GetDns::Extensions extensions;
    const Nameservers nameservers = input.get_nameservers();
    IpAddressesOfNameservers nameserver_addresses;
    Tasks tasks;
    for (Nameservers::const_iterator nameserver_itr = nameservers.begin();
         nameserver_itr != nameservers.end(); ++nameserver_itr)
    {
        const std::string nameserver = *nameserver_itr;
        const ::getdns_transaction_t task_id = solver.add_request_for_address_resolving(
                nameserver,
                GetDns::RequestPtr(new ResolveHostname),
                tcp_only,
                extensions);
        tasks.insert(std::make_pair(task_id, nameserver));
        Process::resolved_hostname(solver, max_number_of_unresolved_queries, tasks, nameserver_addresses);
    }
    Process::resolved_hostname(solver, 0, tasks, nameserver_addresses);

    IpAddressesToDomainNameserver domains_by_nameserver_addresses;
    for (IpAddressesOfNameservers::const_iterator nameserver_itr = nameserver_addresses.begin();
         nameserver_itr != nameserver_addresses.end(); ++nameserver_itr)
    {
        const std::string nameserver = nameserver_itr->first;
        for (IpAddresses::const_iterator address_itr = nameserver_itr->second.begin();
             address_itr != nameserver_itr->second.end(); ++address_itr)
        {
            const Domains domains = input.get_unsigned_domains_of(nameserver);
            DomainNameserver item;
            item.nameserver = nameserver;
            std::set<DomainNameserver>& items = domains_by_nameserver_addresses[*address_itr];
            for (Domains::const_iterator domain_itr = domains.begin(); domain_itr != domains.end(); ++domain_itr)
            {
                item.domain = *domain_itr;
                items.insert(item);
            }
        }
    }

    std::size_t number_of_items = 0;
    for (IpAddressesToDomainNameserver::const_iterator address_itr = domains_by_nameserver_addresses.begin();
         address_itr != domains_by_nameserver_addresses.end(); ++address_itr)
    {
        number_of_items += address_itr->second.size();
    }
    result.clear();
    result.reserve(number_of_items);
    for (IpAddressesToDomainNameserver::const_iterator address_itr = domains_by_nameserver_addresses.begin();
         address_itr != domains_by_nameserver_addresses.end(); ++address_itr)
    {
        DomainNameserverAddress item;
        item.address = address_itr->first;
        for (std::set<DomainNameserver>::const_iterator domain_itr = address_itr->second.begin();
             domain_itr != address_itr->second.end(); ++domain_itr)
        {
            item.domain = domain_itr->domain;
            item.nameserver = domain_itr->nameserver;
            result.push_back(item);
        }
    }
    std::random_shuffle(result.begin(), result.end());
}

Nameservers DomainsToScanning::get_nameservers()const
{
    Nameservers nameservers;
    for (DomainsOfNamserver::const_iterator nameserver_itr = unsigned_domains_of_namserver_.begin();
         nameserver_itr != unsigned_domains_of_namserver_.end(); ++nameserver_itr)
    {
        nameservers.insert(nameserver_itr->first);
    }
    return nameservers;
}

const Domains& DomainsToScanning::get_signed_domains()const
{
    return signed_domains_;
}

Domains DomainsToScanning::get_unsigned_domains_of(const std::string& _nameserver)const
{
    DomainsOfNamserver::const_iterator nameserver_itr = unsigned_domains_of_namserver_.find(_nameserver);
    const bool nameserver_found = nameserver_itr != unsigned_domains_of_namserver_.end();
    if (nameserver_found)
    {
        return nameserver_itr->second;
    }
    const Domains no_content;
    return no_content;
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

const ResolveHostname::Result& ResolveHostname::get_result()const
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

::getdns_transaction_t ResolveHostname::get_request_id()const
{
    if (request_id_)
    {
        return *request_id_;
    }
    throw std::runtime_error("request_id not set yet");
}

void ResolveHostname::join(Event::Base& _event_base)
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
    context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::from_os);
    std::list<boost::asio::ip::address> my_dns;
    my_dns.push_back(boost::asio::ip::address::from_string("127.0.1.1"));
    context_ptr_->set_upstream_recursive_servers(my_dns);
    context_ptr_->set_timeout(1000);
    status_ = Status::in_progress;
}

void ResolveHostname::on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
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

void ResolveHostname::on_cancel(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "cancelled" << std::endl;
    status_ = Status::cancelled;
}

void ResolveHostname::on_timeout(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "timed_out" << std::endl;
    status_ = Status::timed_out;
}

void ResolveHostname::on_error(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "failed" << std::endl;
    status_ = Status::failed;
}

ResolveCdnskeyUnsigned::ResolveCdnskeyUnsigned(
        const boost::optional<GetDns::TransportList>& _transport_list,
        const boost::asio::ip::address& _nameserver)
    : transport_list_(_transport_list),
      nameserver_(_nameserver),
      context_ptr_(NULL),
      status_(Status::none)
{
    result_.trustiness = Result::Trustiness::insecure;
    result_.cdnskey.flags = 0;
    result_.cdnskey.protocol = 0;
    result_.cdnskey.algorithm = 0;
}

ResolveCdnskeyUnsigned::~ResolveCdnskeyUnsigned()
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
}

ResolveCdnskeyUnsigned::Status::Enum ResolveCdnskeyUnsigned::get_status()const
{
    return status_;
}

const ResolveCdnskeyUnsigned::Result& ResolveCdnskeyUnsigned::get_result()const
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

GetDns::Context& ResolveCdnskeyUnsigned::get_context()
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

::getdns_transaction_t ResolveCdnskeyUnsigned::get_request_id()const
{
    if (request_id_)
    {
        return *request_id_;
    }
    throw std::runtime_error("request_id not set yet");
}

void ResolveCdnskeyUnsigned::join(Event::Base& _event_base)
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
    context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::none);
    context_ptr_->set_timeout(1000);
    if (transport_list_)
    {
        context_ptr_->set_dns_transport_list(*transport_list_);
    }
    std::list<boost::asio::ip::address> nameservers;
    nameservers.push_back(nameserver_);
    context_ptr_->set_upstream_recursive_servers(nameservers);
    status_ = Status::in_progress;
}

void ResolveCdnskeyUnsigned::on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
//    std::cout << _answer << std::endl;
    status_ = Status::completed;
    result_.trustiness = Result::Trustiness::insecure;
    result_.cdnskey.flags = 0;
    result_.cdnskey.protocol = 0;
    result_.cdnskey.algorithm = 0;
    result_.cdnskey.public_key.clear();
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
            result_.cdnskey = cdnskey;
        }
    }
}

void ResolveCdnskeyUnsigned::on_cancel(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "cancelled" << std::endl;
    status_ = Status::cancelled;
}

void ResolveCdnskeyUnsigned::on_timeout(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "timed_out" << std::endl;
    status_ = Status::timed_out;
}

void ResolveCdnskeyUnsigned::on_error(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "failed" << std::endl;
    status_ = Status::failed;
}


ResolveCdnskeySigned::ResolveCdnskeySigned(
        const boost::optional<GetDns::TransportList>& _transport_list,
        const GetDns::Data::List& _trust_anchors)
    : transport_list_(_transport_list),
      trust_anchors_(_trust_anchors),
      context_ptr_(NULL),
      status_(Status::none)
{
    result_.trustiness = Result::Trustiness::insecure;
    result_.cdnskey.flags = 0;
    result_.cdnskey.protocol = 0;
    result_.cdnskey.algorithm = 0;
}

ResolveCdnskeySigned::~ResolveCdnskeySigned()
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
}

ResolveCdnskeySigned::Status::Enum ResolveCdnskeySigned::get_status()const
{
    return status_;
}

const ResolveCdnskeySigned::Result& ResolveCdnskeySigned::get_result()const
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

GetDns::Context& ResolveCdnskeySigned::get_context()
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

::getdns_transaction_t ResolveCdnskeySigned::get_request_id()const
{
    if (request_id_)
    {
        return *request_id_;
    }
    throw std::runtime_error("request_id not set yet");
}

void ResolveCdnskeySigned::join(Event::Base& _event_base)
{
    if (context_ptr_ != NULL)
    {
        delete context_ptr_;
        context_ptr_ = NULL;
    }
    context_ptr_ = new GetDns::Context(_event_base, GetDns::Context::InitialSettings::from_os);
    std::list<boost::asio::ip::address> my_dns;
    my_dns.push_back(boost::asio::ip::address::from_string("172.16.1.183"));
    context_ptr_->set_upstream_recursive_servers(my_dns);
    context_ptr_->set_timeout(3000);
    if (transport_list_)
    {
        context_ptr_->set_dns_transport_list(*transport_list_);
    }
    if (0 < trust_anchors_.get_number_of_items())
    {
        context_ptr_->set_dnssec_trust_anchors(trust_anchors_);
    }
    status_ = Status::in_progress;
}

void ResolveCdnskeySigned::on_complete(const GetDns::Data::Dict& _answer, ::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << _answer << std::endl;
    status_ = Status::completed;
    result_.trustiness = Result::Trustiness::secure;
    result_.cdnskey.flags = 0;
    result_.cdnskey.protocol = 0;
    result_.cdnskey.algorithm = 0;
    result_.cdnskey.public_key.clear();
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
            result_.cdnskey = cdnskey;
        }
    }
}

void ResolveCdnskeySigned::on_cancel(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "cancelled" << std::endl;
    status_ = Status::cancelled;
}

void ResolveCdnskeySigned::on_timeout(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "timed_out" << std::endl;
    status_ = Status::timed_out;
}

void ResolveCdnskeySigned::on_error(::getdns_transaction_t _request_id)
{
    request_id_ = _request_id;
    std::cout << "failed" << std::endl;
    status_ = Status::failed;
}

namespace {

template <class T>
T split(const std::string& src, const std::string& delimiters, void(*append)(const std::string& item, T& container))
{
    std::vector<std::string> vector_of_items;
    boost::algorithm::split(vector_of_items, src, boost::algorithm::is_any_of(delimiters));
    T result;
    for (std::vector<std::string>::const_iterator item_itr = vector_of_items.begin();
            item_itr != vector_of_items.end(); ++item_itr)
    {
        append(*item_itr, result);
    }
    return result;
}

void append_ip_address(const std::string& item, std::vector<boost::asio::ip::address>& addresses)
{
    addresses.push_back(boost::asio::ip::address::from_string(item));
}

void append_trust_anchor(const std::string& item, GetDns::Data::List& anchors)
{
    std::istringstream dnskey(item);
    std::string zone;
    int flags;
    int protocol;
    int algorithm;
    std::string base64_encoded_public_key;
    dnskey >> zone >> flags >> protocol >> algorithm >> base64_encoded_public_key;
    const GetDns::Data::Dict anchor =
            GetDns::Data::Dict::get_trust_anchor(
                    zone,
                    flags,
                    protocol,
                    algorithm,
                    GetDns::Data::base64_decode(base64_encoded_public_key));
    std::cout << anchor << std::endl;
    GetDns::Data::set_item_of(anchors, anchors.get_number_of_items(), anchor.get_base_ptr());
}

}//namespace {anonymous}
