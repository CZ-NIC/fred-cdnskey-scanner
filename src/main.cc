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
#include "src/insecure_cdnskey_resolver.hh"
#include "src/secure_cdnskey_resolver.hh"
#include "src/time_unit.hh"

#include "src/getdns/data.hh"
#include "src/getdns/context.hh"
#include "src/getdns/solver.hh"
#include "src/getdns/exception.hh"
#include "src/getdns/error.hh"

#include <algorithm>
#include <string>
#include <set>
#include <map>
#include <list>
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
#include <boost/lexical_cast.hpp>

namespace {

typedef std::set<std::string> Nameservers;
typedef std::set<std::string> Domains;

class DomainsToScanning
{
public:
    DomainsToScanning(std::istream& _data_source);
    ~DomainsToScanning();
    std::size_t get_number_of_nameservers()const;
    std::size_t get_number_of_domains()const;
    std::size_t get_number_of_secure_domains()const;
    Nameservers get_nameservers()const;
    const Domains& get_signed_domains()const;
    Domains get_unsigned_domains_of(const std::string& _nameserver)const;
private:
    DomainsToScanning& append_data(const char* _data_chunk, std::streamsize _data_chunk_length);
    void data_finished();
    enum Section
    {
        none,
        secure,
        insecure,
    } section_;
    typedef std::map<std::string, Domains> DomainsOfNamserver;
    DomainsOfNamserver unsigned_domains_of_namserver_;
    std::string nameserver_;
    Domains signed_domains_;
    Domains unsigned_domains_;
    std::string rest_of_data_;
    bool data_starts_at_new_line_;
};

void resolve_hostnames_of_nameservers(
        const DomainsToScanning& domains_to_scanning,
        const TimeUnit::Seconds& timeout_sec,
        const TimeUnit::Nanoseconds& runtime_usec,
        const boost::optional<GetDns::TransportList>& transport_list,
        const std::list<boost::asio::ip::address>& resolvers,
        VectorOfInsecures& result);

template <class T>
T split(const std::string& src, const std::string& delimiters, void(*append)(const std::string& item, T& container));

void append_ip_address(const std::string& item, std::list<boost::asio::ip::address>& addresses);
void append_trust_anchor(const std::string& item, std::list<GetDns::Data::TrustAnchor>& anchors);

extern const char cmdline_help_text[];

}//namespace {anonymous}

int main(int, char* argv[])
{
    std::string hostname_resolvers_opt;
    std::string cdnskey_resolvers_opt;
    std::string dnssec_trust_anchors_opt;
    std::string timeout_opt;
    std::string runtime_opt;
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
        else if (std::strcmp(*arg_ptr, "--timeout") == are_the_same)
        {
            if (!timeout_opt.empty())
            {
                std::cerr << "timeout option can be used once only" << std::endl;
                return EXIT_FAILURE;
            }
            ++arg_ptr;
            if (*arg_ptr == NULL)
            {
                std::cerr << "no argument for timeout option" << std::endl;
                return EXIT_FAILURE;
            }
            timeout_opt = *arg_ptr;
            if (timeout_opt.empty())
            {
                std::cerr << "timeout argument can not be empty" << std::endl;
                return EXIT_FAILURE;
            }
        }
        else if (std::strcmp(*arg_ptr, "--help") == are_the_same)
        {
            std::cerr << cmdline_help_text << std::endl;
            return EXIT_SUCCESS;
        }
        else
        {
            if (!runtime_opt.empty())
            {
                std::cerr << "runtime value has to be set once only" << std::endl;
                return EXIT_FAILURE;
            }
            runtime_opt = *arg_ptr;
            if (runtime_opt.empty())
            {
                std::cerr << "runtime value can not be empty" << std::endl;
                return EXIT_FAILURE;
            }
        }
    }
    if (runtime_opt.empty())
    {
        std::cerr << "runtime value has to be set" << std::endl;
        return EXIT_FAILURE;
    }
    try
    {
        const TimeUnit::Seconds runtime(boost::lexical_cast< ::int64_t >(runtime_opt));
        if (runtime.value <= 0)
        {
            std::cerr << "lack of time" << std::endl;
            return EXIT_FAILURE;
        }
        const std::list<boost::asio::ip::address> hostname_resolvers = split(hostname_resolvers_opt, ",", append_ip_address);
        const std::list<boost::asio::ip::address> cdnskey_resolvers = split(cdnskey_resolvers_opt, ",", append_ip_address);
        const std::list<GetDns::Data::TrustAnchor> anchors = split(dnssec_trust_anchors_opt, ",", append_trust_anchor);
        const TimeUnit::Seconds timeout_default(10);
        const TimeUnit::Seconds query_timeout = timeout_opt.empty() ? timeout_default
                                                          : TimeUnit::Seconds(boost::lexical_cast< ::uint64_t >(timeout_opt));
        const DomainsToScanning domains_to_scanning(std::cin);
        if ((domains_to_scanning.get_number_of_nameservers() <= 0) &&
            (domains_to_scanning.get_number_of_secure_domains() <= 0))
        {
            return EXIT_SUCCESS;
        }
        const struct ::timespec t_end = TimeUnit::get_clock_monotonic() + runtime;
        GetDns::TransportList tcp_only;
        tcp_only.push_back(GetDns::Transport::tcp);
        GetDns::TransportList udp_first;
        udp_first.push_back(GetDns::Transport::udp);
        udp_first.push_back(GetDns::Transport::tcp);
        VectorOfInsecures insecure_queries;
        {
            const std::size_t estimated_total_number_of_queries =
                    domains_to_scanning.get_number_of_nameservers() + 2 * domains_to_scanning.get_number_of_domains();
            std::cerr << "estimated_total_number_of_queries = " << estimated_total_number_of_queries << std::endl;
            const double query_distance = double(runtime.value) / estimated_total_number_of_queries;
            std::cerr << "query_distance = " << query_distance << std::endl;
            const std::size_t queries_to_ask_now = domains_to_scanning.get_number_of_nameservers();
            std::cerr << "queries_to_ask_now = " << queries_to_ask_now << std::endl;
            const TimeUnit::Nanoseconds time_for_hostname_resolver(query_distance * queries_to_ask_now * 1000000000LL);
            std::cerr << "time_for_hostname_resolver = " << time_for_hostname_resolver.value << "ns" << std::endl;
            resolve_hostnames_of_nameservers(
                    domains_to_scanning,
                    query_timeout,
                    time_for_hostname_resolver,
                    udp_first,
                    hostname_resolvers,
                    insecure_queries);
        }
        const std::size_t number_of_insecure_queries = insecure_queries.size();
        std::cerr << "number_of_insecure_queries = " << number_of_insecure_queries << std::endl;
        const std::size_t number_of_secure_queries = domains_to_scanning.get_number_of_secure_domains();
        std::cerr << "number_of_secure_queries = " << number_of_secure_queries << std::endl;
        const std::size_t total_number_of_queries = number_of_insecure_queries + number_of_secure_queries;
        const std::size_t max_number_of_queries_per_second = 1000;
        const TimeUnit::Nanoseconds min_runtime(total_number_of_queries / (max_number_of_queries_per_second / 1.0e+9));
        TimeUnit::Nanoseconds time_to_the_end = t_end - TimeUnit::get_clock_monotonic();
        if (time_to_the_end.value < min_runtime.value)
        {
            time_to_the_end = min_runtime;
        }
        const double query_distance_nsec = double(time_to_the_end.value) / total_number_of_queries;
        std::cerr << "query_distance = " << query_distance_nsec << "ns" << std::endl;
        const TimeUnit::Nanoseconds time_for_insecure_resolver((query_distance_nsec * number_of_insecure_queries) + 0.5);
        const TimeUnit::Nanoseconds time_for_secure_resolver((query_distance_nsec * number_of_secure_queries) + 0.5);
        InsecureCdnskeyResolver::resolve(
                insecure_queries,
                query_timeout,
                tcp_only,
                time_for_insecure_resolver);
        SecureCdnskeyResolver::resolve(
                domains_to_scanning.get_signed_domains(),
                query_timeout,
                tcp_only,
                cdnskey_resolvers,
                anchors,
                time_for_secure_resolver);
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

namespace {

DomainsToScanning::DomainsToScanning(std::istream& _data_source)
    : section_(none),
      data_starts_at_new_line_(true)
{
    while (!_data_source.eof())
    {
        const bool stdin_is_broken = !_data_source;
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

std::size_t DomainsToScanning::get_number_of_nameservers()const
{
    return unsigned_domains_of_namserver_.size();
}

std::size_t DomainsToScanning::get_number_of_domains()const
{
    std::size_t sum_count = signed_domains_.size();
    for (DomainsOfNamserver::const_iterator itr = unsigned_domains_of_namserver_.begin();
         itr != unsigned_domains_of_namserver_.end(); ++itr)
    {
        sum_count += itr->second.size();
    }
    return sum_count;
}

std::size_t DomainsToScanning::get_number_of_secure_domains()const
{
    return signed_domains_.size();
}

const char section_of_signed_domains[] = "[secure]";
const char section_of_unsigned_domains[] = "[insecure]";

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
        rest_of_data_.clear();
        const bool check_section_flag = data_starts_at_new_line_ && line_end_reached;
        if (check_section_flag)
        {
            const bool section_of_signed_domains_reached = item == section_of_signed_domains;
            if (section_of_signed_domains_reached)
            {
                section_ = secure;
                nameserver_.clear();
                unsigned_domains_.clear();
                data_starts_at_new_line_ = true;
                ++current_pos;
                item_begin = current_pos;
                continue;
            }
            const bool section_of_unsigned_domains_reached = item == section_of_unsigned_domains;
            if (section_of_unsigned_domains_reached)
            {
                section_ = insecure;
                nameserver_.clear();
                unsigned_domains_.clear();
                data_starts_at_new_line_ = true;
                ++current_pos;
                item_begin = current_pos;
                continue;
            }
        }
        switch (section_)
        {
            case secure:
                if (!item.empty())
                {
                    signed_domains_.insert(item);
                }
                else
                {
                    std::cerr << "secure section contains an empty fqdn of domain" << std::endl;
                }
                break;
            case insecure:
            {
                const bool item_is_nameserver = data_starts_at_new_line_;
                if (item_is_nameserver)
                {
                    if (item.empty())
                    {
                        throw std::runtime_error("insecure section contains an empty hostname of nameserver");
                    }
                    nameserver_ = item;
                    data_starts_at_new_line_ = false;
                    unsigned_domains_.clear();
                }
                else
                {
                    if (!item.empty())
                    {
                        unsigned_domains_.insert(item);
                    }
                    else
                    {
                        std::cerr << "insecure section contains an empty fqdn of domain" << std::endl;
                    }
                }
                break;
            }
            case none:
                throw std::runtime_error("no section specified yet");
        }
        if (line_end_reached)
        {
            const bool nameserver_data_available = (section_ == insecure) && !nameserver_.empty() && !unsigned_domains_.empty();
            if (nameserver_data_available)
            {
                unsigned_domains_of_namserver_.insert(std::make_pair(nameserver_, unsigned_domains_));
            }
            nameserver_.clear();
            unsigned_domains_.clear();
            data_starts_at_new_line_ = true;
        }
        ++current_pos;
        item_begin = current_pos;
    }
    const std::size_t rest_of_data_length = current_pos - item_begin;
    rest_of_data_.append(item_begin, rest_of_data_length);
    return *this;
}

void DomainsToScanning::data_finished()
{
    const std::string item = rest_of_data_;
    const bool check_section_flag = data_starts_at_new_line_;
    if (check_section_flag)
    {
        const bool section_of_signed_domains_reached = item == section_of_signed_domains;
        if (section_of_signed_domains_reached)
        {
            return;
        }
        const bool section_of_unsigned_domains_reached = item == section_of_unsigned_domains;
        if (section_of_unsigned_domains_reached)
        {
            return;
        }
    }
    switch (section_)
    {
        case secure:
            if (!item.empty())
            {
                signed_domains_.insert(item);
            }
            return;
        case insecure:
        {
            const bool item_is_nameserver = data_starts_at_new_line_;
            if (!item_is_nameserver)
            {
                if (!item.empty())
                {
                    unsigned_domains_.insert(item);
                }
                const bool nameserver_data_available = !nameserver_.empty() && !unsigned_domains_.empty();
                if (nameserver_data_available)
                {
                    unsigned_domains_of_namserver_.insert(std::make_pair(nameserver_, unsigned_domains_));
                }
                nameserver_.clear();
                unsigned_domains_.clear();
            }
            return;
        }
        case none:
            throw std::runtime_error("no section specified yet");
    }
}

void resolve_hostnames_of_nameservers(
        const DomainsToScanning& domains_to_scanning,
        const TimeUnit::Seconds& query_timeout,
        const TimeUnit::Nanoseconds& runtime_nsec,
        const boost::optional<GetDns::TransportList>& transport_list,
        const std::list<boost::asio::ip::address>& resolvers,
        VectorOfInsecures& result)
{
    typedef std::set<boost::asio::ip::address> IpAddresses;
    typedef std::map<std::string, IpAddresses> IpAddressesOfNameservers;
    typedef std::map<std::string, Nameservers> DomainNameservers;
    typedef std::map<boost::asio::ip::address, DomainNameservers> IpAddressesToDomainNameservers;
//    GetDns::Extensions extensions;
    const Nameservers nameservers = domains_to_scanning.get_nameservers();
    const HostnameResolver::Result nameserver_addresses = HostnameResolver::get_result(
            nameservers,
            query_timeout,
            transport_list,
            resolvers,
            runtime_nsec);

    IpAddressesToDomainNameservers addresses_to_domains;
    for (IpAddressesOfNameservers::const_iterator nameserver_itr = nameserver_addresses.begin();
         nameserver_itr != nameserver_addresses.end(); ++nameserver_itr)
    {
        const std::string nameserver = nameserver_itr->first;
//        std::cerr << nameserver;
        const Domains domains = domains_to_scanning.get_unsigned_domains_of(nameserver);
        for (IpAddresses::const_iterator address_itr = nameserver_itr->second.begin();
             address_itr != nameserver_itr->second.end(); ++address_itr)
        {
//            std::cerr << " " << *address_itr;
            DomainNameservers& domain_nameservers = addresses_to_domains[*address_itr];
            for (Domains::const_iterator domain_itr = domains.begin(); domain_itr != domains.end(); ++domain_itr)
            {
                domain_nameservers[*domain_itr].insert(nameserver);
            }
        }
//        std::cerr << std::endl;
    }

    std::size_t number_of_items = 0;
    for (IpAddressesToDomainNameservers::const_iterator address_itr = addresses_to_domains.begin();
         address_itr != addresses_to_domains.end(); ++address_itr)
    {
        number_of_items += address_itr->second.size();
    }
    result.clear();
    result.reserve(number_of_items);
    for (IpAddressesToDomainNameservers::const_iterator address_itr = addresses_to_domains.begin();
         address_itr != addresses_to_domains.end(); ++address_itr)
    {
        Insecure item;
        item.address = address_itr->first;
        for (DomainNameservers::const_iterator domain_itr = address_itr->second.begin();
             domain_itr != address_itr->second.end(); ++domain_itr)
        {
            item.domain = domain_itr->first;
            item.nameservers = domain_itr->second;
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

template <class T>
T split(const std::string& src, const std::string& delimiters, void(*append)(const std::string& item, T& container))
{
    if (src.empty())
    {
        return T();
    }
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

void append_ip_address(const std::string& item, std::list<boost::asio::ip::address>& addresses)
{
    addresses.push_back(boost::asio::ip::address::from_string(item));
}

void append_trust_anchor(const std::string& item, std::list<GetDns::Data::TrustAnchor>& anchors)
{
    std::istringstream anchor_stream(item);
    std::string zone;
    int flags;
    int protocol;
    int algorithm;
    std::string public_key;
    std::string base64_encoded_public_key;
    anchor_stream >> zone
                  >> flags
                  >> protocol
                  >> algorithm
                  >> base64_encoded_public_key;
    GetDns::Data::TrustAnchor trust_anchor;
    trust_anchor.zone = zone;
    trust_anchor.flags = flags;
    trust_anchor.protocol = protocol;
    trust_anchor.algorithm = algorithm;
    trust_anchor.public_key = GetDns::Data::base64_decode(base64_encoded_public_key);
    anchors.push_back(trust_anchor);
}

const char cmdline_help_text[] =
        "Scanner of CDNSKEY records.\n\n"
        "usage: cdnskey-scanner [--hostname_resolvers IP address[,...]] "
                               "[--cdnskey_resolvers IP address[,...]] "
                               "[--dnssec_trust_anchors anchor[,...]] "
                               "[--timeout sec] "
                               "RUNTIME | "
                               "--help\n\n"
        "    Arguments:\n"
        "        --hostname_resolvers ..... IP addresses of resolvers used for resolving A and AAAA\n"
        "                                   records of nameservers; default is in system configured\n"
        "                                   resolver\n"
        "        --cdnskey_resolvers ...... IP addresses of resolvers used for resolving signed CDNSKEY\n"
        "                                   records of domains; default is in system configured\n"
        "                                   resolver\n"
        "        --dnssec_trust_anchors ... chain of trust for verification of signed CDNSKEY records;\n"
        "                                   default is in system configured chain of trust\n"
        "            * anchor's format: zone flags protocol algorithm public_key_base64\n"
        "                       example: . 257 3 8 AwEAAdAjHYjq...xAU8=\n"
        "        --timeout ................ maximum time (in seconds) spent by one DNS request;\n"
        "                                   default is 10 seconds\n"
        "        RUNTIME .................. total time (in seconds) reserved for application run\n"
        "        --help ................... this help\n\n"
        "    Format of data received from standard input:\n"
        "        [secure]\n"
        "        podepsana1.cz podepsana2.cz ... podepsanaN.cz\n"
        "        [insecure]\n"
        "        nameserver1.cz domena1.cz domena2.cz ... domenaN.cz\n"
        "        nameserver2.sk blabla1.cz blabla2.cz ... blablaM.cz\n\n"
        "    Format of data sent to standard output:\n"
        "        insecure nameserver ip domain flags protocol algorithm public_key_base64\n"
        "        insecure-empty nameserver ip domain\n"
        "        secure domain flags protocol algorithm public_key_base64\n"
        "        secure-empty domain\n"
        "        untrustworthy domain\n"
        "        unknown domain\n"
        "        unresolved nameserver ip domain\n"
        "        unresolved-ip nameserver\n";

}//namespace {anonymous}
