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
#include "src/insecure_cdnskey_resolver.hh"
#include "src/secure_cdnskey_resolver.hh"
#include "src/time_unit.hh"

#include "src/getdns/data.hh"
#include "src/getdns/context.hh"
#include "src/getdns/solver.hh"
#include "src/getdns/exception.hh"

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>

#include <sys/time.h>
#include <sys/resource.h>

#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <iostream>
#include <list>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

typedef std::set<std::string> Nameservers;
typedef std::set<std::string> Domains;

class DomainsToScan
{
public:
    DomainsToScan(std::istream& data_source);
    ~DomainsToScan() = default;
    std::size_t get_number_of_nameservers() const;
    std::size_t get_number_of_domains() const;
    std::size_t get_number_of_secure_domains() const;
    Nameservers get_nameservers() const;
    const Domains& get_signed_domains() const;
    Domains get_unsigned_domains_of(const std::string& nameserver) const;
private:
    DomainsToScan& append_data(const char* data_chunk, std::streamsize data_chunk_length);
    void data_finished();
    enum class Section
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

VectorOfInsecures resolve_hostnames_of_nameservers(
        const DomainsToScan& domains_to_scan,
        GetDns::Context::Timeout query_timeout,
        std::chrono::nanoseconds runtime,
        const std::list<boost::asio::ip::address>& resolvers);

template <class T>
T split(const std::string& src, const std::string& delimiters, void(*append)(const std::string& item, T& container));

void append_ip_address(const std::string& item, std::list<boost::asio::ip::address>& addresses);
void append_trust_anchor(const std::string& item, std::list<GetDns::TrustAnchor>& anchors);

extern const char cmdline_help_text[];

}//namespace {anonymous}

int main(int argc, char* argv[])
{
    if ((argc <= 0) || (argv[0] == nullptr))
    {
        std::cerr << "main() arguments are crazy" << std::endl;
        return EXIT_SUCCESS;
    }
    std::string hostname_resolvers_opt;
    std::string cdnskey_resolvers_opt;
    std::string dnssec_trust_anchors_opt;
    std::string timeout_opt;
    std::string runtime_opt;
    char** const arg_end = argv + argc;
    char** arg_ptr = argv + 1;
    while ((arg_ptr != arg_end) && (*arg_ptr != nullptr))
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
            if (*arg_ptr == nullptr)
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
            if (*arg_ptr == nullptr)
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
            if (*arg_ptr == nullptr)
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
            if (*arg_ptr == nullptr)
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
        ++arg_ptr;
    }
    if (runtime_opt.empty())
    {
        std::cerr << "runtime value has to be set" << std::endl;
        return EXIT_FAILURE;
    }
    else if (runtime_opt[0] == '-')
    {
        std::cerr << "unknown option: " << runtime_opt << std::endl;
        return EXIT_FAILURE;
    }
    try
    {
        const auto runtime = std::chrono::seconds{boost::lexical_cast<std::int64_t>(runtime_opt)};
        if (runtime <= std::chrono::seconds{0})
        {
            std::cerr << "lack of time" << std::endl;
            return EXIT_FAILURE;
        }
        {
            struct ::rlimit limit;
            const int success = 0;
            if (::getrlimit(RLIMIT_NOFILE, &limit) == success)
            {
                std::cerr << "getrlimit(RLIMIT_NOFILE, {" << limit.rlim_cur << ", " << limit.rlim_max << "})" << std::endl;
                const ::rlim_t min_nofile_value = 8192;
                if (limit.rlim_cur < min_nofile_value)
                {
                    const ::rlim_t new_nofile_value = min_nofile_value <= limit.rlim_max ? min_nofile_value : limit.rlim_max;
                    if (limit.rlim_cur < new_nofile_value)
                    {
                        limit.rlim_cur = new_nofile_value;
                        if (::setrlimit(RLIMIT_NOFILE, &limit) == success)
                        {
                            std::cerr << "setrlimit(RLIMIT_NOFILE, {" << limit.rlim_cur << ", " << limit.rlim_max << "})"
                                      << std::endl;
                        }
                        else
                        {
                            const int c_errno = errno;
                            std::cerr << "setrlimit(RLIMIT_NOFILE, {" << limit.rlim_cur << ", " << limit.rlim_max << "}) "
                                         "failed: " << std::strerror(c_errno) << std::endl;
                        }
                    }
                }
            }
            else
            {
                const int c_errno = errno;
                std::cerr << "getrlimit(RLIMIT_NOFILE) failed: " << std::strerror(c_errno) << std::endl;
            }
        }
        const std::list<boost::asio::ip::address> hostname_resolvers = split(hostname_resolvers_opt, ",", append_ip_address);
        const std::list<boost::asio::ip::address> cdnskey_resolvers = split(cdnskey_resolvers_opt, ",", append_ip_address);
        const std::list<GetDns::TrustAnchor> anchors = split(dnssec_trust_anchors_opt, ",", append_trust_anchor);
        static constexpr auto timeout_default = std::chrono::seconds{10};
        const auto query_timeout = GetDns::Context::Timeout{timeout_opt.empty() ? timeout_default
                                                                                : std::chrono::seconds{boost::lexical_cast<std::uint64_t>(timeout_opt)}};
        const DomainsToScan domains_to_scan(std::cin);
        if ((domains_to_scan.get_number_of_nameservers() <= 0) &&
            (domains_to_scan.get_number_of_secure_domains() <= 0))
        {
            return EXIT_SUCCESS;
        }
        const auto t_end = std::chrono::nanoseconds{TimeUnit::get_uptime().get() + runtime};
        VectorOfInsecures insecure_queries;
        {
            const std::size_t estimated_total_number_of_queries =
                    domains_to_scan.get_number_of_nameservers() + 2 * domains_to_scan.get_number_of_domains();
            std::cerr << "estimated_total_number_of_queries = " << estimated_total_number_of_queries << std::endl;
            const auto query_distance = static_cast<double>(runtime.count()) / estimated_total_number_of_queries;
            std::cerr << "query_distance = " << query_distance << std::endl;
            const std::size_t queries_to_ask_now = domains_to_scan.get_number_of_nameservers();
            std::cerr << "queries_to_ask_now = " << queries_to_ask_now << std::endl;
            const auto time_for_hostname_resolver = std::chrono::nanoseconds{static_cast<std::int64_t>(query_distance * queries_to_ask_now * 1000000000LL)};
            std::cerr << "time_for_hostname_resolver = " << time_for_hostname_resolver.count() << "ns" << std::endl;
            insecure_queries = resolve_hostnames_of_nameservers(
                    domains_to_scan,
                    query_timeout,
                    time_for_hostname_resolver,
                    hostname_resolvers);
        }
        const std::size_t number_of_insecure_queries = insecure_queries.size();
        std::cerr << "number_of_insecure_queries = " << number_of_insecure_queries << std::endl;
        const std::size_t number_of_secure_queries = domains_to_scan.get_number_of_secure_domains();
        std::cerr << "number_of_secure_queries = " << number_of_secure_queries << std::endl;
        const std::size_t total_number_of_queries = number_of_insecure_queries + number_of_secure_queries;
        const std::size_t max_number_of_queries_per_second = 1000;
        const auto min_runtime = std::chrono::nanoseconds{static_cast<std::int64_t>(total_number_of_queries / (max_number_of_queries_per_second / 1.0e+9))};
        auto time_to_the_end = t_end - TimeUnit::get_uptime().get();
        if (time_to_the_end < min_runtime)
        {
            time_to_the_end = min_runtime;
        }
        const double query_distance_nsec = double(time_to_the_end.count()) / total_number_of_queries;
        std::cerr << "query_distance = " << query_distance_nsec << "ns" << std::endl;
        const auto time_for_insecure_resolver = std::chrono::nanoseconds{static_cast<std::int64_t>(std::llround(query_distance_nsec * number_of_insecure_queries))};
        const auto time_for_secure_resolver = std::chrono::nanoseconds{static_cast<std::int64_t>(std::llround(query_distance_nsec * number_of_secure_queries))};
        InsecureCdnskeyResolver::resolve(
                insecure_queries,
                query_timeout,
                time_for_insecure_resolver);
        SecureCdnskeyResolver::resolve(
                domains_to_scan.get_signed_domains(),
                query_timeout,
                cdnskey_resolvers,
                GetDns::Data::TrustAnchorList{anchors},
                time_for_secure_resolver);
        return EXIT_SUCCESS;
    }
    catch (const Event::Exception& e)
    {
        std::cerr << "caught Event::Exception: " << e.what() << std::endl;
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

DomainsToScan::DomainsToScan(std::istream& data_source)
    : section_{Section::none},
      data_starts_at_new_line_{true}
{
    while (!data_source.eof())
    {
        const bool stdin_is_broken = !data_source;
        if (stdin_is_broken)
        {
            throw std::runtime_error("stream is broken");
        }
        char data_chunk[0x10000];
        data_source.read(data_chunk, sizeof(data_chunk));
        const std::streamsize data_chunk_length = data_source.gcount();
        this->append_data(data_chunk, data_chunk_length);
    }
    this->data_finished();
}

std::size_t DomainsToScan::get_number_of_nameservers() const
{
    return unsigned_domains_of_namserver_.size();
}

std::size_t DomainsToScan::get_number_of_domains() const
{
    std::size_t sum_count = signed_domains_.size();
    for (DomainsOfNamserver::const_iterator itr = unsigned_domains_of_namserver_.begin();
         itr != unsigned_domains_of_namserver_.end(); ++itr)
    {
        sum_count += itr->second.size();
    }
    return sum_count;
}

std::size_t DomainsToScan::get_number_of_secure_domains() const
{
    return signed_domains_.size();
}

constexpr auto section_of_signed_domains = "[secure]";
constexpr auto section_of_unsigned_domains = "[insecure]";

DomainsToScan& DomainsToScan::append_data(const char* data_chunk, std::streamsize data_chunk_length)
{
    const char* const data_end = data_chunk + data_chunk_length;
    const char* item_begin = data_chunk;
    const char* current_pos = data_chunk;
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
                section_ = Section::secure;
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
                section_ = Section::insecure;
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
            case Section::secure:
                if (!item.empty())
                {
                    signed_domains_.insert(item);
                }
                else
                {
                    std::cerr << "secure section contains an empty fqdn of domain" << std::endl;
                }
                break;
            case Section::insecure:
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
            case Section::none:
                throw std::runtime_error("no section specified yet");
        }
        if (line_end_reached)
        {
            const bool nameserver_data_available =
                    (section_ == Section::insecure) && !nameserver_.empty() && !unsigned_domains_.empty();
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

void DomainsToScan::data_finished()
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
        case Section::secure:
            if (!item.empty())
            {
                signed_domains_.insert(item);
            }
            return;
        case Section::insecure:
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
        case Section::none:
            throw std::runtime_error("no section specified yet");
    }
}

VectorOfInsecures resolve_hostnames_of_nameservers(
        const DomainsToScan& domains_to_scan,
        GetDns::Context::Timeout query_timeout,
        std::chrono::nanoseconds runtime,
        const std::list<boost::asio::ip::address>& resolvers)
{
    typedef std::set<boost::asio::ip::address> IpAddresses;
    typedef std::map<std::string, IpAddresses> IpAddressesOfNameservers;
    typedef std::map<std::string, Nameservers> DomainNameservers;
    typedef std::map<boost::asio::ip::address, DomainNameservers> IpAddressesToDomainNameservers;
    const Nameservers nameservers = domains_to_scan.get_nameservers();
    const auto nameserver_addresses = HostnameResolver::get_result(
            nameservers,
            query_timeout,
            resolvers,
            runtime);

    IpAddressesToDomainNameservers addresses_to_domains;
    for (IpAddressesOfNameservers::const_iterator nameserver_itr = nameserver_addresses.begin();
         nameserver_itr != nameserver_addresses.end(); ++nameserver_itr)
    {
        const std::string nameserver = nameserver_itr->first;
        const Domains domains = domains_to_scan.get_unsigned_domains_of(nameserver);
        for (IpAddresses::const_iterator address_itr = nameserver_itr->second.begin();
             address_itr != nameserver_itr->second.end(); ++address_itr)
        {
            DomainNameservers& domain_nameservers = addresses_to_domains[*address_itr];
            for (Domains::const_iterator domain_itr = domains.begin(); domain_itr != domains.end(); ++domain_itr)
            {
                domain_nameservers[*domain_itr].insert(nameserver);
            }
        }
    }

    std::size_t number_of_items = 0;
    for (IpAddressesToDomainNameservers::const_iterator address_itr = addresses_to_domains.begin();
         address_itr != addresses_to_domains.end(); ++address_itr)
    {
        number_of_items += address_itr->second.size();
    }
    VectorOfInsecures result;
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
    std::shuffle(result.begin(), result.end(), std::mt19937(std::random_device()()));
    return result;
}

Nameservers DomainsToScan::get_nameservers()const
{
    Nameservers nameservers;
    for (DomainsOfNamserver::const_iterator nameserver_itr = unsigned_domains_of_namserver_.begin();
         nameserver_itr != unsigned_domains_of_namserver_.end(); ++nameserver_itr)
    {
        nameservers.insert(nameserver_itr->first);
    }
    return nameservers;
}

const Domains& DomainsToScan::get_signed_domains()const
{
    return signed_domains_;
}

Domains DomainsToScan::get_unsigned_domains_of(const std::string& _nameserver)const
{
    const DomainsOfNamserver::const_iterator nameserver_itr = unsigned_domains_of_namserver_.find(_nameserver);
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

void append_trust_anchor(const std::string& item, std::list<GetDns::TrustAnchor>& anchors)
{
    std::istringstream anchor_stream(item);
    std::string zone;
    int flags;
    int protocol;
    int algorithm;
    std::string base64_encoded_public_key;
    anchor_stream >> zone
                  >> flags
                  >> protocol
                  >> algorithm
                  >> base64_encoded_public_key;
    GetDns::TrustAnchor trust_anchor;
    trust_anchor.zone = zone;
    trust_anchor.flags = flags;
    trust_anchor.protocol = protocol;
    trust_anchor.algorithm = algorithm;
    trust_anchor.public_key = base64_encoded_public_key;
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
