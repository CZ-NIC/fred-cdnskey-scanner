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

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"
#include "src/getdns/error.hh"
#include "src/getdns/exception.hh"

#include <getdns/getdns_ext_libevent.h>

#include <array>
#include <vector>

namespace GetDns
{

Context::Context(Event::Base& _event_base, InitialSettings::Enum _initial_settings)
    : free_on_exit_(_initial_settings)
{
    const ::getdns_return_t retval = ::getdns_extension_set_libevent_base(free_on_exit_.context_ptr, _event_base.get_base());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct SetEventBaseException:Error
        {
            explicit SetEventBaseException(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw SetEventBaseException(retval);
    }
}

Context::~Context()
{
}

::getdns_transaction_t Context::add_request_for_address_resolving(
        const std::string& _hostname,
        void* _user_data_ptr,
        ::getdns_callback_t _on_event,
        Extensions _extensions)
{
    Data::Dict extensions = _extensions.into_dictionary();
    ::getdns_transaction_t transaction_id;
    const ::getdns_return_t retval = ::getdns_address(
            free_on_exit_.context_ptr,
            _hostname.c_str(),
            extensions.get_base_ptr(),
            _user_data_ptr,
            &transaction_id,
            _on_event);
    if (retval == ::GETDNS_RETURN_GOOD)
    {
        return transaction_id;
    }
    struct AddressException:Error
    {
        explicit AddressException(::getdns_return_t _error_code):Error(_error_code) { }
    };
    throw AddressException(retval);
}

::getdns_transaction_t Context::add_request_for_cdnskey_resolving(
        const std::string& _domain,
        void* _user_data_ptr,
        ::getdns_callback_t _on_event,
        Extensions _extensions)
{
    Data::Dict extensions = _extensions.into_dictionary();
    ::getdns_transaction_t transaction_id;
    const ::getdns_return_t retval = ::getdns_general(
            free_on_exit_.context_ptr,
            _domain.c_str(),
            GETDNS_RRTYPE_CDNSKEY,
            extensions.get_base_ptr(),
            _user_data_ptr,
            &transaction_id,
            _on_event);
    if (retval == ::GETDNS_RETURN_GOOD)
    {
        return transaction_id;
    }
    struct AddressException:Error
    {
        explicit AddressException(::getdns_return_t _error_code):Error(_error_code) { }
    };
    throw AddressException(retval);
}

Context& Context::set_dns_transport_list(const TransportList& _transport_list)
{
    std::vector< ::getdns_transport_list_t > list;
    list.reserve(_transport_list.size());
    for (TransportList::const_iterator transport = _transport_list.begin();
         transport != _transport_list.end();
         ++transport)
    {
        class Convert
        {
        public:
            explicit Convert(Transport::Protocol _what):what_(_what) { }
            ::getdns_transport_list_t into_enum()const
            {
                switch (what_)
                {
                    case Transport::udp: return ::GETDNS_TRANSPORT_UDP;
                    case Transport::tcp: return ::GETDNS_TRANSPORT_TCP;
                    case Transport::tls: return ::GETDNS_TRANSPORT_TLS;
                }
                struct UnexpectedValue:Exception
                {
                    const char* what()const throw() { return "unexpected value of Transport::Protocol"; }
                };
                throw UnexpectedValue();
            }
        private:
            const Transport::Protocol what_;
        };
        list.push_back(Convert(*transport).into_enum());
    }
    const ::getdns_return_t retval = ::getdns_context_set_dns_transport_list(
            free_on_exit_.context_ptr,
            _transport_list.size(),
            &(*list.begin()));
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetDnsTransportListException:Error
        {
            explicit ContextSetDnsTransportListException(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextSetDnsTransportListException(retval);
    }
    return *this;
}

Context& Context::set_upstream_recursive_servers(const std::list<boost::asio::ip::address>& _servers)
{
    typedef std::list<boost::asio::ip::address> Addresses;
    Data::List list;
    for (Addresses::const_iterator address = _servers.begin(); address != _servers.end(); ++address)
    {
        Data::Dict item;
        if (address->is_v4())
        {
            Data::set_item_of(item, "address_type", "IPv4");
            typedef boost::asio::ip::address_v4::bytes_type IpAddressData;
            const ::getdns_bindata address_data =
                    {
                        sizeof(IpAddressData::value_type[std::tuple_size<IpAddressData>::value]),
                        address->to_v4().to_bytes().data()
                    };
            Data::set_item_of(item, "address_data", &address_data);
        }
        else if (address->is_v6())
        {
            Data::set_item_of(item, "address_type", "IPv6");
            typedef boost::asio::ip::address_v6::bytes_type IpAddressData;
            const ::getdns_bindata address_data =
                    {
                        sizeof(IpAddressData::value_type[std::tuple_size<IpAddressData>::value]),
                        address->to_v6().to_bytes().data()
                    };
            Data::set_item_of(item, "address_data", &address_data);
        }
        Data::set_item_of(list, list.get_number_of_items(), const_cast<const Data::Dict&>(item).get_base_ptr());
    }
    const ::getdns_return_t retval = ::getdns_context_set_upstream_recursive_servers(
            free_on_exit_.context_ptr,
            list.get_base_ptr());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetUpstreamRecursiveServersFailure:Error
        {
            explicit ContextSetUpstreamRecursiveServersFailure(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextSetUpstreamRecursiveServersFailure(retval);
    }
    struct SetResolution
    {
        static void stub(::getdns_context* _context)
        {
            const ::getdns_return_t retval = ::getdns_context_set_resolution_type(
                    _context,
                    ::GETDNS_RESOLUTION_STUB);
            if (retval != ::GETDNS_RETURN_GOOD)
            {
                struct ContextSetResolutionStubFailure:Error
                {
                    explicit ContextSetResolutionStubFailure(::getdns_return_t _error_code):Error(_error_code) { }
                };
                throw ContextSetResolutionStubFailure(retval);
            }
        }
    };
    SetResolution::stub(free_on_exit_.context_ptr);
    return *this;
}

Context& Context::set_follow_redirects(bool _yes)
{
    const ::getdns_return_t retval = ::getdns_context_set_follow_redirects(
            free_on_exit_.context_ptr,
            _yes ? ::GETDNS_REDIRECTS_FOLLOW : ::GETDNS_REDIRECTS_DO_NOT_FOLLOW);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetFollowRedirectsFailure:Error
        {
            explicit ContextSetFollowRedirectsFailure(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextSetFollowRedirectsFailure(retval);
    }
    return *this;
}

Context& Context::set_timeout(::uint64_t _value_ms)
{
    const ::getdns_return_t retval = ::getdns_context_set_timeout(free_on_exit_.context_ptr, _value_ms);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetTimeoutFailure:Error
        {
            explicit ContextSetTimeoutFailure(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextSetTimeoutFailure(retval);
    }
    return *this;
}

Context& Context::set_dnssec_trust_anchors(const std::list<Data::TrustAnchor>& _anchors)
{
    Data::List anchors;
    for (std::list<Data::TrustAnchor>::const_iterator anchor_itr = _anchors.begin(); anchor_itr != _anchors.end(); ++anchor_itr)
    {
        const Data::Dict anchor = Data::Dict::get_trust_anchor(
                anchor_itr->zone,
                anchor_itr->flags,
                anchor_itr->protocol,
                anchor_itr->algorithm,
                anchor_itr->public_key);
        Data::set_item_of(anchors, anchors.get_number_of_items(), anchor.get_base_ptr());
    }
    const ::getdns_return_t retval = ::getdns_context_set_dnssec_trust_anchors(
            free_on_exit_.context_ptr,
            anchors.get_base_ptr());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetDnssecTrustAnchorsFailure:Error
        {
            explicit ContextSetDnssecTrustAnchorsFailure(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextSetDnssecTrustAnchorsFailure(retval);
    }
    return *this;
}

::getdns_context* Context::release_context()
{
    ::getdns_context* const context_ptr = free_on_exit_.context_ptr;
    free_on_exit_.context_ptr = NULL;
    return context_ptr;
}

Context::FreeOnExit::FreeOnExit(InitialSettings::Enum _initial_settings)
    : context_ptr(NULL)
{
    const ::getdns_return_t retval = ::getdns_context_create(&context_ptr, _initial_settings == InitialSettings::from_os ? 1 : 0);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextCreateException:Error
        {
            explicit ContextCreateException(::getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextCreateException(retval);
    }
}

Context::FreeOnExit::~FreeOnExit()
{
    if (context_ptr != NULL)
    {
        ::getdns_context_destroy(context_ptr);
        context_ptr = NULL;
    }
}

}//namespace GetDns
