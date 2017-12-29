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

namespace GetDns {

namespace {

::getdns_context* create_context(Context::InitialSettings initial_settings)
{
    ::getdns_context* context_ptr = nullptr;
    const ::getdns_return_t retval = ::getdns_context_create(
            &context_ptr,
            initial_settings == Context::InitialSettings::from_os ? 1 : 0);
    if (retval == ::GETDNS_RETURN_GOOD)
    {
        return context_ptr;
    }
    struct ContextCreateException:Error
    {
        ContextCreateException(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw ContextCreateException(retval, __FILE__, __LINE__);
}

}//namespace GetDns::{anonymous}

Context::Context(Event::Base& _event_base, InitialSettings _initial_settings)
    : context_ptr_(create_context(_initial_settings))
{
    const ::getdns_return_t retval = ::getdns_extension_set_libevent_base(context_ptr_.get(), _event_base.get_base());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct SetEventBaseException:Error
        {
            SetEventBaseException(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw SetEventBaseException(retval, __FILE__, __LINE__);
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
            context_ptr_.get(),
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
        AddressException(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw AddressException(retval, __FILE__, __LINE__);
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
            context_ptr_.get(),
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
        AddressException(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw AddressException(retval, __FILE__, __LINE__);
}

Context& Context::set_dns_transport_list(const TransportList& _transport_list)
{
    std::vector<::getdns_transport_list_t> list;
    list.reserve(_transport_list.size());
    for (TransportList::const_iterator transport = _transport_list.begin();
         transport != _transport_list.end();
         ++transport)
    {
        class Convert
        {
        public:
            explicit Convert(TransportProtocol _what):what_(_what) { }
            ::getdns_transport_list_t into_enum()const
            {
                switch (what_)
                {
                    case TransportProtocol::udp: return ::GETDNS_TRANSPORT_UDP;
                    case TransportProtocol::tcp: return ::GETDNS_TRANSPORT_TCP;
                    case TransportProtocol::tls: return ::GETDNS_TRANSPORT_TLS;
                }
                struct UnexpectedValue:Exception
                {
                    const char* what()const noexcept { return "unexpected value of Transport::Protocol"; }
                };
                throw UnexpectedValue();
            }
        private:
            const TransportProtocol what_;
        };
        list.emplace_back(Convert(*transport).into_enum());
    }
    const ::getdns_return_t retval = ::getdns_context_set_dns_transport_list(
            context_ptr_.get(),
            _transport_list.size(),
            list.data());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetDnsTransportListException:Error
        {
            ContextSetDnsTransportListException(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ContextSetDnsTransportListException(retval, __FILE__, __LINE__);
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
            context_ptr_.get(),
            list.get_base_ptr());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetUpstreamRecursiveServersFailure:Error
        {
            ContextSetUpstreamRecursiveServersFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ContextSetUpstreamRecursiveServersFailure(retval, __FILE__, __LINE__);
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
                    ContextSetResolutionStubFailure(::getdns_return_t _error_code, const char* _file, int _line)
                        : Error(_error_code, _file, _line)
                    { }
                };
                throw ContextSetResolutionStubFailure(retval, __FILE__, __LINE__);
            }
        }
    };
    SetResolution::stub(context_ptr_.get());
    return *this;
}

Context& Context::set_follow_redirects(bool _yes)
{
    const ::getdns_return_t retval = ::getdns_context_set_follow_redirects(
            context_ptr_.get(),
            _yes ? ::GETDNS_REDIRECTS_FOLLOW : ::GETDNS_REDIRECTS_DO_NOT_FOLLOW);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetFollowRedirectsFailure:Error
        {
            ContextSetFollowRedirectsFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ContextSetFollowRedirectsFailure(retval, __FILE__, __LINE__);
    }
    return *this;
}

Context& Context::set_timeout(std::uint64_t _value_ms)
{
    const ::getdns_return_t retval = ::getdns_context_set_timeout(context_ptr_.get(), _value_ms);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetTimeoutFailure:Error
        {
            ContextSetTimeoutFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ContextSetTimeoutFailure(retval, __FILE__, __LINE__);
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
            context_ptr_.get(),
            anchors.get_base_ptr());
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetDnssecTrustAnchorsFailure:Error
        {
            ContextSetDnssecTrustAnchorsFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ContextSetDnssecTrustAnchorsFailure(retval, __FILE__, __LINE__);
    }
    return *this;
}

::getdns_context* Context::release_context()
{
    return context_ptr_.release();
}

void Context::Deleter::operator()(::getdns_context* _context_ptr)const
{
    if (_context_ptr != nullptr)
    {
        ::getdns_context_destroy(_context_ptr);
    }
}

}//namespace GetDns
