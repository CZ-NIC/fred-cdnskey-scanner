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

#include "src/getdns/context.hh"
#include "src/getdns/data.hh"
#include "src/getdns/error.hh"
#include "src/getdns/exception.hh"

#include <getdns/getdns_ext_libevent.h>

//#include <iostream>

namespace GetDns
{

Context::Context(Event::Base& _event_base)
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
        ::getdns_callback_t _on_event)
{
    Data::Dict extensions;
    Data::set_item_of(
            extensions,
            "dnssec_return_status",
            static_cast< ::uint32_t >(GETDNS_EXTENSION_TRUE));
    ::getdns_transaction_t transaction_id;
//    std::cout << "extension:\n" << extensions << std::endl;
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

Context& Context::set_dns_transport_list(const TransportList& _transport_list)
{
    ::getdns_transport_list_t list[_transport_list.size()];
    ::getdns_transport_list_t* item_ptr = list;
    for (TransportList::const_iterator transport = _transport_list.begin();
         transport != _transport_list.end();
         ++transport, ++item_ptr)
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
        *item_ptr = Convert(*transport).into_enum();
    }
    const ::getdns_return_t retval = ::getdns_context_set_dns_transport_list(
            free_on_exit_.context_ptr,
            _transport_list.size(),
            list);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextSetDnsTransportListException:Error
        {
            explicit ContextSetDnsTransportListException(getdns_return_t _error_code):Error(_error_code) { }
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
            const ::getdns_bindata address_data =
                    {
                        boost::asio::ip::address_v4::bytes_type::static_size,
                        address->to_v4().to_bytes().c_array()
                    };
            Data::set_item_of(item, "address_data", &address_data);
        }
        else if (address->is_v6())
        {
            Data::set_item_of(item, "address_type", "IPv6");
            const ::getdns_bindata address_data =
                    {
                        boost::asio::ip::address_v6::bytes_type::static_size,
                        address->to_v6().to_bytes().c_array()
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
            explicit ContextSetUpstreamRecursiveServersFailure(getdns_return_t _error_code):Error(_error_code) { }
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
                    explicit ContextSetResolutionStubFailure(getdns_return_t _error_code):Error(_error_code) { }
                };
                throw ContextSetResolutionStubFailure(retval);
            }
        }
    };
    SetResolution::stub(free_on_exit_.context_ptr);
    this->set_follow_redirects(false);
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
            explicit ContextSetFollowRedirectsFailure(getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextSetFollowRedirectsFailure(retval);
    }
    return *this;
}

Context::FreeOnExit::FreeOnExit()
    : context_ptr(NULL)
{
    const bool set_from_os = false;
    const ::getdns_return_t retval = ::getdns_context_create(&context_ptr, set_from_os ? 1 : 0);
    if (retval != ::GETDNS_RETURN_GOOD)
    {
        struct ContextCreateException:Error
        {
            explicit ContextCreateException(getdns_return_t _error_code):Error(_error_code) { }
        };
        throw ContextCreateException(retval);
    }
}

Context::FreeOnExit::~FreeOnExit()
{
    ::getdns_context_destroy(context_ptr);
    context_ptr = NULL;
}

}//namespace GetDns
