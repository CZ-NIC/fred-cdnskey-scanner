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

#ifndef DATA_HH_4BD03E3BE61C61ADC6A6590A94FC068D//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define DATA_HH_4BD03E3BE61C61ADC6A6590A94FC068D

#include "src/getdns/exception.hh"

#include <boost/asio/ip/address.hpp>

#include <getdns/getdns.h>

#include <cstdlib>
#include <iosfwd>
#include <list>
#include <string>
#include <type_traits>

namespace GetDns {

struct Data
{
    class BinData;
    class BinDataRef;
    class Dict;
    class DictRef;
    class Integer;
    class IntegerRef;
    class List;
    class ListRef;
    class DnsName;
    struct TrustAnchor;
    class TrustAnchorList;
};

class PrettyString
{
public:
    ~PrettyString();
private:
    explicit PrettyString(char* src);
    char* const data_;
    friend class Data::DictRef;
    friend std::ostream& operator<<(std::ostream& out, const PrettyString& str);
};

class Data::DictRef
{
public:
    explicit DictRef(const ::getdns_dict* ptr);
    DictRef() = delete;
    DictRef(DictRef&& src) noexcept;
    DictRef(const DictRef&) = delete;
    ~DictRef() noexcept = default;
    DictRef& operator=(DictRef&& src) noexcept;
    DictRef& operator=(const DictRef&) = delete;
    operator const ::getdns_dict*() const noexcept;
    PrettyString get_pretty_string() const;
    template <typename T>
    T get(const char* key) const;
private:
    const ::getdns_dict* ptr_;
    friend std::ostream& operator<<(std::ostream& out, const DictRef& data);
};

template <> Data::BinDataRef Data::DictRef::get<Data::BinDataRef>(const char* key) const;
template <> Data::DictRef Data::DictRef::get<Data::DictRef>(const char* key) const;
template <> Data::IntegerRef Data::DictRef::get<Data::IntegerRef>(const char* key) const;
template <> Data::ListRef Data::DictRef::get<Data::ListRef>(const char* key) const;

class Data::ListRef
{
public:
    explicit ListRef(const ::getdns_list* ptr);
    ListRef() = delete;
    ListRef(ListRef&& src) noexcept;
    ListRef(const ListRef&) = delete;
    ~ListRef() noexcept = default;
    ListRef& operator=(ListRef&& src) noexcept;
    ListRef& operator=(const ListRef&) = delete;
    operator const ::getdns_list*() const noexcept;
    std::size_t length() const;
    template <typename T>
    T get(std::size_t index) const;
private:
    const ::getdns_list* ptr_;
};

template <> Data::BinDataRef Data::ListRef::get<Data::BinDataRef>(std::size_t index) const;
template <> Data::DictRef Data::ListRef::get<Data::DictRef>(std::size_t index) const;
template <> Data::IntegerRef Data::ListRef::get<Data::IntegerRef>(std::size_t index) const;
template <> Data::ListRef Data::ListRef::get<Data::ListRef>(std::size_t index) const;

class Data::BinDataRef
{
public:
    explicit BinDataRef(const ::getdns_bindata* ptr);
    BinDataRef() = delete;
    BinDataRef(BinDataRef&& src) noexcept;
    BinDataRef(const BinDataRef&) = delete;
    ~BinDataRef() noexcept = default;
    BinDataRef& operator=(BinDataRef&& src) noexcept;
    BinDataRef& operator=(const BinDataRef&) = delete;
    operator const ::getdns_bindata*() const noexcept;
    std::size_t size() const noexcept;
    const void* data() const noexcept;
    template <typename T>
    T as() const;
private:
    const ::getdns_bindata* ptr_;
};

template <> boost::asio::ip::address Data::BinDataRef::as<boost::asio::ip::address>() const;
template <> boost::asio::ip::address_v4 Data::BinDataRef::as<boost::asio::ip::address_v4>() const;
template <> boost::asio::ip::address_v6 Data::BinDataRef::as<boost::asio::ip::address_v6>() const;

class Data::IntegerRef
{
public:
    constexpr IntegerRef(const IntegerRef&) noexcept = default;
    constexpr IntegerRef(IntegerRef&&) noexcept = default;
    ~IntegerRef() noexcept = default;
    constexpr IntegerRef& operator=(const IntegerRef&) noexcept = default;
    constexpr IntegerRef& operator=(IntegerRef&&) noexcept = default;
    constexpr operator std::uint32_t() const noexcept { return value_; }
private:
    explicit constexpr IntegerRef(std::uint32_t value) noexcept : value_{value} { }
    IntegerRef() noexcept = default;
    std::uint32_t value_;
    static_assert(std::is_same<decltype(value_), ::uint32_t>::value);
    friend class DictRef;
    friend class ListRef;
    friend class Integer;
};


class Data::BinData
{
public:
    BinData();
    template <std::size_t size>
    explicit BinData(const char (&str)[size]);
    explicit BinData(const std::string& binary_data);
    template <typename Fnc, std::enable_if_t<0 < sizeof(decltype(std::declval<Fnc>()(std::declval<::getdns_bindata**>()))*)>* = nullptr>
    explicit BinData(Fnc&& init_fnc);
    BinData(void* binary_data, std::size_t bytes);
    BinData(const void* binary_data, std::size_t bytes);
    BinData(BinData&& src);
    ~BinData();
    BinData(const BinData& src);
    BinData& operator=(BinData&& src);
    BinData& operator=(const BinData& src);
    Data::BinDataRef operator*() const noexcept;
private:
    ::getdns_bindata bindata_;
};

class Data::Dict
{
public:
    explicit Dict(::getdns_dict* ptr) noexcept;
    template <typename Fnc, std::enable_if_t<0 < sizeof(decltype(std::declval<Fnc>()(std::declval<::getdns_dict**>()))*)>* = nullptr>
    explicit Dict(Fnc&& init_fnc);
    Dict() = delete;
    Dict(Dict&& src) noexcept;
    Dict(const Dict&) = delete;
    ~Dict() noexcept;
    Dict& operator=(Dict&& src) noexcept;
    Dict& operator=(const Dict&) = delete;
    Data::DictRef operator*() const;
    template <typename T>
    Dict& set(const char* key, const T& value);
private:
    ::getdns_dict* ptr_;
};

template <> Data::Dict& Data::Dict::set<Data::BinDataRef>(const char* key, const Data::BinDataRef& value);
template <> Data::Dict& Data::Dict::set<Data::DictRef>(const char* key, const Data::DictRef& value);
template <> Data::Dict& Data::Dict::set<Data::IntegerRef>(const char* key, const Data::IntegerRef& value);
template <> Data::Dict& Data::Dict::set<Data::ListRef>(const char* key, const Data::ListRef& value);

class Data::List
{
public:
    explicit List(::getdns_list* ptr);
    template <typename Fnc, std::enable_if_t<0 < sizeof(decltype(std::declval<Fnc>()(std::declval<::getdns_list**>()))*)>* = nullptr>
    explicit List(Fnc&& init_fnc);
    List() = delete;
    List(List&& src) noexcept;
    List(const List&) = delete;
    ~List() noexcept;
    List& operator=(List&& src) noexcept;
    List& operator=(const List&) = delete;
    std::size_t length() const;
    Data::ListRef operator*() const;
    operator ::getdns_list*() noexcept;
    template <typename T>
    List& set(std::size_t index, const T& value);
    template <typename T>
    List& push_back(const T& value);
private:
    ::getdns_list* ptr_;
};

template <> Data::List& Data::List::set<Data::BinDataRef>(std::size_t index, const Data::BinDataRef& value);
template <> Data::List& Data::List::set<Data::DictRef>(std::size_t index, const Data::DictRef& value);
template <> Data::List& Data::List::set<Data::IntegerRef>(std::size_t index, const Data::IntegerRef& value);
template <> Data::List& Data::List::set<Data::ListRef>(std::size_t index, const Data::ListRef& value);

template <> Data::List& Data::List::push_back<Data::BinDataRef>(const Data::BinDataRef& value);
template <> Data::List& Data::List::push_back<Data::DictRef>(const Data::DictRef& value);
template <> Data::List& Data::List::push_back<Data::IntegerRef>(const Data::IntegerRef& value);
template <> Data::List& Data::List::push_back<Data::ListRef>(const Data::ListRef& value);

class Data::Integer
{
public:
    explicit constexpr Integer(std::uint32_t value) noexcept : value_{value} { }
    Integer() = delete;
    constexpr Integer(const Integer&) noexcept = default;
    constexpr Integer(Integer&&) noexcept = default;
    ~Integer() = default;
    constexpr Integer& operator=(const Integer&) noexcept = default;
    constexpr Integer& operator=(Integer&&) noexcept = default;
    constexpr IntegerRef operator*() const noexcept { return IntegerRef{value_}; }
private:
    std::uint32_t value_;
    static_assert(std::is_same<decltype(value_), ::uint32_t>::value);
};

class Data::DnsName
{
public:
    explicit DnsName(const char* fqdn);
    DnsName() = delete;
    DnsName(const DnsName&) = delete;
    DnsName(DnsName&& src) noexcept;
    ~DnsName() noexcept;
    DnsName& operator=(const DnsName&) = delete;
    DnsName& operator=(DnsName&& src) noexcept;
    Data::BinDataRef operator*() const noexcept;
private:
    BinData bindata_;
};

template <typename T>
T get_as(const Data::BinDataRef&);

Data::BinData base64_decode(const std::string& base64_encoded_text);
std::string base64_encode(const Data::BinDataRef& raw_data);

struct TrustAnchor
{
    std::string zone;
    std::uint16_t flags;
    std::uint8_t protocol;
    std::uint8_t algorithm;
    std::string public_key;
};

struct Data::TrustAnchor
{
    explicit TrustAnchor(const GetDns::TrustAnchor& trust_anchor);
    Dict data;
};

class Data::TrustAnchorList
{
public:
    explicit TrustAnchorList(List data) noexcept;
    explicit TrustAnchorList(const std::list<GetDns::TrustAnchor>& list);
    TrustAnchorList(const TrustAnchorList& src);
    TrustAnchorList(TrustAnchorList&& src) noexcept;
    TrustAnchorList& operator=(const TrustAnchorList& src);
    TrustAnchorList& operator=(TrustAnchorList&& src) noexcept;
    operator ::getdns_list*() noexcept;
    bool empty() const;
private:
    List data_;
};

Data::TrustAnchorList get_root_trust_anchor(::time_t& utc_date_of_anchor);

template <std::size_t size>
Data::BinData::BinData(const char (&str)[size])
    : BinData{reinterpret_cast<const void*>(str), size}
{ }

template <typename Fnc, std::enable_if_t<0 < sizeof(decltype(std::declval<Fnc>()(std::declval<::getdns_bindata**>()))*)>*>
Data::BinData::BinData(Fnc&& init_fnc)
    : BinData{}
{
    ::getdns_bindata* ptr;
    std::forward<Fnc>(init_fnc)(&ptr);
    if (ptr == nullptr)
    {
        raise<MemoryError>(__FILE__, __LINE__);
    }
    bindata_.data = ptr->data;
    bindata_.size = ptr->size;
    std::free(ptr);
}

template <typename Fnc, std::enable_if_t<0 < sizeof(decltype(std::declval<Fnc>()(std::declval<::getdns_dict**>()))*)>*>
Data::Dict::Dict(Fnc&& init_fnc)
    : Dict{static_cast<::getdns_dict*>(nullptr)}
{
    std::forward<Fnc>(init_fnc)(&ptr_);
}

template <typename Fnc, std::enable_if_t<0 < sizeof(decltype(std::declval<Fnc>()(std::declval<::getdns_list**>()))*)>*>
Data::List::List(Fnc&& init_fnc)
    : List{static_cast<::getdns_list*>(nullptr)}
{
    std::forward<Fnc>(init_fnc)(&ptr_);
}

}//namespace GetDns

#endif//DATA_HH_4BD03E3BE61C61ADC6A6590A94FC068D
