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

#include "src/getdns/data.hh"
#include "src/getdns/exception.hh"

#include <boost/variant.hpp>
#include <boost/version.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/algorithm/string.hpp>

#include <iostream>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <sstream>

namespace GetDns {

PrettyString::PrettyString(char* src)
    : data_{src}
{ }

PrettyString::~PrettyString()
{
    ::free(reinterpret_cast<void*>(data_));
}

std::ostream& operator<<(std::ostream& out, const PrettyString& str)
{
    return out << const_cast<const char*>(str.data_);
}

Data::BinDataRef::BinDataRef(const ::getdns_bindata* ptr)
    : ptr_{ptr}
{ }

Data::BinDataRef::operator const ::getdns_bindata*() const noexcept
{
    return ptr_;
}

std::size_t Data::BinDataRef::size() const noexcept
{
    return ptr_->size;
}

const void* Data::BinDataRef::data() const noexcept
{
    return ptr_->data;
}

namespace {

struct Free
{
    void operator()(void* mem) { ::free(mem); }
};

}//namespace GetDns::{anonymous}

using String = std::unique_ptr<char, Free>;

template <>
boost::asio::ip::address Data::BinDataRef::as<boost::asio::ip::address>() const
{
    const auto address = String{::getdns_display_ip_address(ptr_)};
    return boost::asio::ip::make_address(address.get());
}

template <>
boost::asio::ip::address_v4 Data::BinDataRef::as<boost::asio::ip::address_v4>() const
{
    const auto address = String{::getdns_display_ip_address(ptr_)};
    return boost::asio::ip::make_address_v4(address.get());
}

template <>
boost::asio::ip::address_v6 Data::BinDataRef::as<boost::asio::ip::address_v6>() const
{
    const auto address = String{::getdns_display_ip_address(ptr_)};
    return boost::asio::ip::make_address_v6(address.get());
}

Data::DictRef::DictRef(const ::getdns_dict* ptr)
    : ptr_{ptr}
{ }

Data::DictRef::DictRef(DictRef&& src) noexcept
    : DictRef{nullptr}
{
    std::swap(src.ptr_, ptr_);
}

Data::DictRef& Data::DictRef::operator=(DictRef&& src) noexcept
{
    std::swap(src.ptr_, ptr_);
    return *this;
}

Data::DictRef::operator const ::getdns_dict*() const noexcept
{
    return ptr_;
}

PrettyString Data::DictRef::get_pretty_string() const
{
    return PrettyString{::getdns_pretty_print_dict(ptr_)};
}

std::ostream& operator<<(std::ostream& out, const Data::DictRef& data)
{
    return out << data.get_pretty_string();
}

template <>
Data::BinDataRef Data::DictRef::get<Data::BinDataRef>(const char* key) const
{
    ::getdns_bindata* bindata_ptr = nullptr;
    MUST_BE_GOOD(::getdns_dict_get_bindata(ptr_, key, &bindata_ptr));
    return BinDataRef{bindata_ptr};
}

template <>
Data::DictRef Data::DictRef::get<Data::DictRef>(const char* key) const
{
    ::getdns_dict* dict_ptr = nullptr;
    MUST_BE_GOOD(::getdns_dict_get_dict(ptr_, key, &dict_ptr));
    return DictRef{dict_ptr};
}

template <>
Data::IntegerRef Data::DictRef::get<Data::IntegerRef>(const char* key) const
{
    IntegerRef integer{};
    MUST_BE_GOOD(::getdns_dict_get_int(ptr_, key, &integer.value_));
    return integer;
}

template <>
Data::ListRef Data::DictRef::get<Data::ListRef>(const char* key) const
{
    ::getdns_list* list_ptr = nullptr;
    MUST_BE_GOOD(::getdns_dict_get_list(ptr_, key, &list_ptr));
    return ListRef{list_ptr};
}


Data::ListRef::ListRef(const ::getdns_list* ptr)
    : ptr_{ptr}
{ }

Data::ListRef::ListRef(ListRef&& src) noexcept
    : ListRef{nullptr}
{
    std::swap(src.ptr_, ptr_);
}

Data::ListRef& Data::ListRef::operator=(ListRef&& src) noexcept
{
    std::swap(src.ptr_, ptr_);
    return *this;
}

Data::ListRef::operator const ::getdns_list*() const noexcept
{
    return ptr_;
}

std::size_t Data::ListRef::length() const
{
    ::size_t length;
    static_assert(std::is_same<decltype(length), std::size_t>::value);
    MUST_BE_GOOD(::getdns_list_get_length(ptr_, &length));
    return length;
}

template <>
Data::BinDataRef Data::ListRef::get<Data::BinDataRef>(std::size_t index) const
{
    ::getdns_bindata* bindata_ptr = nullptr;
    MUST_BE_GOOD(::getdns_list_get_bindata(ptr_, index, &bindata_ptr));
    return BinDataRef{bindata_ptr};
}

template <>
Data::DictRef Data::ListRef::get<Data::DictRef>(std::size_t index) const
{
    ::getdns_dict* dict_ptr = nullptr;
    MUST_BE_GOOD(::getdns_list_get_dict(ptr_, index, &dict_ptr));
    return DictRef{dict_ptr};
}

template <>
Data::IntegerRef Data::ListRef::get<Data::IntegerRef>(std::size_t index) const
{
    IntegerRef integer{};
    MUST_BE_GOOD(::getdns_list_get_int(ptr_, index, &integer.value_));
    return integer;
}

template <>
Data::ListRef Data::ListRef::get<Data::ListRef>(std::size_t index) const
{
    ::getdns_list* list_ptr = nullptr;
    MUST_BE_GOOD(::getdns_list_get_list(ptr_, index, &list_ptr));
    return ListRef{list_ptr};
}


template <>
const char* get_as<const char*>(const Data::BinDataRef& bindata)
{
    const auto* const bindata_ptr = static_cast<const ::getdns_bindata*>(bindata);
    if ((bindata_ptr != nullptr) &&
        (bindata_ptr->data != nullptr) &&
        (0 < bindata_ptr->size) &&
        (bindata_ptr->data[bindata_ptr->size - 1] == 0))
    {
        return reinterpret_cast<const char*>(bindata_ptr->data);
    }
    raise<GenericError>(__FILE__, __LINE__);
}


Data::BinData::BinData()
{
    bindata_.data = nullptr;
    bindata_.size = 0;
}

Data::BinData::BinData(const BinData& src)
    : BinData{reinterpret_cast<const void*>(src.bindata_.data), src.bindata_.size}
{ }

Data::BinData::BinData(BinData&& src)
    : BinData{}
{
    std::swap(bindata_, src.bindata_);
}

Data::BinData::BinData(const std::string& binary_data)
    : BinData{reinterpret_cast<const void*>(binary_data.c_str()), binary_data.length()}
{ }

Data::BinData::BinData(const void* binary_data, std::size_t bytes)
    : BinData{}
{
    bindata_.data = reinterpret_cast<::uint8_t*>(std::malloc(bytes));
    bindata_.size = bytes;
    std::memcpy(reinterpret_cast<void*>(bindata_.data), binary_data, bytes);
}

Data::BinData::BinData(void* binary_data, std::size_t bytes)
    : BinData{}
{
    bindata_.data = reinterpret_cast<::uint8_t*>(binary_data);
    bindata_.size = bytes;
}

Data::BinData::~BinData()
{
    std::free(bindata_.data);
}

Data::BinData& Data::BinData::operator=(BinData&& src)
{
    std::swap(bindata_, src.bindata_);
    return *this;
}

Data::BinData& Data::BinData::operator=(const BinData& src)
{
    return *this = BinData{src.bindata_.data, src.bindata_.size};
}

Data::BinDataRef Data::BinData::operator*() const noexcept
{
    return Data::BinDataRef{&bindata_};
}


Data::Dict::Dict(::getdns_dict* ptr) noexcept
     : ptr_{ptr}
{ }

Data::Dict::Dict(Dict&& src) noexcept
    : Dict{nullptr}
{
    std::swap(src.ptr_, ptr_);
}

Data::Dict& Data::Dict::operator=(Dict&& src) noexcept
{
    std::swap(src.ptr_, ptr_);
    return *this;
}

Data::Dict::~Dict()
{
    ::getdns_dict_destroy(ptr_);
    ptr_ = nullptr;
}

Data::DictRef Data::Dict::operator*() const
{
    return Data::DictRef{ptr_};
}

template <>
Data::Dict& Data::Dict::set<Data::BinDataRef>(const char* key, const Data::BinDataRef& value)
{
    MUST_BE_GOOD(::getdns_dict_set_bindata(ptr_, key, value));
    return *this;
}

template <>
Data::Dict& Data::Dict::set<Data::DictRef>(const char* key, const Data::DictRef& value)
{
    MUST_BE_GOOD(::getdns_dict_set_dict(ptr_, key, value));
    return *this;
}

template <>
Data::Dict& Data::Dict::set<Data::IntegerRef>(const char* key, const Data::IntegerRef& value)
{
    MUST_BE_GOOD(::getdns_dict_set_int(ptr_, key, value));
    return *this;
}

template <> Data::Dict& Data::Dict::set<Data::ListRef>(const char* key, const Data::ListRef& value)
{
    MUST_BE_GOOD(::getdns_dict_set_list(ptr_, key, value));
    return *this;
}


Data::List::List(::getdns_list* ptr)
    : ptr_{ptr}
{ }

Data::List::List(List&& src) noexcept
    : List{nullptr}
{
    std::swap(src.ptr_, ptr_);
}

Data::List& Data::List::operator=(List&& src) noexcept
{
    std::swap(src.ptr_, ptr_);
    return *this;
}

Data::List::~List()
{
    ::getdns_list_destroy(ptr_);
    ptr_ = nullptr;
}

std::size_t Data::List::length() const
{
    ::size_t length;
    static_assert(std::is_same<decltype(length), std::size_t>::value);
    MUST_BE_GOOD(::getdns_list_get_length(ptr_, &length));
    return length;
}

Data::ListRef Data::List::operator*() const
{
    return Data::ListRef{ptr_};
}

Data::List::operator ::getdns_list*() noexcept
{
    return ptr_;
}

template <>
Data::List& Data::List::set<Data::BinDataRef>(std::size_t index, const Data::BinDataRef& value)
{
    MUST_BE_GOOD(::getdns_list_set_bindata(ptr_, index, value));
    return *this;
}

template <>
Data::List& Data::List::set<Data::DictRef>(std::size_t index, const Data::DictRef& value)
{
    MUST_BE_GOOD(::getdns_list_set_dict(ptr_, index, value));
    return *this;
}

template <>
Data::List& Data::List::set<Data::IntegerRef>(std::size_t index, const Data::IntegerRef& value)
{
    MUST_BE_GOOD(::getdns_list_set_int(ptr_, index, value));
    return *this;
}

template <>
Data::List& Data::List::set<Data::ListRef>(std::size_t index, const Data::ListRef& value)
{
    MUST_BE_GOOD(::getdns_list_set_list(ptr_, index, value));
    return *this;
}


template <>
Data::List& Data::List::push_back<Data::BinDataRef>(const Data::BinDataRef& value)
{
    return this->set(this->length(), value);
}

template <>
Data::List& Data::List::push_back<Data::DictRef>(const Data::DictRef& value)
{
    return this->set(this->length(), value);
}

template <>
Data::List& Data::List::push_back<Data::IntegerRef>(const Data::IntegerRef& value)
{
    return this->set(this->length(), value);
}

template <>
Data::List& Data::List::push_back<Data::ListRef>(const Data::ListRef& value)
{
    return this->set(this->length(), value);
}


Data::DnsName::DnsName(const char* fqdn)
    : bindata_{[&](::getdns_bindata** ptr) { MUST_BE_GOOD(::getdns_convert_fqdn_to_dns_name(fqdn, ptr)); }}
{ }

Data::DnsName::~DnsName() noexcept { }

Data::BinDataRef Data::DnsName::operator*() const noexcept
{
    return *bindata_;
}

Data::TrustAnchor::TrustAnchor(const GetDns::TrustAnchor& trust_anchor)
    : data{[](const GetDns::TrustAnchor& trust_anchor)
           {
               const Data::DnsName zone{trust_anchor.zone.c_str()};
               const auto public_key = base64_decode(trust_anchor.public_key);
               Data::Dict anchor{::getdns_dict_create()};
               anchor.set("class", *Data::Integer{GETDNS_RRCLASS_IN});
               anchor.set("name", *zone);
               anchor.set("type", *Data::Integer{GETDNS_RRTYPE_DNSKEY});
               constexpr auto two_days_in_seconds = 2 * 24 * 3600;
               anchor.set("ttl", *Data::Integer{two_days_in_seconds});
               GetDns::Data::Dict rdata{::getdns_dict_create()};
               rdata.set("flags", *Data::Integer{trust_anchor.flags});
               rdata.set("protocol", *Data::Integer{trust_anchor.protocol});
               rdata.set("algorithm", *Data::Integer{trust_anchor.algorithm});
               rdata.set("public_key", *public_key);
               anchor.set("rdata", *rdata);
               return anchor;
           }(trust_anchor)}
{ }

namespace {


}//namespace GetDns::{anonymous}

Data::TrustAnchorList::TrustAnchorList(List data) noexcept
    : data_{std::move(data)}
{ }

Data::TrustAnchorList::TrustAnchorList(const std::list<GetDns::TrustAnchor>& list)
    : data_{::getdns_list_create()}
{
    std::for_each(begin(list), end(list), [&](auto&& anchor) { data_.push_back(*TrustAnchor{anchor}.data); });
}

Data::TrustAnchorList::TrustAnchorList(const TrustAnchorList& src)
    : data_{::getdns_list_create()}
{
    const auto number_of_anchors = src.data_.length();
    for (std::size_t idx = 0; idx < number_of_anchors; ++idx)
    {
        const auto anchor = (*src.data_).get<DictRef>(idx);
        data_.push_back(anchor);
    }
}

Data::TrustAnchorList::TrustAnchorList(TrustAnchorList&& src) noexcept
    : data_{std::move(src.data_)}
{ }

Data::TrustAnchorList& Data::TrustAnchorList::operator=(const TrustAnchorList& src)
{
    return *this = TrustAnchorList{src};
}

Data::TrustAnchorList& Data::TrustAnchorList::operator=(TrustAnchorList&& src) noexcept
{
    std::swap(data_, src.data_);
    return *this;
}

Data::TrustAnchorList::operator ::getdns_list*() noexcept
{
    return static_cast<::getdns_list*>(data_);
}

bool Data::TrustAnchorList::empty() const
{
    return data_.length() == 0;
}

Data::TrustAnchorList get_root_trust_anchor(::time_t& utc_date_of_anchor)
{
    return Data::TrustAnchorList{Data::List{::getdns_root_trust_anchor(&utc_date_of_anchor)}};
}

namespace {

std::string remove_the_base64_padding_characters(const std::string& with_paddings)
{
    static constexpr int are_the_same = 0;
    if (2 <= with_paddings.length())
    {
        if (with_paddings.compare(with_paddings.length() - 2, 2, "==") == are_the_same)
        {
            return with_paddings.substr(0, with_paddings.length() - 2);
        }
    }
    if (1 <= with_paddings.length())
    {
        if (with_paddings.compare(with_paddings.length() - 1, 1, "=") == are_the_same)
        {
            return with_paddings.substr(0, with_paddings.length() - 1);
        }
    }
    return with_paddings;
}

}//namespace GetDns::{anonymous}

Data::BinData base64_decode(const std::string& base64_encoded_text)
{
    namespace bai = boost::archive::iterators;
    using Base64Decode = bai::transform_width<bai::binary_from_base64<const char*>, 8, 6>;

    const std::string without_paddings = remove_the_base64_padding_characters(base64_encoded_text);
    std::ostringstream decoded_bin_data;

    std::copy(Base64Decode(without_paddings.data()),
              Base64Decode(without_paddings.data() + without_paddings.size()),
              std::ostream_iterator<char>(decoded_bin_data));
    return Data::BinData{decoded_bin_data.str()};
}

std::string base64_encode(const Data::BinDataRef& raw_data)
{
    using Base64Encode = boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<const char*, 6, 8>>;
    std::ostringstream base64_encoded_text;
    const char* const data_begin = reinterpret_cast<const char*>(raw_data.data());
    const char* const data_end = data_begin + raw_data.size();
    std::copy(Base64Encode(data_begin),
              Base64Encode(data_end),
              std::ostream_iterator<char>(base64_encoded_text));
    switch (raw_data.size() % 3)
    {
        case 0:
            break;
        case 1:
            base64_encoded_text << "==";
            break;
        case 2:
            base64_encoded_text << "=";
            break;
    }
    return std::move(base64_encoded_text).str();
}

}//namespace GetDns
