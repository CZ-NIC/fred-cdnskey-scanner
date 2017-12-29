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

#include "src/getdns/data.hh"
#include "src/getdns/exception.hh"
#include "src/getdns/error.hh"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <sstream>

#include <boost/variant.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/algorithm/string.hpp>

namespace GetDns {

namespace {

void dict_ptr_destroy(::getdns_dict** dict_ptr)
{
    if (dict_ptr != nullptr)
    {
        ::getdns_dict_destroy(*dict_ptr);
        delete dict_ptr;
    }
}

void list_ptr_destroy(::getdns_list** list_ptr)
{
    if (list_ptr != nullptr)
    {
        ::getdns_list_destroy(*list_ptr);
        delete list_ptr;
    }
}

}//namespace GetDns::{anonymous}

Data::Dict::Dict()
    : base_ptr_(new ::getdns_dict*(::getdns_dict_create()), dict_ptr_destroy),
      parent_(Empty())
{
    if (*base_ptr_ == nullptr)
    {
        struct DictCreateFailure:Exception
        {
            const char* what()const noexcept { return "Could not create extensions dict"; }
        };
        throw DictCreateFailure();
    }
}

Data::Dict::Dict(const Dict& _src)
    : base_ptr_(_src.base_ptr_),
      parent_(_src.parent_)
{
}

Data::Dict::Dict(Base* _base)
    : base_ptr_(new ::getdns_dict*(_base), dict_ptr_destroy),
      parent_(Empty())
{
}

Data::Dict::Dict(Base* _base, const std::shared_ptr<::getdns_dict*>& _parent)
    : base_ptr_(new ::getdns_dict*(_base)),
      parent_(_parent)
{
}

Data::Dict::Dict(Base* _base, const std::shared_ptr<::getdns_list*>& _parent)
    : base_ptr_(new ::getdns_dict*(_base)),
      parent_(_parent)
{
}

Data::Dict::~Dict()
{
}

Data::Dict& Data::Dict::operator=(const Dict& _src)
{
    base_ptr_ = _src.base_ptr_;
    parent_ = _src.parent_;
    return *this;
}

Data::Dict::Keys Data::Dict::get_keys()const
{
    ::getdns_list* names_ptr = nullptr;
    const ::getdns_return_t result = ::getdns_dict_get_names(*base_ptr_, &names_ptr);
    if (result == ::GETDNS_RETURN_GOOD)
    {
        const List names(names_ptr);//the list has to be freed, I'm not its parent
        Keys keys;
        const std::size_t number_of_names = names.get_number_of_items();
        for (std::size_t idx = 0; idx < number_of_names; ++idx)
        {
            const Value name = get<std::string>(names, idx);
            if (Is(name).of<std::string>().type)
            {
                keys.insert(From(name).get_value_of<std::string>());
            }
        }
        return keys;
    }
    struct DictGetNamesFailure:Error
    {
        DictGetNamesFailure(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw DictGetNamesFailure(result, __FILE__, __LINE__);
}

Data::Type Data::Dict::get_data_type_of_item(const char* _key)const
{
    ::getdns_data_type answer;
    const ::getdns_return_t result = ::getdns_dict_get_data_type(*base_ptr_, _key, &answer);
    if (result == ::GETDNS_RETURN_GOOD)
    {
        switch (answer)
        {
            case ::t_dict: return Type::dictionary;
            case ::t_list: return Type::array;
            case ::t_int: return Type::integer;
            case ::t_bindata: return Type::binary;
        }
        struct UnexpectedEnumValue:std::logic_error
        {
            UnexpectedEnumValue():std::logic_error("Enum value out of range") { }
        };
        throw UnexpectedEnumValue();
    }
    struct DictGetDataTypeFailure:Error
    {
        DictGetDataTypeFailure(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw DictGetDataTypeFailure(result, __FILE__, __LINE__);
}

Data::Type Data::Dict::get_data_type_of_item(const std::string& _key)const
{
    return this->get_data_type_of_item(_key.c_str());
}

std::string Data::Dict::get_pretty_string()const
{
    struct Deleter
    {
        void operator()(char* _str)const { ::free(reinterpret_cast<void*>(_str)); }
    };
    return std::string(std::unique_ptr<char, Deleter>(::getdns_pretty_print_dict(*base_ptr_)).get());
}

Data::Dict::Base* Data::Dict::get_base_ptr()
{
    return *base_ptr_;
}

const Data::Dict::Base* Data::Dict::get_base_ptr()const
{
    return *base_ptr_;
}

Data::LookUpResult Data::Dict::look_up(const char* _key, Type _type)const
{
    ::getdns_list* names_ptr = nullptr;
    const ::getdns_return_t result = ::getdns_dict_get_names(*base_ptr_, &names_ptr);
    if (result != ::GETDNS_RETURN_GOOD)
    {
        struct DictGetNamesFailure:Error
        {
            DictGetNamesFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw DictGetNamesFailure(result, __FILE__, __LINE__);
    }
    const List names(names_ptr);//the list has to be freed, I'm not its parent
    const std::size_t number_of_names = names.get_number_of_items();
    for (std::size_t idx = 0; idx < number_of_names; ++idx)
    {
        const Value item_name = get<std::string>(names, idx);
        if (Is(item_name).of<std::string>().type)
        {
            if (From(item_name).get_value_of<std::string>() == _key)
            {
                const bool is_of_requested_type = this->get_data_type_of_item(_key) == _type;
                return is_of_requested_type ? LookUpResult::success : LookUpResult::different_type;
            }
        }
    }
    return LookUpResult::not_found;
}

Data::Dict Data::Dict::get_trust_anchor(
        const std::string& _zone,
        std::uint16_t _flags,
        std::uint8_t _protocol,
        std::uint8_t _algorithm,
        const Binary& _public_key)
{
    GetDns::Data::Dict anchor;
    GetDns::Data::set_item_of(anchor, "class", static_cast<std::uint32_t>(GETDNS_RRCLASS_IN));
    {
        struct DnsName
        {
            static auto from_fqdn(const std::string& _fqdn)
            {
                ::getdns_bindata* bin_data_ptr;
                const ::getdns_return_t result = ::getdns_convert_fqdn_to_dns_name(_fqdn.c_str(), &bin_data_ptr);
                if (result != ::GETDNS_RETURN_GOOD)
                {
                    struct ConversionFailure:Error
                    {
                        ConversionFailure(::getdns_return_t _error_code, const char* _file, int _line)
                            : Error(_error_code, _file, _line)
                        { }
                    };
                    throw ConversionFailure(result, __FILE__, __LINE__);
                }
                struct Deleter
                {
                    void operator()(::getdns_bindata* _data_ptr)const
                    {
                        if (_data_ptr != nullptr)
                        {
                            ::free(_data_ptr->data);
                            _data_ptr->data = nullptr;
                            ::free(_data_ptr);
                        }
                    }
                };
                return std::unique_ptr<::getdns_bindata, Deleter>(bin_data_ptr);
            }
        };
        const auto zone = DnsName::from_fqdn(_zone);
        GetDns::Data::set_item_of(anchor, "name", const_cast<const ::getdns_bindata*>(zone.get()));
    }
    GetDns::Data::set_item_of(anchor, "type", static_cast<std::uint32_t>(GETDNS_RRTYPE_DNSKEY));
    constexpr auto two_days_in_seconds = 2 * 24 * 3600;
    GetDns::Data::set_item_of(anchor, "ttl", static_cast<std::uint32_t>(two_days_in_seconds));
    GetDns::Data::Dict rdata;
    GetDns::Data::set_item_of(rdata, "flags", static_cast<std::uint32_t>(_flags));
    GetDns::Data::set_item_of(rdata, "protocol", static_cast<std::uint32_t>(_protocol));
    GetDns::Data::set_item_of(rdata, "algorithm", static_cast<std::uint32_t>(_algorithm));
    ::getdns_bindata public_key;
    public_key.size = _public_key.get_length();
    public_key.data = reinterpret_cast<std::uint8_t*>(const_cast<void*>(_public_key.get_binary_data()));
    GetDns::Data::set_item_of(rdata, "public_key", const_cast<const ::getdns_bindata*>(&public_key));
    GetDns::Data::set_item_of(anchor, "rdata", const_cast<const GetDns::Data::Dict&>(rdata).get_base_ptr());
    return anchor;
}

Data::List::List()
    : base_ptr_(new ::getdns_list*(::getdns_list_create()), list_ptr_destroy),
      parent_(Empty())
{
    if (*base_ptr_ == nullptr)
    {
        struct ListCreateFailure:Exception
        {
            const char* what()const noexcept { return "Could not create extensions list"; }
        };
        throw ListCreateFailure();
    }
}

Data::List::List(const List& _src)
    : base_ptr_(_src.base_ptr_),
      parent_(_src.parent_)
{
}

Data::List::List(Base* _base)
    : base_ptr_(new ::getdns_list*(_base), list_ptr_destroy),
      parent_(Empty())
{
}

Data::List::List(Base* _base, const std::shared_ptr<::getdns_dict*>& _parent)
    : base_ptr_(new ::getdns_list*(_base)),
      parent_(_parent)
{
}

Data::List::List(Base* _base, const std::shared_ptr<::getdns_list*>& _parent)
    : base_ptr_(new ::getdns_list*(_base)),
      parent_(_parent)
{
}

Data::List::~List()
{
}

Data::List& Data::List::operator=(const List& _src)
{
    base_ptr_ = _src.base_ptr_;
    parent_ = _src.parent_;
    return *this;
}

std::size_t Data::List::get_number_of_items()const
{
    ::size_t answer;
    const ::getdns_return_t result = ::getdns_list_get_length(*base_ptr_, &answer);
    if (result == ::GETDNS_RETURN_GOOD)
    {
        return answer;
    }
    struct ListGetLengthFailure:Error
    {
        ListGetLengthFailure(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw ListGetLengthFailure(result, __FILE__, __LINE__);
}

Data::Type Data::List::get_data_type_of_item(::size_t _index)const
{
    ::getdns_data_type answer;
    const ::getdns_return_t result = ::getdns_list_get_data_type(*base_ptr_, _index, &answer);
    if (result == ::GETDNS_RETURN_GOOD)
    {
        switch (answer)
        {
            case ::t_dict: return Type::dictionary;
            case ::t_list: return Type::array;
            case ::t_int: return Type::integer;
            case ::t_bindata: return Type::binary;
        }
        struct UnexpectedEnumValue:std::logic_error
        {
            UnexpectedEnumValue():std::logic_error("Enum value out of range") { }
        };
        throw UnexpectedEnumValue();
    }
    struct ListGetDataTypeFailure:Error
    {
        ListGetDataTypeFailure(::getdns_return_t _error_code, const char* _file, int _line)
            : Error(_error_code, _file, _line)
        { }
    };
    throw ListGetDataTypeFailure(result, __FILE__, __LINE__);
}

Data::LookUpResult Data::List::look_up(::size_t _index, Type _type)const
{
    const bool index_is_out_of_range = this->get_number_of_items() <= _index;
    if (index_is_out_of_range)
    {
        return LookUpResult::index_out_of_range;
    }
    const bool is_of_requested_type = this->get_data_type_of_item(_index) == _type;
    return is_of_requested_type ? LookUpResult::success : LookUpResult::different_type;
}

const Data::List::Base* Data::List::get_base_ptr()const
{
    return *base_ptr_;
}

Data::List::Base* Data::List::get_base_ptr()
{
    return *base_ptr_;
}

Data::List Data::List::get_root_trust_anchor(::time_t& _utc_date_of_anchor)
{
    return List(::getdns_root_trust_anchor(&_utc_date_of_anchor));
}

Data::Binary::Binary()
    : binary_data_()
{ }

Data::Binary::Binary(const std::string& _binary_data)
    : binary_data_(_binary_data)
{ }

Data::Binary::Binary(const void* _binary_data, std::uint32_t _data_length)
    : binary_data_(reinterpret_cast<const char*>(_binary_data), _data_length)
{ }

const void* Data::Binary::get_binary_data()const
{
    return static_cast<const void*>(binary_data_.c_str());
}

std::uint32_t Data::Binary::get_length()const
{
    return binary_data_.length();
}

namespace {

std::string remove_the_base64_padding_characters(const std::string& _with_paddings)
{
    const int are_the_same = 0;
    if (2 <= _with_paddings.length())
    {
        if (_with_paddings.compare(_with_paddings.length() - 2, 2, "==") == are_the_same)
        {
            return _with_paddings.substr(0, _with_paddings.length() - 2);
        }
    }
    if (1 <= _with_paddings.length())
    {
        if (_with_paddings.compare(_with_paddings.length() - 1, 1, "=") == are_the_same)
        {
            return _with_paddings.substr(0, _with_paddings.length() - 1);
        }
    }
    return _with_paddings;
}

}//namespace GetDns::{anonymous}

Data::Binary Data::base64_decode(const std::string& _base64_encoded_text)
{
    namespace bai = boost::archive::iterators;
    typedef bai::transform_width<bai::binary_from_base64<const char*>, 8, 6> Base64Decode;

    const std::string without_paddings = remove_the_base64_padding_characters(_base64_encoded_text);
    std::ostringstream decoded_bin_data;

    std::copy(Base64Decode(without_paddings.data()),
              Base64Decode(without_paddings.data() + without_paddings.size()),
              std::ostream_iterator<char>(decoded_bin_data));
    return Binary(decoded_bin_data.str());
}

std::string Data::base64_encode(const Data::Binary& _raw_data)
{
    typedef boost::archive::iterators::base64_from_binary<
                boost::archive::iterators::transform_width<const char*, 6, 8>> Base64Encode;
    std::ostringstream base64_encoded_text;
    const char* const data_begin = reinterpret_cast<const char*>(_raw_data.get_binary_data());
    const char* const data_end = data_begin + _raw_data.get_length();
    std::copy(Base64Encode(data_begin),
              Base64Encode(data_end),
              std::ostream_iterator<char>(base64_encoded_text));
    switch (_raw_data.get_length() % 3)
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
    return base64_encoded_text.str();
}

namespace {

template <typename T>
struct ValueIsOf:boost::static_visitor<bool>
{
    bool operator()(const T&)const { return true; }
    template <typename X>
    bool operator()(const X&)const { return false; }
};

template <typename T>
struct GetValueOf
{
    const T& operator()(const T& _value)const { return _value; }
    template <typename X>
    const T& operator()(const X&)const { throw std::runtime_error("unexpected type"); }
};

}//namespace GetDns::{anonymous}

template <typename T>
Data::Is::Type Data::Is::of()const
{
    return Type(boost::apply_visitor(ValueIsOf<T>(), value_));
}

template Data::Is::Type Data::Is::of<Data::Dict>()const;
template Data::Is::Type Data::Is::of<Data::List>()const;
template Data::Is::Type Data::Is::of<std::uint32_t>()const;
template Data::Is::Type Data::Is::of<std::string>()const;
template Data::Is::Type Data::Is::of<Data::Binary>()const;
template Data::Is::Type Data::Is::of<Data::Fqdn>()const;
template Data::Is::Type Data::Is::of<boost::asio::ip::address>()const;
template Data::Is::Type Data::Is::of<Data::NotSet>()const;
template Data::Is::Type Data::Is::of<Data::NotRequestedType>()const;

template <typename T>
const T& Data::From::get_value_of()const
{
    return boost::apply_visitor(GetValueOf<T>(), value_);
}

template const Data::Dict& Data::From::get_value_of<Data::Dict>()const;
template const Data::List& Data::From::get_value_of<Data::List>()const;
template const Data::Fqdn& Data::From::get_value_of<Data::Fqdn>()const;
template const std::uint32_t& Data::From::get_value_of<std::uint32_t>()const;
template const std::string& Data::From::get_value_of<std::string>()const;
template const Data::Binary& Data::From::get_value_of<Data::Binary>()const;
template const boost::asio::ip::address& Data::From::get_value_of<boost::asio::ip::address>()const;

namespace {

template <class T> struct TypeTraits { };

template <>
struct TypeTraits<::getdns_dict*>
{
    typedef const char* IndexedByType;
};

template <>
struct TypeTraits<::getdns_list*>
{
    typedef ::size_t IndexedByType;
};

template <class W, class F, class B>
::getdns_return_t get_what_from_by(W* what, const F* from, B by);

template <>
::getdns_return_t get_what_from_by<::getdns_dict*, ::getdns_dict, const char*>(
        ::getdns_dict** what,
         const ::getdns_dict* from,
         const char* by)
{
    return ::getdns_dict_get_dict(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<::getdns_list*, ::getdns_dict, const char*>(
        ::getdns_list** what,
         const ::getdns_dict* from,
         const char* by)
{
    return ::getdns_dict_get_list(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<::getdns_bindata*, ::getdns_dict, const char*>(
        ::getdns_bindata** what,
         const ::getdns_dict* from,
         const char* by)
{
    return ::getdns_dict_get_bindata(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<std::uint32_t, ::getdns_dict, const char*>(
        std::uint32_t* what,
         const ::getdns_dict* from,
         const char* by)
{
    return ::getdns_dict_get_int(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<::getdns_dict*, ::getdns_list, ::size_t>(
        ::getdns_dict** what,
         const ::getdns_list* from,
         ::size_t by)
{
    return ::getdns_list_get_dict(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<::getdns_list*, ::getdns_list, ::size_t>(
        ::getdns_list** what,
         const ::getdns_list* from,
         ::size_t by)
{
    return ::getdns_list_get_list(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<::getdns_bindata*, ::getdns_list, ::size_t>(
        ::getdns_bindata** what,
         const ::getdns_list* from,
         ::size_t by)
{
    return ::getdns_list_get_bindata(from, by, what);
}

template <>
::getdns_return_t get_what_from_by<std::uint32_t, ::getdns_list, ::size_t>(
        std::uint32_t* what,
         const ::getdns_list* from,
         ::size_t by)
{
    return ::getdns_list_get_int(from, by, what);
}

template <typename T>
struct ConvertibleInto
{
    static const Data::Type from = Data::Type::binary;
};

template <>
struct ConvertibleInto<Data::Dict>
{
    static const Data::Type from = Data::Type::dictionary;
};

template <>
struct ConvertibleInto<Data::List>
{
    static const Data::Type from = Data::Type::array;
};

template <>
struct ConvertibleInto<std::uint32_t>
{
    static const Data::Type from = Data::Type::integer;
};

template <class R, class S, class K>
Data::LookUpResult look_up(const S& _parent, K _key)
{
    return _parent.look_up(_key, ConvertibleInto<R>::from);
}

template <class R, class S>
Data::LookUpResult look_up(const S& _parent, std::string _key)
{
    return look_up<R>(_parent, _key.c_str());
}

}//namespace GetDns::{anonymous}

template <class R, class S, class K> struct GetItem { };

template <class R, class S>
struct GetItem<R, S, typename TypeTraits<typename S::Base*>::IndexedByType>
{
    typedef R Result;
    typedef S Source;
    typedef typename TypeTraits<typename Source::Base*>::IndexedByType Index;
    static Result from(const typename Source::SharedBasePtr& _parent, Index _key)
    {
        typename Result::Base* item = nullptr;
        const ::getdns_return_t result = get_what_from_by(&item, *_parent, _key);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return Result(item, _parent);
        }
        throw Error(result, __FILE__, __LINE__);
    }
};

template <class S>
struct GetItem<std::uint32_t, S, typename TypeTraits<typename S::Base*>::IndexedByType>
{
    typedef std::uint32_t Result;
    typedef S Source;
    typedef typename TypeTraits<typename Source::Base*>::IndexedByType Index;
    static Result from(const typename Source::SharedBasePtr& _parent, Index _key)
    {
        Result item;
        const ::getdns_return_t result = get_what_from_by(&item, *_parent, _key);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return item;
        }
        throw Error(result, __FILE__, __LINE__);
    }
};

template <class S>
struct GetItem<boost::asio::ip::address, S, typename TypeTraits<typename S::Base*>::IndexedByType>
{
    typedef boost::asio::ip::address Result;
    typedef S Source;
    typedef typename TypeTraits<typename Source::Base*>::IndexedByType Index;
    static Result from(const typename Source::SharedBasePtr& _parent, Index _key)
    {
        ::getdns_bindata* item = nullptr;
        const ::getdns_return_t result = get_what_from_by(&item, *_parent, _key);
        if (result != ::GETDNS_RETURN_GOOD)
        {
            throw Error(result, __FILE__, __LINE__);
        }
        struct Deleter
        {
            void operator()(char* _value)const { ::free(_value); }
        };
        const auto ip_address = std::unique_ptr<char, Deleter>(::getdns_display_ip_address(item));
        if (ip_address != nullptr)
        {
            return boost::asio::ip::address::from_string(ip_address.get());
        }
        struct ConversionException:Exception
        {
            const char* what()const noexcept { return "Could not convert address to string"; }
        };
        throw ConversionException();
    }
};

template <class S>
struct GetItem<std::string, S, typename TypeTraits<typename S::Base*>::IndexedByType>
{
    typedef std::string Result;
    typedef S Source;
    typedef typename TypeTraits<typename Source::Base*>::IndexedByType Index;
    static Result from(const typename Source::SharedBasePtr& _parent, Index _key)
    {
        ::getdns_bindata* item = nullptr;
        const ::getdns_return_t result = get_what_from_by(&item, *_parent, _key);
        if (result != ::GETDNS_RETURN_GOOD)
        {
            throw Error(result, __FILE__, __LINE__);
        }
        const bool is_empty = item->size <= 0;
        if (is_empty)
        {
            return std::string();
        }
        const bool last_character_is_null = item->data[item->size - 1] == static_cast<std::uint8_t>(0);
        return std::string(
                reinterpret_cast<const char*>(item->data),
                item->size - (last_character_is_null ? 1 : 0));
    }
};

template <class S>
struct GetItem<Data::Binary, S, typename TypeTraits<typename S::Base*>::IndexedByType>
{
    typedef Data::Binary Result;
    typedef S Source;
    typedef typename TypeTraits<typename Source::Base*>::IndexedByType Index;
    static Result from(const typename Source::SharedBasePtr& _parent, Index _key)
    {
        ::getdns_bindata* item = nullptr;
        const ::getdns_return_t result = get_what_from_by(&item, *_parent, _key);
        if (result != ::GETDNS_RETURN_GOOD)
        {
            throw Error(result, __FILE__, __LINE__);
        }
        return Data::Binary(reinterpret_cast<const char*>(item->data), item->size);
    }
};

template <class S>
struct GetItem<Data::Fqdn, S, typename TypeTraits<typename S::Base*>::IndexedByType>
{
    typedef Data::Fqdn Result;
    typedef S Source;
    typedef typename TypeTraits<typename Source::Base*>::IndexedByType Index;
    static Result from(const typename Source::SharedBasePtr& _parent, Index _key)
    {
        ::getdns_bindata* item = nullptr;
        {
            const ::getdns_return_t result = get_what_from_by(&item, *_parent, _key);
            if (result != ::GETDNS_RETURN_GOOD)
            {
                throw Error(result, __FILE__, __LINE__);
            }
        }
        char* fqdn_str = nullptr;
        const ::getdns_return_t result = ::getdns_convert_dns_name_to_fqdn(item, &fqdn_str);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            struct Deleter
            {
                void operator()(char* _value)const { ::free(_value); }
            };
            const auto fqdn = std::unique_ptr<char, Deleter>(fqdn_str);
            Data::Fqdn retval;
            if (fqdn != nullptr)
            {
                retval.value = fqdn.get();
            }
            return retval;
        }
        struct ConversionException:Error
        {
            ConversionException(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ConversionException(result, __FILE__, __LINE__);
    }
};

template <class R>
struct GetItem<R, Data::Dict, std::string>
{
    static R from(const Data::Dict::SharedBasePtr& _parent, const std::string& _key)
    {
        return GetItem<R, Data::Dict, const char*>::from(_parent, _key.c_str());
    }
};

template <>
struct SetItem<Data::Dict::SharedBasePtr, const char*, std::uint32_t>
{
    static void into(Data::Dict::SharedBasePtr& _dst, const char* _key, std::uint32_t _value)
    {
        const ::getdns_return_t result = ::getdns_dict_set_int(*_dst, _key, _value);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return;
        }
        struct DictSetItemFailure:Error
        {
            DictSetItemFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw DictSetItemFailure(result, __FILE__, __LINE__);
    }
};

template <>
struct SetItem<Data::Dict::SharedBasePtr, const char*, const ::getdns_bindata*>
{
    static void into(Data::Dict::SharedBasePtr& _dst, const char* _key, const ::getdns_bindata* _value)
    {
        const ::getdns_return_t result = ::getdns_dict_set_bindata(*_dst, _key, _value);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return;
        }
        struct DictSetItemFailure:Error
        {
            DictSetItemFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw DictSetItemFailure(result, __FILE__, __LINE__);
    }
};

template <>
struct SetItem<Data::Dict::SharedBasePtr, const char*, const ::getdns_dict*>
{
    static void into(Data::Dict::SharedBasePtr& _dst, const char* _key, const ::getdns_dict* _value)
    {
        const ::getdns_return_t result = ::getdns_dict_set_dict(*_dst, _key, _value);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return;
        }
        struct DictSetItemFailure:Error
        {
            DictSetItemFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw DictSetItemFailure(result, __FILE__, __LINE__);
    }
};

template <>
struct SetItem<Data::Dict::SharedBasePtr, const char*, const ::getdns_list*>
{
    static void into(Data::Dict::SharedBasePtr& _dst, const char* _key, const ::getdns_list* _value)
    {
        const ::getdns_return_t result = ::getdns_dict_set_list(*_dst, _key, _value);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return;
        }
        struct DictSetItemFailure:Error
        {
            DictSetItemFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw DictSetItemFailure(result, __FILE__, __LINE__);
    }
};

template <>
struct SetItem<Data::Dict::SharedBasePtr, const char*, const char*>
{
    static void into(Data::Dict::SharedBasePtr& _dst, const char* _key, const char* _value)
    {
        ::getdns_bindata value;
        value.data = const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(_value));
        value.size = std::strlen(_value) + 1;
        return SetItem<Data::Dict::SharedBasePtr, const char*, const ::getdns_bindata*>::into(_dst, _key, &value);
    }
};

template <>
struct SetItem<Data::List::SharedBasePtr, ::size_t, const ::getdns_dict*>
{
    static void into(Data::List::SharedBasePtr& _dst, ::size_t _index, const ::getdns_dict* _value)
    {
        const ::getdns_return_t result = ::getdns_list_set_dict(*_dst, _index, _value);
        if (result == ::GETDNS_RETURN_GOOD)
        {
            return;
        }
        struct ListSetDictFailure:Error
        {
            ListSetDictFailure(::getdns_return_t _error_code, const char* _file, int _line)
                : Error(_error_code, _file, _line)
            { }
        };
        throw ListSetDictFailure(result, __FILE__, __LINE__);
    }
};

template <class D, class K, class V>
D& Data::set_item_of(D& _dst, K _index, V _value)
{
    SetItem<typename D::SharedBasePtr, K, V>::into(_dst.base_ptr_, _index, _value);
    return _dst;
}

template <class R, class S, class K>
Data::Value Data::get(const S& _src, K _index)
{
    const auto look_up_result = look_up<R>(_src, _index);
    switch (look_up_result)
    {
        case Data::LookUpResult::success: return Data::Value(GetItem<R, S, K>::from(_src.base_ptr_, _index));
        case Data::LookUpResult::index_out_of_range: return Data::Value(Data::NotSet());
        case Data::LookUpResult::not_found: return Data::Value(Data::NotSet());
        case Data::LookUpResult::different_type: return Data::Value(Data::NotRequestedType());
    }
    struct UnexpectedEnumValue:std::logic_error
    {
        UnexpectedEnumValue():std::logic_error("look_up_result out of range") { }
    };
    throw UnexpectedEnumValue();
}

template Data::Value Data::get<Data::Dict, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<Data::Dict, Data::Dict, std::string>(const Data::Dict&, std::string);

template Data::Value Data::get<Data::List, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<Data::List, Data::Dict, std::string>(const Data::Dict&, std::string);

template Data::Value Data::get<std::uint32_t, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<std::uint32_t, Data::Dict, std::string>(const Data::Dict&, std::string);

template Data::Value Data::get<boost::asio::ip::address, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<boost::asio::ip::address, Data::Dict, std::string>(const Data::Dict&, std::string);

template Data::Value Data::get<std::string, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<std::string, Data::Dict, std::string>(const Data::Dict&, std::string);

template Data::Value Data::get<Data::Binary, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<Data::Binary, Data::Dict, std::string>(const Data::Dict&, std::string);

template Data::Value Data::get<Data::Fqdn, Data::Dict, const char*>(const Data::Dict&, const char*);
template Data::Value Data::get<Data::Fqdn, Data::Dict, std::string>(const Data::Dict&, std::string);


template Data::Value Data::get<Data::Dict, Data::List, ::size_t>(const Data::List&, ::size_t);
template Data::Value Data::get<Data::List, Data::List, ::size_t>(const Data::List&, ::size_t);
template Data::Value Data::get<std::uint32_t, Data::List, ::size_t>(const Data::List&, ::size_t);
template Data::Value Data::get<boost::asio::ip::address, Data::List, ::size_t>(const Data::List&, ::size_t);
template Data::Value Data::get<std::string, Data::List, ::size_t>(const Data::List&, ::size_t);
template Data::Value Data::get<Data::Binary, Data::List, ::size_t>(const Data::List&, ::size_t);
template Data::Value Data::get<Data::Fqdn, Data::List, ::size_t>(const Data::List&, ::size_t);


template Data::Dict& Data::set_item_of<Data::Dict, const char*, std::uint32_t>(Data::Dict&, const char*, std::uint32_t);
template Data::Dict& Data::set_item_of<Data::Dict, const char*, const ::getdns_bindata*>(Data::Dict&, const char*, const ::getdns_bindata*);
template Data::Dict& Data::set_item_of<Data::Dict, const char*, const ::getdns_dict*>(Data::Dict&, const char*, const ::getdns_dict*);
template Data::Dict& Data::set_item_of<Data::Dict, const char*, const ::getdns_list*>(Data::Dict&, const char*, const ::getdns_list*);
template Data::Dict& Data::set_item_of<Data::Dict, const char*, const char*>(Data::Dict&, const char*, const char*);

template Data::List& Data::set_item_of<Data::List, ::size_t, const ::getdns_dict*>(Data::List&, ::size_t, const ::getdns_dict*);

}//namespace GetDns
