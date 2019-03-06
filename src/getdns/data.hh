/*
 * Copyright (C) 2017-2018  CZ.NIC, z. s. p. o.
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

#include "src/getdns/solver_fwd.hh"

#include <getdns/getdns.h>

#include <string>
#include <set>
#include <iosfwd>
#include <memory>

#include <boost/variant/variant.hpp>
#include <boost/asio/ip/address.hpp>

namespace GetDns {

template <class R, class S, class K> struct GetItem;
template <class D, class K, class V> struct SetItem;

struct Data
{
    class Dict;
    class List;
    enum class Type
    {
        dictionary,
        array,
        binary,
        integer
    };
    template <class T>
    struct HolderOf
    {
        explicit HolderOf(T* src, void(*destroy_fnc)(T*) = nullptr)
            : ptr(src),
              destroy_routine(destroy_fnc) { }
        ~HolderOf() { if (destroy_routine != nullptr) { destroy_routine(ptr); } }
        T* const ptr;
        void(*const destroy_routine)(T*);
    };
    struct Empty { };
    typedef boost::variant<std::shared_ptr<::getdns_dict*>,
                           std::shared_ptr<::getdns_list*>,
                           Empty> HolderOfDataPtr;
    class Binary
    {
    public:
        Binary();
        explicit Binary(const std::string& _binary_data);
        Binary(const void* _binary_data, std::uint32_t _data_length);
        const void* get_binary_data()const;
        std::uint32_t get_length()const;
    private:
        std::string binary_data_;
    };
    enum class LookUpResult
    {
        success,
        index_out_of_range,
        not_found,
        different_type
    };
    class Dict
    {
    public:
        typedef ::getdns_dict Base;
        typedef std::shared_ptr<::getdns_dict*> SharedBasePtr;
        Dict();
        Dict(const Dict& _src);
        ~Dict();
        Dict& operator=(const Dict& _src);
        Type get_data_type_of_item(const char* _key)const;
        Type get_data_type_of_item(const std::string& _key)const;
        typedef std::set<std::string> Keys;
        Keys get_keys()const;
        std::string get_pretty_string()const;
        Base* get_base_ptr();
        const Base* get_base_ptr()const;
        LookUpResult look_up(const char* _key, Type _type)const;
        static Dict get_trust_anchor(
                const std::string& _zone,
                std::uint16_t _flags,
                std::uint8_t _protocol,
                std::uint8_t _algorithm,
                 const Binary& _public_key);
        friend std::ostream& operator<<(std::ostream& out, const Dict& data) { return out << data.get_pretty_string(); }
    private:
        explicit Dict(Base* _base);
        Dict(Base* _base, const std::shared_ptr<::getdns_dict*>& _parent);
        Dict(Base* _base, const std::shared_ptr<::getdns_list*>& _parent);
        SharedBasePtr base_ptr_;
        HolderOfDataPtr parent_;
        friend class Data;
        friend class List;
        friend class Solver;
        template <class R, class S, class K> friend struct GetItem;
        template <class D, class K, class V> friend struct SetItem;
    };
    class List
    {
    public:
        typedef ::getdns_list Base;
        typedef std::shared_ptr<::getdns_list*> SharedBasePtr;
        List();
        List(const List& _src);
        ~List();
        List& operator=(const List& _src);
        std::size_t get_number_of_items()const;
        Type get_data_type_of_item(::size_t _index)const;
        LookUpResult look_up(::size_t _index, Type _type)const;
        const Base* get_base_ptr()const;
        Base* get_base_ptr();
        static List get_root_trust_anchor(::time_t& _utc_date_of_anchor);
    private:
        explicit List(Base* _base);
        List(Base* _base, const std::shared_ptr<::getdns_dict*>& _parent);
        List(Base* _base, const std::shared_ptr<::getdns_list*>& _parent);
        SharedBasePtr base_ptr_;
        HolderOfDataPtr parent_;
        friend class Data;
        friend class Dict;
        template <class R, class S, class K> friend struct GetItem;
        template <class D, class K, class V> friend struct SetItem;
    };
    template <class D, class K, class V>
    static D& set_item_of(D& _dst, K _index, V _value);
    struct Fqdn
    {
        std::string value;
    };
    struct NotSet { };
    struct NotRequestedType { };
    typedef boost::variant<
            Dict,
            List,
            std::uint32_t,
            std::string,
            Binary,
            Fqdn,
            boost::asio::ip::address,
            NotSet,
            NotRequestedType> Value;
    struct TrustAnchor
    {
        std::string zone;
        std::uint16_t flags;
        std::uint8_t protocol;
        std::uint8_t algorithm;
        Binary public_key;
    };
    class Is
    {
    public:
        Is(const Value& _value):value_(_value) { }
        struct Type
        {
            explicit Type(bool value):type(value) { }
            const bool type;
        };
        template <typename T>
        Type of()const;
    private:
        const Value& value_;
    };
    class From
    {
    public:
        From(const Value& _value):value_(_value) { }
        template <typename T>
        const T& get_value_of()const;
    private:
        const Value& value_;
    };
    template <class R, class S, class K>
    static Value get(const S& _src, K _index);
    static Binary base64_decode(const std::string& _base64_encoded_text);
    static std::string base64_encode(const Binary& _raw_data);
};

}//namespace GetDns

#endif//DATA_HH_4BD03E3BE61C61ADC6A6590A94FC068D
