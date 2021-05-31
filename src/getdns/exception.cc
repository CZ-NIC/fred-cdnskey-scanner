/*
 * Copyright (C) 2021  CZ.NIC, z. s. p. o.
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

#include "src/getdns/exception.hh"

#include <getdns/getdns_extra.h>

#include <iostream>
#include <sstream>

namespace GetDns {

namespace {

void log_error(const char* file, int line, const char* msg)
{
    std::ostringstream out;
    out << "at " << file << ":" << line << " occurred: " << msg << std::endl;
    std::cerr << out.str();
}

}//namespace GetDns::{anonymous}

template <>
[[noreturn]] void raise<GenericError>(const char* file, int line)
{
    struct Error : GenericError
    {
        const char* what() const noexcept override { return GETDNS_RETURN_GENERIC_ERROR_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<BadDomainName>(const char* file, int line)
{
    struct Error : BadDomainName
    {
        const char* what() const noexcept override { return GETDNS_RETURN_BAD_DOMAIN_NAME_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<BadContext>(const char* file, int line)
{
    struct Error : BadContext
    {
        const char* what() const noexcept override { return GETDNS_RETURN_BAD_CONTEXT_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<ContextUpdateFail>(const char* file, int line)
{
    struct Error : ContextUpdateFail
    {
        const char* what() const noexcept override { return GETDNS_RETURN_CONTEXT_UPDATE_FAIL_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<UnknownTransaction>(const char* file, int line)
{
    struct Error : UnknownTransaction
    {
        const char* what() const noexcept override { return GETDNS_RETURN_UNKNOWN_TRANSACTION_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<NoSuchListItem>(const char* file, int line)
{
    struct Error : NoSuchListItem
    {
        const char* what() const noexcept override { return GETDNS_RETURN_NO_SUCH_LIST_ITEM_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<NoSuchDictName>(const char* file, int line)
{
    struct Error : NoSuchDictName
    {
        const char* what() const noexcept override { return GETDNS_RETURN_NO_SUCH_DICT_NAME_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<WrongTypeRequested>(const char* file, int line)
{
    struct Error : WrongTypeRequested
    {
        const char* what() const noexcept override { return GETDNS_RETURN_WRONG_TYPE_REQUESTED_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<NoSuchExtension>(const char* file, int line)
{
    struct Error : NoSuchExtension
    {
        const char* what() const noexcept override { return GETDNS_RETURN_NO_SUCH_EXTENSION_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<ExtensionMisformat>(const char* file, int line)
{
    struct Error : ExtensionMisformat
    {
        const char* what() const noexcept override { return GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<DnssecWithStubDisallowed>(const char* file, int line)
{
    struct Error : DnssecWithStubDisallowed
    {
        const char* what() const noexcept override { return GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<MemoryError>(const char* file, int line)
{
    struct Error : MemoryError
    {
        const char* what() const noexcept override { return GETDNS_RETURN_MEMORY_ERROR_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<InvalidParameter>(const char* file, int line)
{
    struct Error : InvalidParameter
    {
        const char* what() const noexcept override { return GETDNS_RETURN_INVALID_PARAMETER_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<NotImplemented>(const char* file, int line)
{
    struct Error : NotImplemented
    {
        const char* what() const noexcept override { return GETDNS_RETURN_NOT_IMPLEMENTED_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<IoError>(const char* file, int line)
{
    struct Error : IoError
    {
        const char* what() const noexcept override { return GETDNS_RETURN_IO_ERROR_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<NoUpstreamAvailable>(const char* file, int line)
{
    struct Error : NoUpstreamAvailable
    {
        const char* what() const noexcept override { return GETDNS_RETURN_NO_UPSTREAM_AVAILABLE_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

template <>
[[noreturn]] void raise<NeedMoreSpace>(const char* file, int line)
{
    struct Error : NeedMoreSpace
    {
        const char* what() const noexcept override { return GETDNS_RETURN_NEED_MORE_SPACE_TEXT; }
    };
    log_error(file, line, Error{}.what());
    throw Error{};
}

void success_required(::getdns_return_t result, const char* file, int line)
{
    if (result == ::GETDNS_RETURN_GOOD)
    {
        return;
    }
    switch (result)
    {
        case ::GETDNS_RETURN_GOOD:
            return;
        case ::GETDNS_RETURN_GENERIC_ERROR:
            raise<GenericError>(file, line);
        case ::GETDNS_RETURN_BAD_DOMAIN_NAME:
            raise<BadDomainName>(file, line);
        case ::GETDNS_RETURN_BAD_CONTEXT:
            raise<BadContext>(file, line);
        case ::GETDNS_RETURN_CONTEXT_UPDATE_FAIL:
            raise<ContextUpdateFail>(file, line);
        case ::GETDNS_RETURN_UNKNOWN_TRANSACTION:
            raise<UnknownTransaction>(file, line);
        case ::GETDNS_RETURN_NO_SUCH_LIST_ITEM:
            raise<NoSuchListItem>(file, line);
        case ::GETDNS_RETURN_NO_SUCH_DICT_NAME:
            raise<NoSuchDictName>(file, line);
        case ::GETDNS_RETURN_WRONG_TYPE_REQUESTED:
            raise<WrongTypeRequested>(file, line);
        case ::GETDNS_RETURN_NO_SUCH_EXTENSION:
            raise<NoSuchExtension>(file, line);
        case ::GETDNS_RETURN_EXTENSION_MISFORMAT:
            raise<ExtensionMisformat>(file, line);
        case ::GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED:
            raise<DnssecWithStubDisallowed>(file, line);
        case ::GETDNS_RETURN_MEMORY_ERROR:
            raise<MemoryError>(file, line);
        case ::GETDNS_RETURN_INVALID_PARAMETER:
            raise<InvalidParameter>(file, line);
        case ::GETDNS_RETURN_NOT_IMPLEMENTED:
            raise<NotImplemented>(file, line);
    }
    switch (static_cast<int>(result))
    {
        case GETDNS_RETURN_IO_ERROR:
            raise<IoError>(file, line);
        case GETDNS_RETURN_NO_UPSTREAM_AVAILABLE:
            raise<NoUpstreamAvailable>(file, line);
        case GETDNS_RETURN_NEED_MORE_SPACE:
            raise<NeedMoreSpace>(file, line);
    }
    class Error : public UnknownGetDnsErrorCode
    {
    public:
        explicit Error(::getdns_return_t result)
            : UnknownGetDnsErrorCode{},
              msg_{"unknown GetDns return value " + std::to_string(result)}
        { }
        const char* what() const noexcept override { return msg_.c_str(); }
    private:
        std::string msg_;
    };
    const Error error{result};
    log_error(file, line, error.what());
    throw error;
}

}//namespace GetDns
