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

#ifndef EXCEPTION_HH_0030927EE255A372CE05363BB615578A//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define EXCEPTION_HH_0030927EE255A372CE05363BB615578A

#include <exception>

#include <getdns/getdns.h>

namespace GetDns {

struct Exception : std::exception { };

struct GenericError : Exception { };
struct BadDomainName : Exception { };
struct BadContext : Exception { };
struct ContextUpdateFail : Exception { };
struct UnknownTransaction : Exception { };
struct NoSuchListItem : Exception { };
struct NoSuchDictName : Exception { };
struct WrongTypeRequested : Exception { };
struct NoSuchExtension : Exception { };
struct ExtensionMisformat : Exception { };
struct DnssecWithStubDisallowed : Exception { };
struct MemoryError : Exception { };
struct InvalidParameter : Exception { };
struct NotImplemented : Exception { };
struct IoError : Exception { };
struct NoUpstreamAvailable : Exception { };
struct NeedMoreSpace : Exception { };
struct UnknownGetDnsErrorCode : Exception { };

void success_required(::getdns_return_t result, const char* file, int line);

template <typename> [[noreturn]] void raise(const char* file, int line);

template <> [[noreturn]] void raise<GenericError>(const char* file, int line);
template <> [[noreturn]] void raise<BadDomainName>(const char* file, int line);
template <> [[noreturn]] void raise<BadContext>(const char* file, int line);
template <> [[noreturn]] void raise<ContextUpdateFail>(const char* file, int line);
template <> [[noreturn]] void raise<UnknownTransaction>(const char* file, int line);
template <> [[noreturn]] void raise<NoSuchListItem>(const char* file, int line);
template <> [[noreturn]] void raise<NoSuchDictName>(const char* file, int line);
template <> [[noreturn]] void raise<WrongTypeRequested>(const char* file, int line);
template <> [[noreturn]] void raise<NoSuchExtension>(const char* file, int line);
template <> [[noreturn]] void raise<ExtensionMisformat>(const char* file, int line);
template <> [[noreturn]] void raise<DnssecWithStubDisallowed>(const char* file, int line);
template <> [[noreturn]] void raise<MemoryError>(const char* file, int line);
template <> [[noreturn]] void raise<InvalidParameter>(const char* file, int line);
template <> [[noreturn]] void raise<NotImplemented>(const char* file, int line);
template <> [[noreturn]] void raise<IoError>(const char* file, int line);
template <> [[noreturn]] void raise<NoUpstreamAvailable>(const char* file, int line);
template <> [[noreturn]] void raise<NeedMoreSpace>(const char* file, int line);
template <> [[noreturn]] void raise<UnknownGetDnsErrorCode>(const char* file, int line);

#define MUST_BE_GOOD(RESULT) ::GetDns::success_required(RESULT, __FILE__, __LINE__)

}//namespace GetDns

#endif//EXCEPTION_HH_0030927EE255A372CE05363BB615578A
