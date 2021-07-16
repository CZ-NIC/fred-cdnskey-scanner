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

#ifndef IS_UNIQUE_HH_402F8C544DBDC3C01AB7963CE4E5F1D2//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define IS_UNIQUE_HH_402F8C544DBDC3C01AB7963CE4E5F1D2

#include <type_traits>


namespace Util {

template <typename S, typename ...Ts> struct HasType;
template <typename S, typename ...Ts>
struct HasType<S, S, Ts...> : std::true_type { };

template <typename S, typename T, typename ...Ts>
struct HasType<S, T, Ts...> : HasType<S, Ts...> { };

template <typename S>
struct HasType<S> : std::false_type { };

template <typename ...> struct IsUnique;

template <>
struct IsUnique<> : std::true_type { };

template <typename T, typename ...Ts>
struct IsUnique<T, Ts...> : std::integral_constant<bool, !HasType<T, Ts...>::value && IsUnique<Ts...>::value> { };

}//namespace Util

#endif//IS_UNIQUE_HH_402F8C544DBDC3C01AB7963CE4E5F1D2
