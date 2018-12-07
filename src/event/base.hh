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
#ifndef BASE_HH_32D195DD34FB9368357A0101AA561CD6//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define BASE_HH_32D195DD34FB9368357A0101AA561CD6

#include <event2/event.h>

#include <cstdint>
#include <exception>

namespace Event
{

struct Exception:std::exception { };

class Base
{
public:
    Base();
    ~Base();
    enum class Result
    {
        success,
        no_events
    };
    Result loop();
    ::event_base* get_base();
private:
    ::event_base* base_;
};

class OnTimeout
{
protected:
    virtual ~OnTimeout() { }
    virtual OnTimeout& on_timeout_occurrence() = 0;
};

class Timeout:protected OnTimeout
{
public:
    Timeout(Base& _base);
    ~Timeout();
    Timeout& set(std::uint64_t _timeout_usec);
    Timeout& remove();
private:
    void on_event(short _events);
    static void callback_routine(evutil_socket_t _fd, short _events, void* _user_data_ptr);
    int fd_;
    struct ::event* event_ptr_;
};

}//namespace Event

#endif//BASE_HH_32D195DD34FB9368357A0101AA561CD6
