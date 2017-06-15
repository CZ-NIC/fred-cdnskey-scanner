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

#include "src/event/base.hh"

namespace Event
{

Base::Base()
    : base_(::event_base_new())
{
    if (base_ == NULL)
    {
        struct BaseException:Exception
        {
            const char* what()const throw() { return "Could not create event base"; }
        };
        throw BaseException();
    }
}

Base::~Base()
{
    if (base_ != NULL)
    {
        ::event_base_free(base_);
        base_ = NULL;
    }
}

Base::Result::Enum Base::loop()
{
    struct Repeate
    {
        enum Flag
        {
            once,
            while_an_active_consumer
        };
    };
    struct Wait
    {
        enum Flag
        {
            next_event,
            do_not_wait
        };
    };
    struct Flag
    {
        Flag(Repeate::Flag value):as_int(value == Repeate::once ? EVLOOP_ONCE : 0) { }
        Flag(Wait::Flag value):as_int(value == Wait::do_not_wait ? EVLOOP_NONBLOCK : 0) { }
        const int as_int;
    };
    const int flags = Flag(Repeate::once).as_int | Flag(Wait::next_event).as_int;

    switch (::event_base_loop(base_, flags))
    {
    case 0:
        return Result::success;
    case 1:
        return Result::no_events;
    case -1:
        {
            struct DispatchingException:Exception
            {
                const char* what()const throw() { return "Error occurred during events loop"; }
            };
            throw DispatchingException();
        }
    }
    struct DispatchingException:Exception
    {
        const char* what()const throw() { return "event_base_loop returned unexpected value"; }
    };
    throw DispatchingException();
}

::event_base* Base::get_base()
{
    return base_;
}

}//namespace Event
