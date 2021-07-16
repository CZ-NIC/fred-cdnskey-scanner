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

#ifndef BASE_HH_32D195DD34FB9368357A0101AA561CD6//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define BASE_HH_32D195DD34FB9368357A0101AA561CD6

#include "src/util/is_unique.hh"

#include <event2/event.h>

#include <chrono>
#include <exception>
#include <iostream>


namespace Event {

struct Exception : std::exception { };

struct Loop
{
    template <typename> struct Flag { };
    using Once = Flag<struct Once_>;
    using Nonblock = Flag<struct Nonblock_>;
};

class Base
{
public:
    explicit Base();
    ~Base();
    enum class Result
    {
        success,
        no_events
    };
    template <typename ...Tags>
    Result operator()(Loop::Flag<Tags>...);
    operator ::event_base*() noexcept;
private:
    static constexpr int as_int() noexcept { return 0; }
    static constexpr int as_int(Loop::Once) noexcept { return EVLOOP_ONCE; }
    static constexpr int as_int(Loop::Nonblock) noexcept { return EVLOOP_NONBLOCK; }
    template <typename FirstTag, typename ...Tags>
    static constexpr int as_int(Loop::Flag<FirstTag> first_flag, Loop::Flag<Tags> ...other_flags) noexcept
    {
        static_assert(as_int(first_flag) != 0);
        return as_int(first_flag) | as_int(other_flags...);
    }
    Result loop(int flags);
    ::event_base* ptr_;
};


template <typename ...Tags>
Base::Result Base::operator()(Loop::Flag<Tags> ...flags)
{
    static_assert(Util::IsUnique<Tags...>::value);
    return this->loop(as_int(flags...));
}

class TimeoutEvent
{
public:
    TimeoutEvent(Base& base, ::event_callback_fn on_timeout);
    ~TimeoutEvent();
    TimeoutEvent& set(std::chrono::microseconds timeout);
    TimeoutEvent& remove();
    bool has_descriptor(int fd) const noexcept;
private:
    class Descriptor
    {
    public:
        Descriptor();
        ~Descriptor();
        operator int() const noexcept;
        void free() noexcept;
    private:
        int number_;
    };
    Descriptor descriptor_;
    struct ::event* event_ptr_;
};

template <typename Derived>
class OnTimeout
{
public:
    OnTimeout(Base& base);
    OnTimeout& operator()()
    {
        static_cast<Derived*>(this)->on_timeout_occurrence();
        return *this;
    }
    OnTimeout& set(std::chrono::microseconds timeout);
    OnTimeout& remove();
    bool has_descriptor(int fd) const noexcept;
private:
    static void callback_routine(evutil_socket_t fd, short events, void* user_data_ptr);
    TimeoutEvent timeout_event_;
};

template <typename Derived>
OnTimeout<Derived>::OnTimeout(Base& base)
    : timeout_event_{base, callback_routine}
{ }

template <typename Derived>
OnTimeout<Derived>& OnTimeout<Derived>::set(std::chrono::microseconds timeout)
{
    timeout_event_.set(timeout);
    return *this;
}

template <typename Derived>
OnTimeout<Derived>& OnTimeout<Derived>::remove()
{
    timeout_event_.remove();
    return *this;
}

template <typename Derived>
bool OnTimeout<Derived>::has_descriptor(int fd) const noexcept
{
    return timeout_event_.has_descriptor(fd);
}

template <typename Derived>
void OnTimeout<Derived>::callback_routine(evutil_socket_t fd, short events, void* user_data_ptr)
{
    auto* const event_ptr = reinterpret_cast<OnTimeout<Derived>*>(user_data_ptr);
    if ((event_ptr != nullptr) && (event_ptr->has_descriptor(fd)))
    {
        try
        {
            static_assert(EV_TIMEOUT != 0);
            const bool timeout_occured = (events & EV_TIMEOUT) == EV_TIMEOUT;
            if (timeout_occured)
            {
                static_cast<Derived*>(event_ptr)->on_timeout_occurrence();
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Timeout::on_event failed: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Timeout::on_event threw unexpected exception" << std::endl;
        }
    }
}

}//namespace Event

#endif//BASE_HH_32D195DD34FB9368357A0101AA561CD6
