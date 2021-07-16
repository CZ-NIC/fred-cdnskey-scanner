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

#include "src/event/base.hh"

#include "src/getdns/exception.hh"

#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utility>


namespace Event {

Base::Base()
    : ptr_{::event_base_new()}
{
    if (ptr_ == nullptr)
    {
        struct BaseException : Exception
        {
            const char* what()const noexcept override { return "Could not create event base"; }
        };
        throw BaseException();
    }
}

Base::~Base()
{
    if (ptr_ != nullptr)
    {
        ::event_base_free(ptr_);
        ptr_ = nullptr;
    }
}

Base::Result Base::loop(int flags)
{
    switch (::event_base_loop(ptr_, flags))
    {
        case 0:
            return Result::success;
        case 1:
            return Result::no_events;
        case -1:
            {
                struct DispatchingException : Exception
                {
                    const char* what() const noexcept override { return "Error occurred during events loop"; }
                };
                throw DispatchingException{};
            }
    }
    struct DispatchingException : Exception
    {
        const char* what() const noexcept override { return "event_base_loop returned unexpected value"; }
    };
    throw DispatchingException{};
}

Base::operator ::event_base*() noexcept
{
    return ptr_;
}

namespace {

constexpr char dev_null_file[] = "/dev/null";

int get_file_descriptor()
{
    const int open_failed = -1;
    const int fd = ::open(dev_null_file, O_RDONLY);
    if (fd != open_failed)
    {
        return fd;
    }
    struct OpenFailure : Exception
    {
        OpenFailure(const char* desc) : desc_{desc} { }
        const char* what() const noexcept override { return desc_; }
        const char* const desc_;
    };
    const int c_errno = errno;
    throw OpenFailure{std::strerror(c_errno)};
}

auto to_timeval(std::chrono::microseconds t)
{
    struct ::timeval result;
    static constexpr auto units_per_second = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds{1}).count();
    result.tv_sec = t.count() / units_per_second;
    result.tv_usec = t.count() % units_per_second;
    return result;
}

}//namespace Event::{anonymous}

TimeoutEvent::TimeoutEvent(Base& base, event_callback_fn on_timeout)
    : descriptor_{},
      event_ptr_{::event_new(base, descriptor_, EV_TIMEOUT, on_timeout, this)}
{ }

TimeoutEvent::~TimeoutEvent()
{
    if (event_ptr_ != nullptr)
    {
        ::event_del(event_ptr_);
        ::event_free(event_ptr_);
    }
}

TimeoutEvent& TimeoutEvent::set(std::chrono::microseconds timeout)
{
    const auto wait_at_most = [&]()
    {
        static constexpr auto min_timeout = std::chrono::microseconds{1000};
        static_assert((std::chrono::seconds::zero() <= min_timeout) && (min_timeout < std::chrono::seconds{1}));
        const bool timeout_too_short = timeout < min_timeout;
        return timeout_too_short ? to_timeval(min_timeout)
                                 : to_timeval(timeout);
    }();
    const int retval = ::event_add(event_ptr_, &wait_at_most);
    static constexpr int success = 0;
    if (retval == success)
    {
        return *this;
    }
    struct EventAddFailure : Exception
    {
        const char* what() const noexcept override { return "event_add failed"; }
    };
    throw EventAddFailure{};
}

TimeoutEvent& TimeoutEvent::remove()
{
    if (event_ptr_ != nullptr)
    {
        ::event_del(event_ptr_);
        ::event_free(event_ptr_);
        event_ptr_ = nullptr;
    }
    descriptor_.free();
    return *this;
}

bool TimeoutEvent::has_descriptor(int fd) const noexcept
{
    return descriptor_ == fd;
}

TimeoutEvent::Descriptor::Descriptor()
    : number_{get_file_descriptor()}
{ }

TimeoutEvent::Descriptor::~Descriptor()
{
    this->free();
}

TimeoutEvent::Descriptor::operator int() const noexcept
{
    return number_;
}

void TimeoutEvent::Descriptor::free() noexcept
{
    static constexpr int invalid_descriptor = -1;
    if (number_ != invalid_descriptor)
    {
        ::close(number_);
        number_ = invalid_descriptor;
    }
}

}//namespace Event
