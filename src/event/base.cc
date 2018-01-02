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

#include "src/event/base.hh"

#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

namespace Event
{

Base::Base()
    : base_(::event_base_new())
{
    if (base_ == nullptr)
    {
        struct BaseException:Exception
        {
            const char* what()const noexcept override { return "Could not create event base"; }
        };
        throw BaseException();
    }
}

Base::~Base()
{
    if (base_ != nullptr)
    {
        ::event_base_free(base_);
        base_ = nullptr;
    }
}

Base::Result Base::loop()
{
    enum class Repeate
    {
        once,
        while_an_active_consumer
    };
    enum class Wait
    {
        next_event,
        do_not_wait
    };
    struct Flag
    {
        constexpr Flag(Repeate value):as_int(value == Repeate::once ? EVLOOP_ONCE : 0) { }
        constexpr Flag(Wait value):as_int(value == Wait::do_not_wait ? EVLOOP_NONBLOCK : 0) { }
        const int as_int;
    };
    constexpr int flags = Flag(Repeate::once).as_int | Flag(Wait::next_event).as_int;

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
                const char* what()const noexcept override { return "Error occurred during events loop"; }
            };
            throw DispatchingException();
        }
    }
    struct DispatchingException:Exception
    {
        const char* what()const noexcept override { return "event_base_loop returned unexpected value"; }
    };
    throw DispatchingException();
}

::event_base* Base::get_base()
{
    return base_;
}

namespace
{

constexpr char dev_null_file[] = "/dev/null";

int get_file_descriptor()
{
    const int open_failed = -1;
    const int fd = ::open(dev_null_file, O_RDONLY);
    if (fd != open_failed)
    {
        return fd;
    }
    struct OpenFailure:Exception
    {
        OpenFailure(const char* _desc):desc_(_desc) { }
        const char* what()const noexcept override { return desc_; }
        const char* const desc_;
    };
    const int c_errno = errno;
    throw OpenFailure(std::strerror(c_errno));
}

}//namespace Event::{anonymous}

Timeout::Timeout(Base& _base)
    : fd_(get_file_descriptor()),
      event_ptr_(::event_new(_base.get_base(), fd_, EV_TIMEOUT, callback_routine, this))
{
}

Timeout::~Timeout()
{
    if (event_ptr_ != nullptr)
    {
        ::event_del(event_ptr_);
        ::event_free(event_ptr_);
    }
    const int invalid_descriptor = -1;
    if (fd_ != invalid_descriptor)
    {
        ::close(fd_);
    }
}

Timeout& Timeout::set(std::uint64_t _timeout_usec)
{
    const int success = 0;
    struct ::timeval timeout;
    timeout.tv_sec = _timeout_usec / 1000000;
    timeout.tv_usec = _timeout_usec % 1000000;
    const long min_timeout_usec = 1000;
    const bool timeout_too_short = (timeout.tv_sec <= 0) && (timeout.tv_usec < min_timeout_usec);
    if (timeout_too_short)
    {
        timeout.tv_usec = min_timeout_usec;
    }
    const int retval = ::event_add(event_ptr_, &timeout);
    if (retval == success)
    {
        return *this;
    }
    struct EventAddFailure:Exception
    {
        const char* what()const noexcept override { return "event_add failed"; }
    };
    throw EventAddFailure();
}

Timeout& Timeout::remove()
{
    if (event_ptr_ != nullptr)
    {
        ::event_del(event_ptr_);
        ::event_free(event_ptr_);
        event_ptr_ = nullptr;
    }
    const int invalid_descriptor = -1;
    if (fd_ != invalid_descriptor)
    {
        ::close(fd_);
        fd_ = invalid_descriptor;
    }
    return *this;
}

void Timeout::on_event(short _events)
{
    if ((_events & EV_TIMEOUT) != 0)
    {
        this->on_timeout_occurrence();
    }
}

void Timeout::callback_routine(evutil_socket_t _fd, short _events, void* _user_data_ptr)
{
    auto const event_ptr = static_cast<Timeout*>(_user_data_ptr);
    if ((event_ptr != nullptr) && (event_ptr->fd_ == _fd))
    {
        try
        {
            event_ptr->on_event(_events);
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
