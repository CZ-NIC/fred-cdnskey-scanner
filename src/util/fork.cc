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

#include "src/util/fork.hh"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <string>

namespace Util {

Fork::~Fork()
{

}

void Fork::init()
{
    const ::pid_t error = -1;
    if (fork_result_ == error)
    {
        struct ForkFailed:std::runtime_error
        {
            ForkFailed(int _error_code):std::runtime_error(std::string("fork() failed: ") + std::strerror(_error_code)) { }
        };
        throw ForkFailed(errno);
    }
}

Fork::ChildResultStatus Fork::get_child_result_status()
{
    if (!child_is_running_)
    {
        throw std::runtime_error("no child is running");
    }
    return ChildResultStatus(*this, ChildResultStatus::Waitpid::return_immediately);
}

namespace {

int get_process_exit_status(::pid_t process, bool wait_on_exit)
{
    const bool wait_for_specific_process = 0 < process;
    if (!wait_for_specific_process)
    {
        struct RequestedPidOutOfRange:std::runtime_error
        {
            RequestedPidOutOfRange():std::runtime_error("requested pid is out of range") { }
        };
        throw RequestedPidOutOfRange();
    }
    int status;
    const ::pid_t waitpid_failed = -1;
    const ::pid_t waitpid_child_is_still_running = 0;
    struct UnexpectedWaitpidResult:std::runtime_error
    {
        UnexpectedWaitpidResult():std::runtime_error("unexpected result of waitpid") { }
    };
    const ::pid_t waitpid_result = ::waitpid(process, &status, wait_on_exit ? 0 : WNOHANG);
    switch (waitpid_result)
    {
        case waitpid_failed:
        {
            struct WaitpidFailed:std::runtime_error
            {
                WaitpidFailed(int _error_code):std::runtime_error(std::string("waitpid() failed: ") + std::strerror(_error_code)) { }
            };
            throw WaitpidFailed(errno);
        }
        case waitpid_child_is_still_running:
            if (!wait_on_exit)
            {
                throw Fork::ChildIsStillRunning();
            }
            throw UnexpectedWaitpidResult();
    }
    if (waitpid_result == process)
    {
        return status;
    }
    throw UnexpectedWaitpidResult();
}

}//namespace Util::{anonymous}

Fork::ChildResultStatus Fork::kill_child()
{
    if (!child_is_running_)
    {
        throw std::runtime_error("no child is running");
    }
    const int success = 0;
    const int kill_result = ::kill(fork_result_, SIGKILL);
    if (kill_result == success)
    {
        return ChildResultStatus(*this, ChildResultStatus::Waitpid::wait_on_exit);
    }
    struct KillFailed:std::runtime_error
    {
        KillFailed(int _error_code):std::runtime_error(std::string("kill() failed: ") + std::strerror(_error_code)) { }
    };
    throw KillFailed(errno);
}

const char* Fork::ChildIsStillRunning::what()const throw()
{
    return "child is still running";
}

Fork::ChildResultStatus::ChildResultStatus(Fork& _parent, Waitpid::Option _option)
    : status_(get_process_exit_status(_parent.fork_result_, _option == Waitpid::wait_on_exit))
{
    _parent.child_is_running_ = false;
}

Fork::ChildResultStatus::ChildResultStatus(const ChildResultStatus& _src)
: status_(_src.status_)
{
}

bool Fork::ChildResultStatus::exited()const
{
    return WIFEXITED(status_);
}

int Fork::ChildResultStatus::get_exit_status()const
{
    return WEXITSTATUS(status_);
}

bool Fork::ChildResultStatus::signaled()const
{
    return WIFSIGNALED(status_);
}

int Fork::ChildResultStatus::get_signal_number()const
{
    return WTERMSIG(status_);
}

}//namespace Util
