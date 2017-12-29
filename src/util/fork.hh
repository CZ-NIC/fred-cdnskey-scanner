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

#ifndef FORK_HH_423F047A86768FC03DCC0C0747FC631C//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define FORK_HH_423F047A86768FC03DCC0C0747FC631C

#include <unistd.h>
#include <cstdlib>
#include <exception>

namespace Util {

class Fork
{
public:
    template <typename C>
    Fork(const C& _child);
    struct ChildIsStillRunning:std::exception
    {
        const char* what()const noexcept override;
    };
    class ChildResultStatus
    {
    public:
        ChildResultStatus(const ChildResultStatus& _src);
        bool exited()const;
        int get_exit_status()const;
        bool signaled()const;
        int get_signal_number()const;
    private:
        enum class WaitpidOption
        {
            wait_on_exit,
            return_immediately
        };
        ChildResultStatus(Fork& _parent, WaitpidOption _option);
        const int status_;
        friend class Fork;
    };
    ChildResultStatus get_child_result_status();
    ChildResultStatus kill_child();
    ~Fork();
private:
    void init();
    const ::pid_t fork_result_;
    bool child_is_running_;
};

template <typename C>
Fork::Fork(const C& _child)
    : fork_result_(::fork()),
      child_is_running_(0 < fork_result_)
{
    const int im_child = 0;
    if (fork_result_ == im_child)
    {
        try
        {
            const int child_exit_status = _child();
            ::_exit(child_exit_status);
        }
        catch (...)
        {
            ::_exit(EXIT_FAILURE);
        }
    }
    this->init();
}

}//namespace Util

#endif//FORK_HH_423F047A86768FC03DCC0C0747FC631C
