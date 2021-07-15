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

#include "src/util/pipe.hh"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <sstream>

namespace Util {

namespace {

constexpr int invalid_descriptor = -1;

enum class Direction
{
    read,
    write
};

template <Direction direction>
void close(int (&pipe_fd)[2]);

template <Direction direction>
void dup(int (&pipe_fd)[2], int new_fd);

template <Direction direction>
struct Descriptor { };

template <>
struct Descriptor<Direction::read>
{
    static int& get(int (&pipe_fd)[2])
    {
        return pipe_fd[idx_of_reading_end];
    }
    static int get(const int (&pipe_fd)[2])
    {
        return pipe_fd[idx_of_reading_end];
    }
    static const int idx_of_reading_end = 0;
};

template <>
struct Descriptor<Direction::write>
{
    static int& get(int (&pipe_fd)[2])
    {
        return pipe_fd[idx_of_writing_end];
    }
    static int get(const int (&pipe_fd)[2])
    {
        return pipe_fd[idx_of_writing_end];
    }
    static const int idx_of_writing_end = 1;
};

}//namespace Util::{anonymous}

Pipe::Pipe()
{
    static const int success = 0;
    const int retval = ::pipe(fd_);
    if (retval != success)
    {
        struct PipeFailed:std::runtime_error
        {
            PipeFailed(int error_code):std::runtime_error(std::string("pipe() failed: ") + std::strerror(error_code)) { }
        };
        throw PipeFailed(errno);
    }
}

Pipe::~Pipe()
{
    try { close<Direction::read>(fd_); } catch (...) { }
    try { close<Direction::write>(fd_); } catch (...) { }
}

ImReader::ImReader(Pipe& _pipe)
:   pipe_(_pipe)
{
    close<Direction::write>(_pipe.fd_);
}

void ImReader::set_nonblocking()const
{
    struct FcntlFailed:std::runtime_error
    {
        FcntlFailed(int error_code):std::runtime_error(std::string("fcntl() failed: ") + std::strerror(error_code)) { }
    };
    static constexpr int failure = -1;
    const int current_flags = ::fcntl(this->get_descriptor(), F_GETFL);
    if (current_flags == failure)
    {
        throw FcntlFailed(errno);
    }
    const bool is_nonblocking = (current_flags & O_NONBLOCK) != 0;
    if (is_nonblocking)
    {
        return;
    }
    const int new_flags = current_flags | O_NONBLOCK;
    static constexpr int success = 0;
    if (::fcntl(this->get_descriptor(), F_SETFL, new_flags) != success)
    {
        throw FcntlFailed(errno);
    }
}

int ImReader::get_descriptor()const
{
    return Descriptor<Direction::read>::get(pipe_.fd_);
}

namespace {

int get_descriptor_number_of(ImWriter::Stream stream)
{
    switch (stream)
    {
        case ImWriter::Stream::stdout:
            return STDOUT_FILENO;
        case ImWriter::Stream::stderr:
            return STDERR_FILENO;
    }
    throw std::logic_error("unexpected enum value");
}

}//namespace Util::{anonymous}

ImWriter::ImWriter(Pipe& _pipe, Stream _into)
:   pipe_(_pipe)
{
    close<Direction::read>(_pipe.fd_);
    dup<Direction::write>(_pipe.fd_, get_descriptor_number_of(_into));
}

namespace {

template <Direction direction>
void close(int (&pipe_fd)[2])
{
    int& fd = Descriptor<direction>::get(pipe_fd);
    if (fd != invalid_descriptor)
    {
        const int result = ::close(fd);
        static constexpr int success = 0;
        if (result == success)
        {
            fd = invalid_descriptor;
            return;
        }
        struct CloseFailed:std::runtime_error
        {
            CloseFailed(int error_code):std::runtime_error(std::string("close() failed: ") + std::strerror(error_code)) { }
        };
        throw CloseFailed(errno);
    }
}

template <Direction direction>
void dup(int (&pipe_fd)[2], int new_fd)
{
    static constexpr int failure = -1;
    const int retval = ::dup2(Descriptor<direction>::get(pipe_fd), new_fd);
    if (retval != failure)
    {
        close<direction>(pipe_fd);
        return;
    }
    struct Dup2Failed:std::runtime_error
    {
        Dup2Failed(int error_code):std::runtime_error(std::string("dup2() failed: ") + std::strerror(error_code)) { }
    };
    throw Dup2Failed(errno);
}

}//namespace Util::{anonymous}

}//namespace Util
