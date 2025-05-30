// Copyright (c) 2024-2025 Grigoryev Vyacheslav Vladimirovich
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "utils.h"
#include "interceptor_types.h"

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <limits>
#include <exception>
#include <system_error>
#include <algorithm>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <iostream>

namespace fan_interceptor::utils {

// Prefixes an output with steady clock's seconds and milliseconds
sync_logger::step_out sync_logger::operator()(bool add_endl) {
    ::timespec ts;
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    std::unique_lock l{m_mutex};
    m_os << std::dec << ts.tv_sec << '.' << std::setw(3) << std::setfill('0') << ts.tv_nsec / 1'000'000L
        << " [" << ::gettid() << "] ";
    return {std::move(l), m_os, add_endl};
}

sync_logger g_sync_logger{std::cout};

std::vector<char> read_whole_file(const char* path, int atdir_fd) {
    fd_holder fd;
    if (atdir_fd >= 0)
        fd.reset(::openat(atdir_fd, path, O_CLOEXEC | O_RDONLY));
    else
        fd.reset(::open(path, O_CLOEXEC | O_RDONLY));

    if (! fd)
        throw std::system_error(errno, std::generic_category(),
            "unable open file '" + std::string{path} + "' for whole "
            "reading");

    std::vector<char> buffer(16 * 1024);
    size_t total = 0;

    while (true) {
        auto read_bytes = ::read(fd.handle(), buffer.data() + total, buffer.size() - total);
        if (read_bytes < 0) {
            if (errno == EAGAIN)
                continue;

            throw std::system_error(errno, std::generic_category(),
                "unable to read file '" + std::string{path} + '\'');
        }

        total += (size_t)read_bytes;
        if (read_bytes == 0) {
            buffer.resize(total);
            return buffer;
        }

        if (total == buffer.size())
            buffer.resize(buffer.size() * 2);
    }
}

std::string_view trim_left(std::string_view str) {
    while (! str.empty() && std::isspace(*str.begin()))
        str.remove_prefix(1);
    return str;
}

std::string_view trim_right(std::string_view str) {
    while (! str.empty() && std::isspace(*str.rbegin()))
        str.remove_suffix(1);
    return str;
}

template <class T>
num_conv_result to_number_ref(std::string_view str, T& val, int base,
        std::enable_if_t<details::is_for_strtol<T>::value, void>*) {

    char* eptr;
    char buffer[std::numeric_limits<T>::digits10 + 3];

    // Original strto(u)l swallows spaces at the beginning - let's preserve this behavior
    // assuming that we need to prepare local buffer and it has no undetermined size for
    // these spaces
    str = trim(str);

    if (str.size() >= sizeof(buffer))
        return num_conv_result::overflow;

    str.copy(buffer, str.size());
    buffer[str.size()] = '\0';
    long l_val = ::strtol(buffer, &eptr, base);
    if (val == LONG_MIN || val == LONG_MAX)
        return num_conv_result::overflow;
    if (eptr != buffer + str.size())
        return num_conv_result::garbage;

    if constexpr (std::is_same_v<T, long>) {
        val = l_val;
        return num_conv_result::ok;
    } else {
        if (l_val < static_cast<long>(std::numeric_limits<T>::min()) ||
            l_val > static_cast<long>(std::numeric_limits<T>::max()))
            return num_conv_result::overflow;
        val = static_cast<T>(l_val);
        return num_conv_result::ok;
    }
}

template <class T>
num_conv_result to_number_ref(std::string_view str, T& val, int base,
        std::enable_if_t<details::is_for_strtoul<T>::value, void>*) {

    char* eptr;
    char buffer[std::numeric_limits<T>::digits10 + 2];

    // Original strto(u)l swallows spaces at the beginning - let's preserve this behavior
    // assuming that we need to prepare local buffer and it has no undetermined size for
    // these spaces
    str = trim(str);

    if (! str.empty() && *str.begin() == '-')
        return num_conv_result::garbage;

    if (str.size() >= sizeof(buffer))
        return num_conv_result::overflow;

    str.copy(buffer, str.size());
    buffer[str.size()] = '\0';
    unsigned long l_val = ::strtoul(buffer, &eptr, base);
    if (val == ULONG_MAX)
        return num_conv_result::overflow;
    if (eptr != buffer + str.size())
        return num_conv_result::garbage;

    if constexpr (std::is_same_v<T, unsigned long>) {
        val = l_val;
        return num_conv_result::ok;
    } else {
        if (l_val > static_cast<unsigned long>(std::numeric_limits<T>::max()))
            return num_conv_result::overflow;
        val = static_cast<T>(l_val);
        return num_conv_result::ok;
    }
}

template num_conv_result to_number_ref<char>(std::string_view, char&, int, void*);
template num_conv_result to_number_ref<signed char>(std::string_view, signed char&, int, void*);
template num_conv_result to_number_ref<unsigned char>(std::string_view, unsigned char&, int, void*);
template num_conv_result to_number_ref<signed short>(std::string_view, signed short&, int, void*);
template num_conv_result to_number_ref<unsigned short>(std::string_view, unsigned short&, int, void*);
template num_conv_result to_number_ref<signed int>(std::string_view, signed int&, int, void*);
template num_conv_result to_number_ref<unsigned int>(std::string_view, unsigned int&, int, void*);
template num_conv_result to_number_ref<signed long>(std::string_view, signed long&, int, void*);
template num_conv_result to_number_ref<unsigned long>(std::string_view, unsigned long&, int, void*);

template <class T>
void to_string_sign(T &n, char* &where, std::true_type) {
    if (n < 0) {
        *where++ = '-';
        n = -n;
    }
}

template <class T>
void to_string_sign(T &n, char* &where, std::false_type) {}

template <class T>
char* to_string(T n, char* where) {
    to_string_sign(n, where, std::is_signed<T>{});

    char* p = where;

    do {
        *p++ = '0' + (n % 10);
        n /= 10;
    } while (n);

    *p = '\0';
    for (char *pp = p - 1; pp > where; --pp, ++where) {
        char z = *pp;
        *pp = *where;
        *where = z;
    }
    return p;
}

template char* to_string<char>(char, char*);
template char* to_string<signed char>(signed char, char*);
template char* to_string<unsigned char>(unsigned char, char*);
template char* to_string<short>(short, char*);
template char* to_string<unsigned short>(unsigned short, char*);
template char* to_string<int>(int, char*);
template char* to_string<unsigned int>(unsigned int, char*);
template char* to_string<long>(long, char*);
template char* to_string<unsigned long>(unsigned long, char*);

auto polling_timer_executor::execute(std::function<time_point_t()> now_provider) -> time_point_t {
    std::size_t pos = 0;
    std::exception_ptr err;

    while (! err) {
        auto now_tp = now_provider();
        bool move_it = false;
        cb_t cb;

        {
            std::unique_lock l{m_items_mutex};

            if (pos > 0) {
                auto& prev_task = m_items[pos - 1];
                if (prev_task.m_duration.count() == 0) {
                    prev_task.m_executing = false;
                    prev_task.m_executed = true;
                } else {
                    auto new_tp_for_repeat = now_tp + prev_task.m_duration;
                    auto it = lower_bound(
                        m_items.begin() + pos, m_items.end(), new_tp_for_repeat,
                        [](auto& v, auto ref_val){ return v.m_when < ref_val; });
                    if (it == m_items.begin() + pos) {
                        --pos;
                        prev_task.m_when = new_tp_for_repeat;
                        prev_task.m_executing = false;
                    } else {
                        it = m_items.insert(it, std::move(prev_task));
                        it->m_when = new_tp_for_repeat;
                        it->m_executing = false;
                    }
                }
            }
            if (pos < m_items.size() && m_items[pos].m_when <= now_tp) {
                m_items[pos].m_executing = true;
                if (m_items[pos].m_duration.count() == 0) {
                    cb = std::move(m_items[pos].m_cb);
                    move_it = true;
                } else
                    cb = m_items[pos].m_cb;
            }
            else
                break;
        }

        try {
            if (move_it)
                std::move(cb)();
            else
                cb();
        } catch (...) {
            err = std::current_exception();
        }

        ++pos;
    }

    std::unique_lock l{m_items_mutex};
    m_items.erase(m_items.begin(), m_items.begin() + pos);

    if (m_current_task_cancelling) {
        m_current_task_cancelling = false;
        m_executing_cv.notify_all();
    }

    if (err)
        std::rethrow_exception(err);

    return m_items.empty() ? time_point_t::max() : m_items.begin()->m_when;
}

int polling_timer_executor::post_single_shot_task(cb_t cb, time_point_t when) {
    int res_id;
    bool at_start;

    {
        std::unique_lock l{m_items_mutex};

        auto it = lower_bound(
            find_if(m_items.begin(), m_items.end(),
                [](auto& v){ return ! v.m_executing && ! v.m_executed; }),
            m_items.end(),
            when,
            [](auto& v, auto ref_val){ return v.m_when < ref_val; });

        at_start = it == m_items.begin();
        m_items.insert(it, work_item{m_id_gen++, when, {}, std::move(cb)});
        res_id = m_id_gen - 1;
    }

    if (at_start)
        m_replan_cb();

    return res_id;
}

int polling_timer_executor::post_repeat_task(cb_t cb, time_point_t::duration pause) {
    int res_id;
    bool at_start;

    {
        std::unique_lock l{m_items_mutex};

        auto it = find_if(m_items.begin(), m_items.end(),
            [](auto& v){ return ! v.m_executing && ! v.m_executed; });

        at_start = it == m_items.begin();
        m_items.insert(it, work_item{m_id_gen++, {}, pause, std::move(cb)});
        res_id = m_id_gen - 1;
    }

    if (at_start)
        m_replan_cb();

    return res_id;
}

void polling_timer_executor::cancel_task(int id) {
    std::unique_lock l{m_items_mutex};

    auto it = find_if(m_items.begin(), m_items.end(),
        [id](auto& v){ return v.m_id == id; });

    if (it == m_items.end() || it->m_executed)
        return;

    it->m_duration = {};

    if (it->m_executing) {
        m_current_task_cancelling = true;
        m_executing_cv.wait(l, [this](){ return m_current_task_cancelling == false; });
        return;
    }

    m_items.erase(it);
}

void polling_timer_executor::cancel_all() {
    std::unique_lock l{m_items_mutex};
    bool executing = false;

    // Scan all from the beginning and find first task which is has not been executed already and
    // which is not executing currently.
    m_items.erase(
        find_if(m_items.begin(), m_items.end(),
            [&executing](auto& v){
                if (v.m_executing) {
                    executing = true;
                    v.m_duration = {};
                }
                return ! v.m_executing && ! v.m_executed;
            }),
        m_items.end());

    if (executing) {
        m_current_task_cancelling = true;
        m_executing_cv.wait(l, [this](){ return m_current_task_cancelling == false; });
    }
}

/*
bool polling_timer_executor::empty() {
    std::unique_lock l{m_items_mutex};
    return find_if(m_items.begin(), m_items.end(), [](auto& v){ return ! v.m_executed; })
        != m_items.end();
};
*/

thread_timer_executor::thread_timer_executor()
    : m_timer([this](){ m_cv.notify_all(); }) {
}

void thread_timer_executor::thread_proc() {
    while (! m_stopping) {
        time_point_t next_tp{};
        try {
            next_tp = m_timer.execute([](){ return std::chrono::steady_clock::now(); });
        } catch (const std::exception& e) {
            TRACE_ERROR() << "failure while executing a task in a threaded timer: "
                << utils::dump_exc_with_nested(e);
        }

        if (next_tp.time_since_epoch().count()) {
            std::unique_lock l{m_m};
            m_cv.wait_until(l, next_tp);
        }
    }
}

void thread_timer_executor::stop() {
    if (m_thread.joinable()) {
        m_stopping = true;
        m_timer.cancel_all();
        m_cv.notify_all();

        m_thread.join();
        m_stopping = false;
    }
}

} // ns fan_interceptor::utils
