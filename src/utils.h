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

#pragma once

// The module contains auxiliary tools needed for the whole library implementation. It's not assumed
// to be exported somehow to the library's clients.

#include <new>
#include <utility>
#include <stdexcept>
#include <string_view>
#include <string>
#include <vector>
#include <deque>
#include <atomic>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <ostream>
#include <iomanip>
#include <ctime>
#include <functional>
#include <thread>

#include <type_traits>
#include <iterator>

namespace fan_interceptor::utils {

// Opens a file by provided path and reads all its content
std::vector<char> read_whole_file(const char* path, int atdir_fd = -1);

class string_splitter {
public:
    class iterator {
    public:
        typedef std::string_view value_type;
        typedef const std::string_view& reference;
        typedef const std::string_view* pointer;
        typedef std::intptr_t difference_type;
        typedef std::forward_iterator_tag iterator_category;

        iterator(std::string_view input, std::string_view delims) noexcept
            : m_input(input), m_delims(delims) {
            advance(/*reset*/ true);
        }

        iterator() = default;

        reference operator*() const noexcept {
            return m_part;
        }

        pointer operator->() const noexcept {
            return &m_part;
        }

        bool operator==(const iterator& r) const noexcept {
            return m_pos == r.m_pos;
        }

        bool operator!=(const iterator& r) const noexcept {
            return m_pos != r.m_pos;
        }

        iterator& operator++() noexcept {
            advance();
            return *this;
        }

        iterator operator++(int) noexcept {
            auto t = *this;
            advance();
            return t;
        }

    private:
        std::string_view m_input;
        std::string_view m_delims;
        std::string_view m_part;
        std::string_view::size_type m_pos = std::string_view::npos;

        void advance(bool reset = false) noexcept {
            auto b = reset ? 0 : m_pos + m_part.size();

            m_pos = m_input.find_first_not_of(m_delims, b);
            if (m_pos != std::string_view::npos) {
                auto e = m_input.find_first_of(m_delims, m_pos);
                if (e != std::string_view::npos)
                    m_part = std::string_view{m_input.data() + m_pos, e - m_pos};
                else
                    m_part = std::string_view{m_input.data() + m_pos, m_input.size() - m_pos};
            }
        }
    };

    string_splitter(std::string_view input, std::string_view delims) noexcept
        : m_input(input), m_delims(delims) {
    }

    iterator begin() const noexcept { return {m_input, m_delims}; }
    iterator end() const noexcept { return {}; }

    bool empty() const noexcept { return iterator{m_input, m_delims} == iterator{}; }

private:
    std::string_view m_input;
    std::string_view m_delims;
};

namespace details {

template <class ... T> struct is_one_of;

template <class T1, class T2>
struct is_one_of<T1, T2> : std::is_same<T1, T2> {};

template <class T1, class T2, class T3, class ... T>
struct is_one_of<T1, T2, T3, T...>
    : std::bool_constant<is_one_of<T1, T2>::value || is_one_of<T1, T3, T...>::value> {};

template <class T>
struct is_for_strtol
    : std::bool_constant<
        is_one_of<T, signed char, signed short, signed int, signed long>::value
            || (std::is_signed_v<char> && std::is_same_v<T, char>)> {};

template <class T>
struct is_for_strtoul
    : std::bool_constant<
        is_one_of<T, unsigned char, unsigned short, unsigned int, unsigned long>::value
            || (! std::is_signed_v<char> && std::is_same_v<T, char>)> {};

} // ns details

// Trivial vector implementation with pre-allocated storage inside the object itself
// (some kind of SSO - small string optimization). Only a subset of standard operations
// implemented - those which are needed for this library.
template <class T, std::size_t FixedSize>
class small_vector {
    struct storage {
        alignas(alignof(T)) char m_data[sizeof(T)];
    };

public:
    typedef T value_type;
    typedef unsigned short size_type;
    typedef T& reference;
    typedef const T& const_reference;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef pointer iterator;
    typedef const_pointer const_iterator;

    static constexpr size_type fixed_size = FixedSize;

    small_vector() = default;

    ~small_vector() {
        clear();
    }

    void clear() {
        storage* s = m_is_internal ? m_data.m_int : m_data.m_ext.m_ptr;
        for (size_type i = 0; i < m_len; ++i)
            std::launder(reinterpret_cast<T*>(s[i].m_data))->T::~T();
        if (! m_is_internal)
            delete[] s;
        m_is_internal = true;
        m_len = 0;
    }

    small_vector(const small_vector& r) {
        if (r.size() <= fixed_size) {
            for (size_type i = 0; i < r.size(); ++i)
                new(m_data.m_int[i].m_data) T(r[i]);
        } else {
            m_is_internal = false;
            m_data.m_ext.m_capacity = r.size();
            m_data.m_ext.m_ptr = new storage[r.size()];
            try {
                for (size_type i = 0; i < r.size(); ++i)
                    new(m_data.m_ext.m_ptr[i].m_data) T(r[i]);
            } catch (...) {
                delete[] m_data.m_ext.m_ptr;
                throw;
            }
        }
        m_len = r.size();
    }

    small_vector(small_vector&& r) noexcept(noexcept(T(std::declval<T>()))) {
        if (r.size() <= fixed_size) {
            for (size_type i = 0; i < r.size(); ++i) {
                new(m_data.m_int[i].m_data) T(std::move(r[i]));
            }
            m_len = r.size();
            r.clear();
        } else {
            m_is_internal = false;
            m_len = r.size();
            r.m_is_internal = true;
            r.m_len = 0;
            m_data.m_ext.m_capacity = r.m_data.m_ext.m_capacity;
            m_data.m_ext.m_ptr = r.m_data.m_ext.m_ptr;
        }
    }

    small_vector& operator=(const small_vector&) = delete;
    small_vector& operator=(small_vector&&) = delete;

    void push_back(const T& v) {
        ensure_more_space();
        storage* s = m_is_internal ? m_data.m_int : m_data.m_ext.m_ptr;
        new (s[m_len]->m_data) T(v);
        ++m_len;
    }

    void push_back(T&& v) {
        ensure_more_space();
        storage* s = m_is_internal ? m_data.m_int : m_data.m_ext.m_ptr;
        new (s[m_len].m_data) T(std::move(v));
        ++m_len;
    }

    iterator insert(const_iterator pos, const T& value) {
        size_type ins_off = pos - data();
        ensure_more_space();
        storage* s = m_is_internal ? m_data.m_int : m_data.m_ext.m_ptr;
        for (size_type dst_off = m_len, src_off = m_len - 1; ins_off < dst_off; --dst_off, --src_off) {
            T* from = std::launder(reinterpret_cast<T*>(s[src_off].m_data));
            new (s[dst_off].m_data) T(std::move(*from));
            from->T::~T();
        }
        ++m_len;
        return new (s[ins_off].m_data) T(value);
    }

    iterator insert(const_iterator pos, T&& value) {
        size_type ins_off = pos - data();
        ensure_more_space();
        storage* s = m_is_internal ? m_data.m_int : m_data.m_ext.m_ptr;
        for (size_type dst_off = m_len, src_off = m_len - 1; ins_off < dst_off; --dst_off, --src_off) {
            T* from = std::launder(reinterpret_cast<T*>(s[src_off].m_data));
            new (s[dst_off].m_data) T(std::move(*from));
            from->T::~T();
        }
        ++m_len;
        return new (s[ins_off].m_data) T(std::move(value));
    }

    void pop_back() {
        storage* s = m_is_internal ? m_data.m_int : m_data.m_ext.m_ptr;
        std::launder(reinterpret_cast<T*>(s[m_len - 1].m_data))->T::~T();
        --m_len;
    }

    const_pointer data() const noexcept {
        return m_is_internal
            ? std::launder(reinterpret_cast<const T*>(m_data.m_int[0].m_data))
            : std::launder(reinterpret_cast<const T*>(m_data.m_ext.m_ptr[0].m_data));
    }

    pointer data() noexcept {
        return const_cast<pointer>(static_cast<const small_vector*>(this)->data());
    }

    const_reference front() const noexcept { return *data(); }
    reference front() noexcept { return *data(); }
    const_reference back() const noexcept { return *(data() + m_len - 1); }
    reference back() noexcept { return *(data() + m_len - 1); }
    const_reference operator[](size_type i) const noexcept { return *(data() + i); }
    reference operator[](size_type i) noexcept { return *(data() + i); }

    iterator begin() noexcept { return data(); }
    const_iterator begin() const noexcept { return data(); }
    iterator end() noexcept { return data() + m_len; }
    const_iterator end() const noexcept { return data() + m_len; }

    size_type size() const noexcept { return m_len; }
    size_type capacity() const noexcept {
        return m_is_internal ? fixed_size : m_data.m_ext.m_capacity; }
    bool empty() const noexcept { return m_len == 0; }

private:
    union {
        storage m_int[fixed_size];
        struct {
            storage* m_ptr;
            size_type m_capacity;
        } m_ext;
    } m_data;
    size_type m_len = 0;
    bool m_is_internal = true;

    void ensure_more_space() {
        if (m_len == (size_type)~0)
            throw std::bad_alloc();
        if (m_len + 1 > fixed_size && m_is_internal)
            switch_to_external();
        if (! m_is_internal && m_len + 1 > m_data.m_ext.m_capacity) {
            if (m_data.m_ext.m_capacity & ((size_type)~0 / 2 + 1))
                m_data.m_ext.m_capacity = (size_type)~0;
            else
                m_data.m_ext.m_capacity <<= 1;
            storage* s = new storage[m_data.m_ext.m_capacity];
            for (size_type i = 0; i < m_len; ++i) {
                T* from = std::launder(reinterpret_cast<T*>(m_data.m_ext.m_ptr[i].m_data));
                new (s[i].m_data) T(std::move(*from));
                from->T::~T();
            }
            delete[] m_data.m_ext.m_ptr;
            m_data.m_ext.m_ptr = s;
        }
    }

    void switch_to_external() {
        auto new_size = m_len;
        if ((new_size > (size_type)~0 / 2 && new_size != (size_type)~0) || new_size == 0)
            ++new_size;
        else
            for (size_type i = (size_type)~0 / 2 + 1; i != 1; i >>= 1)
                if (new_size & (i >> 1)) {
                    new_size = i;
                    break;
                }

        storage* s = new storage[new_size];
        for (size_type i = 0; i < m_len; ++i) {
            T* from = std::launder(reinterpret_cast<T*>(m_data.m_int[i].m_data));
            new (s[i].m_data) T(std::move(*from));
            from->T::~T();
        }
        m_data.m_ext.m_ptr = s;
        m_data.m_ext.m_capacity = new_size;
        m_is_internal = false;
    }

    void switch_to_internal() {
        storage* s = m_data.m_ext.m_ptr;
        for (size_type i = 0; i < m_len; ++i) {
            T* from = std::launder(reinterpret_cast<T*>(s[i]->m_data));
            new (m_data.m_int[i].m_data) T(std::move(*from));
            from->T::~T();
        }
        delete[] s;
        m_is_internal = true;
    }
};

enum class num_conv_result : char {
    ok, overflow, garbage
};

std::string_view trim_left(std::string_view str);
std::string_view trim_right(std::string_view str);
inline std::string_view trim(std::string_view str) {
    return trim_left(trim_right(str));
}

inline bool starts_with(std::string_view s, std::string_view part) {
    return s.size() >= part.size() && s.substr(0, part.size()) == part;
}

template <class T>
num_conv_result to_number_ref(std::string_view str, T& val, int base = 10,
    std::enable_if_t<details::is_for_strtol<T>::value, void>* = nullptr);

template <class T>
num_conv_result to_number_ref(std::string_view str, T& val, int base = 10,
    std::enable_if_t<details::is_for_strtoul<T>::value, void>* = nullptr);

template <class T>
T to_number(std::string_view str, int base = 10) {
    T val;
    switch (to_number_ref(str, val, base)) {
    case num_conv_result::ok:
        break;
    case num_conv_result::overflow:
        throw std::range_error("unable to convert \"" + std::string{str} + "\" to a number - overflow");
    case num_conv_result::garbage:
        throw std::range_error("unable to convert \"" + std::string{str} + "\" to a number - "
            "some unconvertable characters here");
    };
    return val;
}

template <class T>
char* to_string(T n, char* where);

template <class I>
I advance_checked(I i, I e, typename std::iterator_traits<I>::difference_type d) {
    do {
        if (i == e)
            throw std::out_of_range("iterator went out of range on advancing");
        if (d == 0)
            return i;
        ++i; --d;
    } while (true);
}

template <class I>
I step_behind(I i, I e, typename std::iterator_traits<I>::value_type v) {
    while (i != e && *i != v)
        ++i;
    if (i != e)
        ++i;
    if (i != e)
        return i;
    throw std::out_of_range("iterator went out of range on stepping begind");
}

struct empty_logger {
    struct step_out {
        template <class T>
        step_out&& operator<<(T&&) && {
            return std::move(*this);
        }
        step_out&& operator<<(std::ostream& (*func)(std::ostream&)) && {
            return std::move(*this);
        }
    };

    step_out operator()() { return {}; }
};

// Allows to output any data into specified ostream under lock
class sync_logger {
    // While there is a live object of this type, no other thread can
    // output anything using the sync_logger object
    struct step_out {
        std::unique_lock<std::mutex> m_l;
        std::ostream& m_os;
        bool m_add_endl;

        template <class T>
        step_out&& operator<<(T&& obj) && {
            m_os << std::forward<T>(obj);
            return std::move(*this);
        }
        step_out&& operator<<(std::ostream& (*func)(std::ostream&)) && {
            m_os << func;
            return std::move(*this);
        }
        ~step_out() {
            if (m_add_endl)
                m_os << std::endl;
        }
    };

public:
    sync_logger(std::ostream& os) : m_os(os) {
        std::ios_base::sync_with_stdio(false);
        os.tie(nullptr);
    }

    // Prefixes an output with steady clock's seconds and milliseconds
    step_out operator()(bool add_endl = true);

private:
    std::mutex m_mutex;
    std::ostream& m_os;
};

extern sync_logger g_sync_logger;

#define TRACE_INFO() ::fan_interceptor::utils::g_sync_logger()
#define TRACE_ERROR() ::fan_interceptor::utils::g_sync_logger()
#define TRACE_OFF() ::fan_interceptor::utils::g_empty_logger()

template <class T>
struct dump_exc_with_nested {
    const T& m_obj;

    explicit dump_exc_with_nested(const T& obj)
        : m_obj(obj) {
    }

    template <class S> void dump(S& os) {
        os << m_obj.what();
    }

    void rethrow() {
        std::rethrow_if_nested(m_obj);
    }
};

template <>
struct dump_exc_with_nested<std::exception_ptr> {
    std::exception_ptr m_ptr;

    explicit dump_exc_with_nested<std::exception_ptr>(std::exception_ptr p)
        : m_ptr(std::move(p)) {
    }

    void dump() {}

    void rethrow() {
        std::rethrow_exception(m_ptr);
    }
};

template <class S, class T>
S& operator<<(S& os, dump_exc_with_nested<T> d) {
    d.dump(os);
    try {
        d.rethrow();
    } catch (const std::exception& nested) {
        os << "; " << dump_exc_with_nested{nested};
    } catch (...) {
        os << "[unknown exception type]";
    }
    return os;
}

/*
 * TODO: Spinlock or mutex? Torvalds says it's crap.
 *   https://www.realworldtech.com/forum/?threadid=189711&curpostid=189723
 *
 * A gay from habr.com says it could have more drawbacks than I can see:
 *   https://habr.com/ru/articles/689310/
 */
class spin_lock final {
public:
    spin_lock() noexcept {
        atomic_init(&m_flag, false);
    }

    void lock() noexcept {
        while (true) {
            if (! m_flag.exchange(true, std::memory_order_acquire))
                break;

            while (m_flag.load(std::memory_order_relaxed))
                __builtin_ia32_pause();
        }
    }

    bool try_lock() noexcept {
        return ! m_flag.exchange(true, std::memory_order_acquire);
    }

    void unlock() noexcept {
        m_flag.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool> m_flag;
};

struct trivial_timer {
    virtual ~trivial_timer() = default;

    typedef std::chrono::steady_clock::time_point time_point_t;
    typedef std::function<void()> cb_t;

    virtual int post_single_shot_task(cb_t cb, time_point_t when) = 0;
    virtual int post_repeat_task(cb_t cb, time_point_t::duration pause) = 0;
    virtual void cancel_task(int id) = 0;
    virtual void cancel_all() = 0;
//    virtual void empty() = 0;
};

// Assumes small amount of work items (vector is used for internal storage)
class polling_timer_executor : public trivial_timer {
public:
    explicit polling_timer_executor(cb_t replan_cb)
        : m_replan_cb(std::move(replan_cb)) {
    }

    int post_single_shot_task(cb_t cb, time_point_t when) override;
    int post_repeat_task(cb_t cb, time_point_t::duration pause) override;
    void cancel_task(int id) override;
    void cancel_all() override;
//    bool empty() override;

    // Returns a time point when this method should be executed next time
    std::chrono::steady_clock::time_point execute(std::function<time_point_t()> now_provider);

private:
    struct work_item {
        int m_id;
        time_point_t m_when;
        time_point_t::duration m_duration;
        cb_t m_cb;
        bool m_executing = false;
        bool m_executed = false;
    };

    const cb_t m_replan_cb;

    std::mutex m_items_mutex;
    std::condition_variable m_executing_cv;
    std::deque<work_item> m_items;
    int m_id_gen = 1;
    bool m_current_task_cancelling = false;
};

class thread_timer_executor : public trivial_timer {
public:
    thread_timer_executor();
    ~thread_timer_executor() { stop(); }

    int post_single_shot_task(cb_t cb, time_point_t when) override {
        return m_timer.post_single_shot_task(std::move(cb), when);
    }

    int post_repeat_task(cb_t cb, time_point_t::duration pause) override {
        return m_timer.post_repeat_task(std::move(cb), pause);
    }

    void cancel_task(int id) override {
        m_timer.cancel_task(id);
    }

    void cancel_all() override {
        m_timer.cancel_all();
    }

    void start() { m_thread = std::thread{[this](){ thread_proc(); }}; }
    void stop();

private:
    polling_timer_executor m_timer;
    std::thread m_thread;

    std::mutex m_m;
    std::condition_variable m_cv;
    bool m_stopping = false;

    void thread_proc();
};

} // ns fan_interceptor::utils
