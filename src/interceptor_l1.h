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

#include "utils.h"
#include "interceptor_types.h"

#include <cstdint>
#include <utility>
#include <atomic>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <chrono>
#include <functional>
#include <optional>
#include <string_view>
#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <deque>

#include <sys/types.h>

namespace fan_interceptor {

// This is a specific poller for fanotify task. Its difference from typical reactors
// like one in boost::asio is next:
//
//  1. the same callback can be called asynchronously from a few threads if a few
//     operations happened on fd.
//
//  2. waiting on the same fd with epoll_wait happens in every thread calling poll method.
//
//  3. from (1) and (2) follows that different read operations can be reordered - there is
//     no one sequence of readings. It should be good enough for fanotify where every read
//     delivers one fanotify event and different events can be handled out of order
//     (especially important for FUSE case when a fanotifier monitors both mount point with
//     user filesystem and underlying filesystem which FUSE controller uses). And the
//     absence of the sequence of readings makes it impossible to read long packets by
//     fragments as it usually happens with tcp sockets.
//
//  4. there is no aim to install different callbacks for different types of events - only
//     reading is supported.
//
// There is no any guarantee in official Linux documentation that epoll_wait can't return
// an event for recently removed fd via epoll_ctl. For example, the thread executing
// epoll_wait 'almost returned' from the epoll_wait when another thread called epoll_ctl
// and removed the fd. When it's safe to believe that removed event can't be observed
// in another thread? Need to introduce floating timeouts based on thread starvation
// timings. Let's say all other threads can process possibly happened event inside their
// epoll_wait call during 10 seconds. Don't like this logic because it will be broken by
// a box sleeping / hibernation.
//
// Interruption is another tricky case on this reactor. boost::asio executes epoll_wait
// in one thread only but this poller is designed so that all the threads called poll
// method can run a callback eventually, so a few threads execute epoll_wait. Edge-triggered
// fd can't be used to interruption because only one arbitrary thread will wake up.
// Level triggered fd will infinitely trigger poll_wait in all threads so one thread can't
// continue to normally operate while another still handling interruption sequence. The
// interrupter is suitable for stop sequence only.
class poller {
public:
    typedef std::function<void(void*)> cb_t;

private:
    struct subscription final {
        cb_t m_cb;
        int m_fd;
        short m_usages = 0;
        bool m_unregistered = false;
        bool m_unregister_from_cb = false;

        std::chrono::time_point<std::chrono::steady_clock> m_when_deleted;

        std::mutex m_mutex;
        std::condition_variable m_cv;

        subscription(cb_t cb, int fd)
            : m_cb(std::move(cb)), m_fd(fd)
        {}

        void reinit(cb_t cb, int fd) {
            m_cb = std::move(cb);
            m_fd = fd;
            m_unregistered = false;
        }
    };

    typedef std::list<subscription> subscription_list_t;

public:
    typedef subscription_list_t::iterator cb_id_t;

    explicit poller();

    poller(const poller&) = delete;
    poller& operator=(const poller&) = delete;

    // Register a callback for specified fd and epoll flags - it will be called
    // every time the fd is in signalled state.
    cb_id_t register_cb(cb_t cb, int fd, std::uint32_t events);

    // Unregister previously registered poller callback. The method guarantees that
    // no other threads driving a poll method are executing this callback currently.
    // The only exception could be a thread executing a poll method which eventually
    // called this method - no wait (else it would be deadlock), just return.
    void unregister_cb(cb_id_t);

    // Can be called from any number of threads - all of them assumed to process
    // I/O separately. Returns false if the poller is disabled currenly. Re-throws any
    // exception got from any callback.
    bool poll(void* ctx);

    void enable(bool enab = true);

private:
    fd_holder m_poll_fd;
    fd_holder m_enable_pipe_read_fd, m_enable_pipe_write_fd;

    std::atomic<bool> m_enabled{true};
    std::atomic<int> m_waiting_threads_count{0};
    std::mutex m_subscription_mutex;
    std::mutex m_one_thread_polling_mutex;
    subscription_list_t m_subscriptions;
    subscription_list_t m_deleted_subscriptions;

    static thread_local int s_executing_on_thread;
};

class deferred_dispatcher {
public:
    typedef std::function<void(void*)> cb_t;

private:
    struct state {
        std::atomic<int> m_refcnt;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_executing = false;
        bool m_cancelled_from_cb = false;
        cb_t m_cb;
    };

    class state_ptr {
        state* m_state;

        explicit state_ptr(state* s) noexcept : m_state(s) {
            atomic_init(&m_state->m_refcnt, 1);
        }

        state* operator->() const noexcept {
            return m_state;
        }

    public:
        state_ptr() : m_state{} {}

        bool empty() const noexcept { return ! m_state; }

        state_ptr(const state_ptr& r) noexcept : m_state(r.m_state) {
            if (m_state)
                m_state->m_refcnt.fetch_add(1, std::memory_order_relaxed);
        }

        state_ptr(state_ptr&& r) noexcept : m_state(r.m_state) {
            r.m_state = nullptr;
        }

        void swap(state_ptr& r) noexcept {
            using std::swap;
            swap(m_state, r.m_state);
        }

        state_ptr& operator=(const state_ptr& r) noexcept {
            auto t = r;
            swap(t);
            return *this;
        }

        state_ptr& operator=(state_ptr&& r) noexcept {
            auto t{std::move(r)};
            swap(t);
            return *this;
        }

        ~state_ptr() {
            if (m_state && m_state->m_refcnt.fetch_sub(1, std::memory_order_acq_rel) == 1)
                delete m_state;
        }

        friend deferred_dispatcher;
    };

public:
    typedef state_ptr cb_id_t;

    // Defer execution of a callable until next call a dispatch method from any thread
    cb_id_t defer(cb_t cb);

    // Cancel execution of previously added callable by specified id. Does nothing if the
    // callable was executed already. Waits for it completion in case if it executes
    // currently (except the case if this method is called in context of any thread
    // calling a dispatch method).
    void cancel(cb_id_t);

    bool has_gone(cb_id_t) const;

    void dispatch(void* ctx);

private:
    std::mutex m_task_list_mutex;
    std::deque<state_ptr> m_tasks;

    static thread_local int s_executing_on_thread;
};

class reactor : poller, deferred_dispatcher {
public:
    typedef poller::cb_t poller_cb_t;
    typedef poller::cb_id_t poller_cb_id_t;

    using poller::register_cb;
    using poller::unregister_cb;
    using poller::poll;
    using poller::enable;

    typedef deferred_dispatcher::cb_t defer_cb_t;
    typedef deferred_dispatcher::cb_id_t defer_cb_id_t;

    reactor();

    defer_cb_id_t defer(defer_cb_t);
    void cancel_deferred(defer_cb_id_t id) { deferred_dispatcher::cancel(id); }
    bool deferred_has_gone(defer_cb_id_t id) const { return deferred_dispatcher::has_gone(id); }

private:
    fd_holder m_defer_pipe_read_fd;
    fd_holder m_defer_pipe_write_fd;
};

class interceptor_l1_impl final : mnt_namespace_detector::subscription, public interceptor_l1 {
public:
    explicit interceptor_l1_impl(
        const l1_params& params,
        mnt_namespace_detector_ptr ns_detector = {});
    ~interceptor_l1_impl();

    void set_client(l1_client* c) override { m_next_layer = c; }

    // Starts a thread poll for driving an internal reactor, registers known mount namespaces
    // to be monitored.
    void start() override;

    // Disables an internal reactor, stops (joins) all threads from a thread pool.
    void stop() override;

    void request_update_masks_async(::ino_t mnt_ns_id, void* ctx) override;
    void request_update_masks(std::optional<::ino_t> mnt_ns_id, void* ctx) override;

    // TODO: optimize to not look up namespace data if on_fs_event handler calls this method
    // in its call stack
    void post_verdict(::ino_t mnt_ns_id, int fd, verdict vrd) override;

private:
    struct mount_data {
        ::dev_t m_dev_id;
        int m_mount_id;
        std::string m_mountpoint_path;
        std::uint32_t m_tracking_mask = 0;
        std::uint32_t m_new_tracking_mask = 0;
    };

    struct mnt_namespace {
        ::ino_t m_mnt_ns_id;

        fd_holder m_fan_fd;
        fd_holder m_root_fd;
        fd_holder m_base_proc_dir_fd;
        fd_holder m_mounts_fd;      // needed only for tracking changes in a kernel mount table

        reactor::poller_cb_id_t m_fan_cb_id;
        reactor::poller_cb_id_t m_mounts_cb_id;
        reactor::defer_cb_id_t m_onetime_read_cb_id;
        std::vector<reactor::defer_cb_id_t> m_ask_client_cb_ids;

        std::mutex m_mount_list_mutex;
        std::unordered_map<int, mount_data> m_mount_list;
    };

    const l1_params m_params;
    l1_client* m_next_layer = nullptr;
    mnt_namespace_detector_ptr m_ns_detector;
    reactor m_reactor;
    std::vector<std::thread> m_read_threads;

    std::shared_mutex m_namespace_list_mutex;
    std::mutex m_pending_deleted_namespace_list_mutex;
    std::condition_variable_any m_namespace_list_cv;

    // There should be the only value for each namespace id evidently. The only reason to have
    // multimap instead of map here is to store a few structures in {pending deleted} map - very
    // rare case when the same namespace is added and removed a few times.
    std::unordered_multimap<::ino_t, mnt_namespace> m_namespaces;
    std::unordered_multimap<::ino_t, mnt_namespace> m_pending_deleted_namespaces;

    std::atomic<std::uint64_t> m_event_id_gen;
    bool m_started = false;

    // Returns false if a namespace with specified id has been registered already. All other
    // errors reported as exceptions. Namespace's mount points will be processed, adopted and
    // reported asynchronously in an arbitrary thread context.
    bool add_mnt_ns_monitor(::ino_t mnt_ns_id, fd_holder root_fd, fd_holder base_proc_dir_fd);

    // Returns false if a namespace with specified id hasn't been registered. All other errors
    // reported as exceptions. Namespace's mount points will be unregistered, detached from
    // fanotify and reported to a client asynchronously in an arbitrary thread context.
    bool remove_mnt_ns_monitor(::ino_t mnt_ns_id);

    void namespace_found(::ino_t mnt_ns_id, fd_holder root_fd, fd_holder base_proc_dir_fd) override;
    void namespace_have_gone(::ino_t mnt_ns_id) override;

    void update_mountinfo(mnt_namespace& ns_data, bool remove_all = false);
    void flush_masks(mnt_namespace& ns_data, std::unordered_map<int, mount_data>& new_list);

    void read_fanotify(void* ctx, const mnt_namespace& ns_data);
};

} // ns fan_interceptor
