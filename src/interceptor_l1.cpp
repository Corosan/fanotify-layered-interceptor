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

#include "interceptor_l1.h"

#include <cassert>
#include <cstring>
#include <cerrno>
#include <system_error>
#include <algorithm>
#include <iterator>
#include <bitset>

#include <unistd.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <sched.h>

#define TRACE_L1_INFO() TRACE_INFO() << "interceptor_l1(" << (void*)this << ") "
#define TRACE_L1_ERROR() TRACE_INFO() << "interceptor_l1(" << (void*)this << ") "

namespace fan_interceptor {

thread_local int poller::s_executing_on_thread = 0;

poller::poller() {
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    if (fd < 0)
        throw std::system_error(errno, std::generic_category(),
            "unable to create new fanotify poller based on {epoll}");

    m_poll_fd.reset(fd);

    int fds[2];
    if (::pipe2(fds, O_CLOEXEC) < 0)
        throw std::system_error(errno, std::generic_category(),
            "unable to create enabling pipe for new fanotify poller");

    m_enable_pipe_read_fd.reset(fds[0]);
    m_enable_pipe_write_fd.reset(fds[1]);

    // As long as we don't know how many threads will call a poll method in future (and
    // this number can change), the only case to kick out all threads from a waitable state
    // on epoll_wait is to use an armed file descriptor which is added as level-triggered,
    // not edge-triggered. enabling/disabling uses this logic.
    ::epoll_event ev{EPOLLIN};
    if (::epoll_ctl(m_poll_fd.handle(), EPOLL_CTL_ADD, m_enable_pipe_read_fd.handle(), &ev) < 0) {
        auto e = errno;
        throw std::system_error(e, std::generic_category(),
            "unable to add enabling pipe into newly created fanotify poller");
    }
}

auto poller::register_cb(cb_t cb, int fd, std::uint32_t events) -> cb_id_t {
    subscription_list_t tmp;
    subscription_list_t::iterator it;
    ::epoll_event ev{events};

    {
        std::unique_lock l{m_subscription_mutex};

        // We hope that no any thread can freeze so much that it still handles a subscription
        // which was deactivated (removed from epoll) more than 10 seconds before. Such freezing
        // can happen only if some thread (A) detected armed fd, returned from epoll_wait in poll
        // method, then it was scheduled out, then thread (B) removed the subscription, then...
        // 10 seconds elapsed and the thread A returned back.
        if (! m_deleted_subscriptions.empty() &&
            std::chrono::steady_clock::now() - m_deleted_subscriptions.begin()->m_when_deleted
                >= std::chrono::seconds(10)) {
            tmp.splice(tmp.begin(), m_deleted_subscriptions, m_deleted_subscriptions.begin());
            tmp.begin()->reinit(std::move(cb), fd);
        } else {
            l.unlock();
            tmp.emplace_back(std::move(cb), fd);
            l.lock();
        }

        // Address of internally created subscription structure shouldn't change
        // due to this list node migration later.
        ev.data.ptr = std::addressof(*tmp.begin());

        m_subscriptions.splice(m_subscriptions.end(), tmp, tmp.begin());
        it = prev(m_subscriptions.end());
    }

    if (::epoll_ctl(m_poll_fd.handle(), EPOLL_CTL_ADD, fd, &ev) < 0) {
        auto e = errno;
        {
            std::lock_guard l{m_subscription_mutex};
            m_subscriptions.erase(it);
        }
        throw std::system_error(e, std::generic_category(),
            "unable to add polling for fd=" + std::to_string(fd) + " into a fanotify poller");
    }

    return it;
}

void poller::unregister_cb(cb_id_t id) {
    auto& s = *id;

    if (::epoll_ctl(m_poll_fd.handle(), EPOLL_CTL_DEL, s.m_fd, nullptr) < 0) {
        auto e = errno;
        throw std::system_error(e, std::generic_category(),
            "unable to remove polling for fd=" + std::to_string(s.m_fd) + " from a fanotify poller");
    }

    std::unique_lock l{s.m_mutex};
    s.m_unregister_from_cb = s_executing_on_thread > 0;
    s.m_unregistered = true;

    m_deleted_subscriptions.splice(m_deleted_subscriptions.end(), m_subscriptions, id);
    s.m_cv.wait(l, [&s]{ return s.m_usages == (s.m_unregister_from_cb ? 1 : 0); });

    // If this method is called in context of a thread executing poll method,
    // the callback can hold a reference to an object which in turn called this method.
    // Resetting the callback right now can yield to dangling reference - let's poller's
    // cycle will do it for us later.
    if (! s.m_unregister_from_cb)
        s.m_cb = {};

    s.m_when_deleted = std::chrono::steady_clock::now();
}

void poller::enable(bool enab) {
    if (enab && ! m_enabled.exchange(true, std::memory_order_relaxed)) {
        while (true) {
            char buf{};
            if (::read(m_enable_pipe_read_fd.handle(), &buf, 1) < 0) {
                if (errno == EINTR)
                    continue;
                m_enabled.store(false, std::memory_order_relaxed);
                throw std::system_error(errno, std::generic_category(),
                    "unable to enable fanotify poller by reading from the interruption pipe");
            }
            break;
        }
    } else if (! enab && m_enabled.exchange(false, std::memory_order_relaxed)) {
        while (true) {
            char buf{};
            if (::write(m_enable_pipe_write_fd.handle(), &buf, 1) < 0) {
                if (errno == EINTR)
                    continue;
                m_enabled.store(true, std::memory_order_relaxed);
                throw std::system_error(errno, std::generic_category(),
                    "unable to disable fanotify poller by writing to the interruption pipe");
            }
            break;
        }
    }
}

bool poller::poll(void* ctx) {
    const size_t MAX_EPOLL_EVENTS = 32;
    ::epoll_event events[MAX_EPOLL_EVENTS];

    if (! m_enabled.load(std::memory_order_relaxed))
        return false;

    m_waiting_threads_count.fetch_add(1, std::memory_order_relaxed);
    // TODO: check with edge-triggered events and without the next lock
    m_one_thread_polling_mutex.lock();
    int ready_fds;
    do {
        ready_fds = ::epoll_wait(m_poll_fd.handle(), events, MAX_EPOLL_EVENTS, -1);
    } while (ready_fds < 0 && errno == EINTR);
    auto e = errno;
    m_one_thread_polling_mutex.unlock();
    m_waiting_threads_count.fetch_sub(1, std::memory_order_relaxed);

    if (ready_fds < 0)
        throw std::system_error(e, std::generic_category(), "unable to wait on a fanotify poller");

    for (auto ev = events; ready_fds > 0; ++ev, --ready_fds) {
        // enable_pipe has signalled - it means that the poller is in disabled state
        if (ev->data.ptr == nullptr)
            return false;

        auto& s = *static_cast<subscription*>(ev->data.ptr);

        {
            std::lock_guard l{s.m_mutex};
            if (! s.m_unregistered) {
                ++s.m_usages;
            } else
                continue;
        }

        std::exception_ptr exc;

        ++s_executing_on_thread;

        try {
            s.m_cb(ctx);
        } catch (...) {
            exc = std::current_exception();
        }

        --s_executing_on_thread;

        {
            std::lock_guard l{s.m_mutex};
            if (--s.m_usages == (s.m_unregister_from_cb ? 1 : 0)) {
                s.m_cv.notify_all();
            }
            if (s.m_usages == 0 && s.m_unregister_from_cb)
                s.m_cb = {};
        }

        if (exc)
            std::rethrow_exception(exc);
    }

    return true;
}

thread_local int deferred_dispatcher::s_executing_on_thread = 0;

auto deferred_dispatcher::defer(cb_t cb) -> cb_id_t {
    auto st = new state;
    state_ptr sptr{st};
    sptr->m_cb = std::move(cb);

    std::lock_guard l{m_task_list_mutex};
    m_tasks.push_back(sptr);

    return sptr;
}

void deferred_dispatcher::cancel(cb_id_t id) {
    std::unique_lock l{id->m_mutex};

    if (! id->m_executing) {
        id->m_cb = {};
        return;
    }

    id->m_cancelled_from_cb = s_executing_on_thread > 0;

    if (! id->m_cancelled_from_cb) {
        id->m_cv.wait(l, [&id]{ return ! id->m_executing; });
        id->m_cb = {};
    }
}

bool deferred_dispatcher::has_gone(cb_id_t id) const {
    std::lock_guard l{id->m_mutex};
    return ! id->m_cb;
}

void deferred_dispatcher::dispatch(void* ctx) {
    std::unique_lock l{m_task_list_mutex};

    while (! m_tasks.empty()) {
        auto sptr = std::move(m_tasks.front());
        m_tasks.pop_front();
        l.unlock();

        while (true) {
            {
                std::lock_guard l2{sptr->m_mutex};
                if (! sptr->m_cb)
                    break;

                sptr->m_executing = true;
            }

            ++s_executing_on_thread;

            try {
                sptr->m_cb(ctx);
            } catch (...) {
                // TODO: what should I do with a failure in deferred procedure - no
                // client's context here, who ordered it to run. The ordering happened
                // some time ago
            }

            --s_executing_on_thread;

            {
                std::unique_lock l2{sptr->m_mutex};

                sptr->m_executing = false;
                sptr->m_cb = {};
                if (! sptr->m_cancelled_from_cb)
                    sptr->m_cv.notify_all();
            }
            break;
        }

        l.lock();
    }
}

//-----------------------------------------------------------------------------
reactor::reactor() {
    int fds[2];
    if (::pipe2(fds, O_CLOEXEC) < 0)
        throw std::system_error(errno, std::generic_category(),
            "unable to create interrupting pipe for new fanotify reactor");

    m_defer_pipe_read_fd.reset(fds[0]);
    m_defer_pipe_write_fd.reset(fds[1]);

    register_cb([this](void* ctx){
            char buf[128];
            // Read much more than 1 byte becase more than one client could defer his routine
            // and post interruption bytes into the pipe. But only one edge-triggered signal
            // will come
            std::ignore = ::read(m_defer_pipe_read_fd.handle(), &buf, sizeof(buf));
            dispatch(ctx);
        },
        m_defer_pipe_read_fd.handle(), EPOLLIN | EPOLLET);
}

auto reactor::defer(defer_cb_t cb) -> defer_cb_id_t {
    auto id = deferred_dispatcher::defer(std::move(cb));

    while (true) {
        char buf{};
        if (::write(m_defer_pipe_write_fd.handle(), &buf, 1) < 0) {
            if (errno == EINTR)
                continue;
            auto e = errno;
            deferred_dispatcher::cancel(id);
            throw std::system_error(e, std::generic_category(),
                "unable to write into interrupting pipe of a fanotify reactor");
        }
        return id;
    }
}

namespace {

class this_mnt_namespace final : public mnt_namespace_detector {
public:
    void subscribe(subscription& client) override {
        struct ::stat st{};
        if (::stat("/proc/self/ns/mnt", &st) < 0)
            throw std::system_error(errno, std::generic_category(),
                "unable to determine self mount namespace id");

        fd_holder root_fd{::open("/", O_CLOEXEC | O_RDONLY)};
        if (! root_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open root dir in self mount namespace");

        fd_holder base_proc_dir_fd{::open("/proc/self", O_CLOEXEC | O_RDONLY)};
        if (! base_proc_dir_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open base process directory in self mount namespace");

        client.namespace_found(st.st_ino, std::move(root_fd), std::move(base_proc_dir_fd));

        m_self_mnt_ns_id = st.st_ino;
        m_client = &client;
    }

    void unsubscribe(subscription&) override {
        if (m_client)
            m_client->namespace_have_gone(m_self_mnt_ns_id);
    }

private:
    subscription* m_client = nullptr;
    ::ino_t m_self_mnt_ns_id;
};

::pid_t g_this_pid;
std::atomic_flag g_this_pid_init_flag = ATOMIC_FLAG_INIT;

}

interceptor_l1_impl::interceptor_l1_impl(
        const l1_params& params,
        mnt_namespace_detector_ptr ns_detector)
    : m_params(params)
    , m_ns_detector{std::move(ns_detector)} {

    atomic_init(&m_event_id_gen, 1);

    if (! g_this_pid_init_flag.test_and_set())
        g_this_pid = ::getpid();

    m_read_threads.resize(m_params.m_worker_thread_count);

    if (! m_ns_detector)
        m_ns_detector = std::make_shared<this_mnt_namespace>();

    TRACE_L1_INFO() << "created";
}

interceptor_l1_impl::~interceptor_l1_impl() {
    if (m_started)
        try {
            stop();
        } catch (...) {}

    TRACE_L1_INFO() << "destroing";
}

void interceptor_l1_impl::start() {
    if (m_started)
        return;

    TRACE_L1_INFO() << "starting with " << m_read_threads.size() << " threads for processing ...";

    try {
        m_reactor.enable();
        for (auto& t : m_read_threads)
            t = std::thread([this]{
                    void* thread_ctx = nullptr;

                    struct sched_param sp{};
                    sp.sched_priority = sched_get_priority_max(SCHED_RR);
                    if (sched_setscheduler(0, SCHED_RR, &sp) < 0) {
                        auto e = errno;
                        TRACE_ERROR() << "interceptor_l1(" << (void*)this << ") unable to "
                            "change scheduler policy: " << strerror(e);
                    }

                    try {
                        m_next_layer->thread_started(&thread_ctx);
                        while (m_reactor.poll(thread_ctx))
                            ;
                    } catch (...) {
                        m_next_layer->failure(thread_ctx, std::current_exception());
                    }
                    m_next_layer->thread_finishing(thread_ctx);
                });
        m_ns_detector->subscribe(*this);
        m_started = true;
        TRACE_L1_INFO() << "started";
    } catch (...) {
        stop();
        throw;
    }
}

void interceptor_l1_impl::stop() {
    TRACE_L1_INFO() << "stopping ...";

    m_ns_detector->unsubscribe(*this);

    std::shared_lock ns_list_lock{m_namespace_list_mutex};
    m_namespace_list_cv.wait(ns_list_lock,
        [this]{ return m_namespaces.empty(); });

    std::unique_lock pending_deleted_ns_list_lock{m_pending_deleted_namespace_list_mutex};
    m_namespace_list_cv.wait(pending_deleted_ns_list_lock,
        [this]{ return m_pending_deleted_namespaces.empty(); });

    m_reactor.enable(false);
    for (auto& t : m_read_threads)
        if (t.joinable())
            t.join();

    m_started = false;
    TRACE_L1_INFO() << "stopped";
}

void interceptor_l1_impl::namespace_found(::ino_t mnt_ns_id, fd_holder root_fd, fd_holder base_proc_dir_fd) {
    try {
        add_mnt_ns_monitor(mnt_ns_id, std::move(root_fd), std::move(base_proc_dir_fd));
    } catch (const std::exception& e) {
        TRACE_L1_ERROR() << "- failure on adding new mount namespace id=" << mnt_ns_id << ": "
            << utils::dump_exc_with_nested(e);
    }
}

void interceptor_l1_impl::namespace_have_gone(::ino_t mnt_ns_id) {
    try {
        remove_mnt_ns_monitor(mnt_ns_id);
    } catch (const std::exception& e) {
        TRACE_L1_ERROR() << "- failure on removing absent mount namespace id=" << mnt_ns_id << ": "
            << utils::dump_exc_with_nested(e);
    }
}

bool interceptor_l1_impl::add_mnt_ns_monitor(::ino_t mnt_ns_id, fd_holder root_fd, fd_holder base_proc_dir_fd) {
    std::unique_lock l{m_namespace_list_mutex};

    if (m_namespaces.find(mnt_ns_id) != m_namespaces.end())
        return false;

    TRACE_L1_INFO() << "adding new mount namespace id=" << mnt_ns_id;

    auto& ns_data = m_namespaces.emplace(
        std::piecewise_construct, std::forward_as_tuple(mnt_ns_id), std::make_tuple())->second;

    ns_data.m_mnt_ns_id = mnt_ns_id;
    ns_data.m_root_fd = std::move(root_fd);
    ns_data.m_base_proc_dir_fd = std::move(base_proc_dir_fd);

    bool fan_cb_registered = false;
    bool mounts_cb_registered = false;

    try {
        ns_data.m_mounts_fd.reset(::openat(ns_data.m_base_proc_dir_fd.handle(), "mounts", O_CLOEXEC));
        if (! ns_data.m_mounts_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open 'mounts' pseudo file in new mount namespace");

        ns_data.m_fan_fd.reset(::fanotify_init(
            FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
            O_RDONLY | O_CLOEXEC | O_NOATIME));
        if (! ns_data.m_fan_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to create fanotify control fd");

        ns_data.m_fan_cb_id = m_reactor.register_cb(
            [this, &ns_data](void* ctx){ read_fanotify(ctx, ns_data); },
                ns_data.m_fan_fd.handle(), EPOLLIN/* | EPOLLET*/);
        fan_cb_registered = true;

        ns_data.m_mounts_cb_id = m_reactor.register_cb(
            [this, &ns_data](void*){ update_mountinfo(ns_data); },
                ns_data.m_mounts_fd.handle(), EPOLLPRI);
        mounts_cb_registered = true;

        // Request to read mountinfo for the first time
        ns_data.m_onetime_read_cb_id = m_reactor.defer(
            [this, &ns_data](void*){ update_mountinfo(ns_data); });
    } catch (...) {
        if (mounts_cb_registered)
            m_reactor.unregister_cb(ns_data.m_mounts_cb_id);
        if (fan_cb_registered)
            m_reactor.unregister_cb(ns_data.m_fan_cb_id);

        update_mountinfo(ns_data, /*remove_all*/ true);

        m_namespaces.erase(mnt_ns_id);
        m_namespace_list_cv.notify_all();
        throw;
    }

    return true;
}

bool interceptor_l1_impl::remove_mnt_ns_monitor(::ino_t mnt_ns_id) {
    std::unique_lock ns_list_lock{m_namespace_list_mutex};

    auto it = m_namespaces.find(mnt_ns_id);
    if (it == m_namespaces.end())
        return false;

    TRACE_L1_INFO() << "removing mount namespace id=" << mnt_ns_id;

    std::lock_guard pending_deleted_ns_list_lock{m_pending_deleted_namespace_list_mutex};

    // Though the mnt_namespace entity is moved from actual known namespaces into {pending deleted}
    // ones, the entity still has the same address so deferred handler can use it later.
    it = m_pending_deleted_namespaces.insert(m_namespaces.extract(it));
    ns_list_lock.unlock();

    auto& ns_data = it->second;

    for (auto& id : ns_data.m_ask_client_cb_ids)
        m_reactor.cancel_deferred(id);

    m_reactor.cancel_deferred(ns_data.m_onetime_read_cb_id);
    m_reactor.unregister_cb(ns_data.m_mounts_cb_id);
    m_reactor.unregister_cb(ns_data.m_fan_cb_id);

    try {
        m_reactor.defer([this, &ns_data, it](void*){
            // ns_data is held by "m_pending_deleted_namespaces" container and can has gone only
            // as the result of executing {erase} operation 2 lines below.
            update_mountinfo(ns_data, /*remove_all*/ true);
            std::lock_guard l{m_pending_deleted_namespace_list_mutex};
            m_pending_deleted_namespaces.erase(it);
            m_namespace_list_cv.notify_all();
        });
    } catch (...) {
        // Paranoidal hanlding of failure to defer mount points de-registering with
        // update_mountinfo call later. The namespace will be unregistered but the
        // mount points from it still will be controlled by fanotify.
        m_pending_deleted_namespaces.erase(it);
        m_namespace_list_cv.notify_all();
        throw;
    }

    return true;
}

void interceptor_l1_impl::request_update_masks_async(::ino_t mnt_ns_id, void* ctx) {
    // Take unique lock instead of shared one only due to working with m_ask_client_cb_ids array.
    // Another solution could be to introduce another mutex for protecting the array. Think it
    // should be good enough because actual work will be done in deferred statement after this lock
    // released.
    std::unique_lock l{m_namespace_list_mutex};

    auto it = m_namespaces.find(mnt_ns_id);
    if (it == m_namespaces.end())
        return;

    auto& ids = it->second.m_ask_client_cb_ids;

    ids.erase(remove_if(ids.begin(), ids.end(),
        [this](auto& id){ return m_reactor.deferred_has_gone(id); }),
        ids.end());

    ids.push_back(m_reactor.defer([this, &ns_data = it->second, ctx](void* /* thread ctx */){
        bool need_to_update = false;
        const l1_client::mask_setter_t mask_setter =
            [&need_to_update, &ns_data](int mount_id, std::uint32_t new_mask){
                if (auto it = ns_data.m_mount_list.find(mount_id); it != ns_data.m_mount_list.end()) {
                    if (it->second.m_tracking_mask != new_mask) {
                        it->second.m_new_tracking_mask = new_mask;
                        need_to_update = true;
                    }
                }
            };

        std::lock_guard l{ns_data.m_mount_list_mutex};

        try {
            m_next_layer->update_masks(ns_data.m_mnt_ns_id, ctx, mask_setter);
        } catch (const std::exception& e) {
            TRACE_L1_ERROR() << "called client as requested but client raised unexpected exception: "
                << utils::dump_exc_with_nested(e);

            need_to_update = false;
            for (auto& [mount_id, mnt] : ns_data.m_mount_list)
                mnt.m_new_tracking_mask = mnt.m_tracking_mask;
        }

        if (need_to_update)
            flush_masks(ns_data, ns_data.m_mount_list);
    }));
}

void interceptor_l1_impl::request_update_masks(std::optional<::ino_t> mnt_ns_id, void* ctx) {
    std::shared_lock l{m_namespace_list_mutex};

    for (auto it = mnt_ns_id ? m_namespaces.find(*mnt_ns_id) : m_namespaces.begin();
         it != m_namespaces.end();
         mnt_ns_id ? it = m_namespaces.end() : ++it) {

        auto& ns_data = it->second;
        bool need_to_update = false;
        const l1_client::mask_setter_t mask_setter =
            [&need_to_update, &ns_data](int mount_id, std::uint32_t new_mask){
                if (auto it = ns_data.m_mount_list.find(mount_id); it != ns_data.m_mount_list.end()) {
                    if (it->second.m_tracking_mask != new_mask) {
                        it->second.m_new_tracking_mask = new_mask;
                        need_to_update = true;
                    }
                }
            };

        std::lock_guard l2{ns_data.m_mount_list_mutex};

        try {
            m_next_layer->update_masks(ns_data.m_mnt_ns_id, ctx, mask_setter);
        } catch (...) {
            for (auto& [mount_id, mnt] : ns_data.m_mount_list)
                mnt.m_new_tracking_mask = mnt.m_tracking_mask;
            throw;
        }

        if (need_to_update)
            flush_masks(ns_data, ns_data.m_mount_list);
    }

    m_next_layer->update_masks_done(ctx);
}

void interceptor_l1_impl::update_mountinfo(mnt_namespace& ns_data, bool remove_all) {
    TRACE_INFO() << "interceptor_l1(" << (void*)this << ") "
        << (remove_all ? "clearing" : "re-reading")
        << " mountinfo for a mount namespace id=" << ns_data.m_mnt_ns_id;

    // TODO: do not use the list but determine properties of each fs
    const std::string_view pseudofs_list[] = {"sysfs", "proc", "devtmpfs", "devpts", "cgroup", "bpf",
        "cgroup2", "pstore", "securityfs", "efivarfs", "debugfs", "tracefs", "configfs"};
    std::unordered_map<int, mount_data> mount_list;

    std::unique_lock l{ns_data.m_mount_list_mutex, std::defer_lock};

    const l1_client::mask_setter_t mask_setter = [&mount_list](int mount_id, std::uint32_t new_mask){
        if (auto it = mount_list.find(mount_id); it != mount_list.end())
            it->second.m_new_tracking_mask = new_mask;
    };

    std::vector<char> buffer;
    if (! remove_all) {
        // It's crazy that Linux doesn't provide mechanisms for guaranteed reading of pseudo
        // files without race conditions... So let's read the same file twice to be sure that
        // it's been read without intermediate changes
        buffer = utils::read_whole_file("mountinfo", ns_data.m_base_proc_dir_fd.handle());
        while (true) {
            auto tmp_buffer = utils::read_whole_file("mountinfo", ns_data.m_base_proc_dir_fd.handle());
            if (buffer == tmp_buffer)
                break;
            buffer.swap(tmp_buffer);
        }

        l.lock();

        // Extract from each line just needed fields: fs_type, mount path, mount id. Try to do this
        // without extra allocations.
        short line_num = 0;
        for (std::string_view line : utils::string_splitter(
                std::string_view{buffer.data(), buffer.size()}, "\n\r")) {
            ++line_num;
            utils::string_splitter fields(line, " \t");

            bool good = true;
            int mount_id;
            std::string_view mountpoint_path, fs_type;
            ::dev_t dev_id;

            try {
                auto f_it = utils::advance_checked(fields.begin(), fields.end(), 0);
                mount_id = utils::to_number<int>(*f_it);

                {
                    utils::string_splitter dev_parts{
                        *(f_it = utils::advance_checked(f_it, fields.end(), 2)), ":"};
                    auto it = utils::advance_checked(dev_parts.begin(), dev_parts.end(), 0);
                    unsigned dev_major = utils::to_number<unsigned>(*it);
                    unsigned dev_minor = utils::to_number<unsigned>(
                        *utils::advance_checked(it, dev_parts.end(), 1));
                    dev_id = makedev(dev_major, dev_minor);
                }

                mountpoint_path = *(f_it = utils::advance_checked(f_it, fields.end(), 2));

                fs_type = *(f_it = utils::step_behind(f_it, fields.end(), "-"));
                if (any_of(std::begin(pseudofs_list), std::end(pseudofs_list),
                        [&fs_type](auto v){ return v == fs_type; }))
                    continue;
            } catch (const std::out_of_range&) {
                good = false;
            } catch (const std::range_error&) {
                good = false;
            }
            if (! good) {
                TRACE_L1_ERROR() << "unable to parse mountinfo line " << line_num << ": " << line;
                continue;
            }

            // If some mountpoint has been mounted into a directory named with spaces, its path will
            // be modified by kernel on reading the "mountinfo" file - spaces will be replaced with
            // "\040" code. It should be replaced here back. As usual, let's avoid redundant
            // allocations if no replacing required and no new mountpoint descriptor going to be
            // created.
            std::string mountpoint_path_str;
            constexpr std::string_view repl_str = "\\040";
            auto repl_pos = mountpoint_path.find(repl_str, 0);

            if (repl_pos != std::string_view::npos) {
                mountpoint_path_str = mountpoint_path;
                do {
                    mountpoint_path_str.replace(repl_pos, repl_str.size(), std::string_view{" "});
                    repl_pos = mountpoint_path_str.find(repl_str, repl_pos);
                } while (repl_pos != std::string::npos);
                mountpoint_path = mountpoint_path_str;
            }

            auto mount_it = ns_data.m_mount_list.find(mount_id);
            if (mount_it != ns_data.m_mount_list.end() && mount_it->second.m_mountpoint_path == mountpoint_path) {
                mount_list.insert(ns_data.m_mount_list.extract(mount_it));
            } else {
                auto& new_mount = mount_list[mount_id];
                new_mount.m_dev_id = dev_id;
                new_mount.m_mount_id = mount_id;
                if (mountpoint_path_str.empty())
                    new_mount.m_mountpoint_path = mountpoint_path;
                else
                    new_mount.m_mountpoint_path = std::move(mountpoint_path_str);

                try {
                    m_next_layer->on_mount(ns_data.m_mnt_ns_id, dev_id, mount_id,
                        new_mount.m_mountpoint_path, mask_setter);

                    TRACE_L1_INFO() << "found new mountpoint '"
                        << new_mount.m_mountpoint_path << "', id=" << mount_id
                        << ", fs_type=" << fs_type;
                }
                catch (const std::exception& e) {
                    TRACE_L1_ERROR() << "found new mountpoint '"
                        << new_mount.m_mountpoint_path << "', id=" << mount_id
                        << ", fs_type=" << fs_type << ", but client raised unexpected exception: "
                        << utils::dump_exc_with_nested(e);
                }
            }
        }
    }

    if (! l)
        l.lock();

    for (auto& [old_mount_id, old_mount] : ns_data.m_mount_list) {
        try {
            m_next_layer->on_umount(ns_data.m_mnt_ns_id, old_mount.m_dev_id, old_mount_id,
                old_mount.m_mountpoint_path, mask_setter);

            TRACE_L1_INFO() << "lost mountpoint '"
                << old_mount.m_mountpoint_path << "', id=" << old_mount_id;
        } catch (const std::exception& e) {
            TRACE_L1_ERROR() << "lost mountpoint '"
                << old_mount.m_mountpoint_path << "', id=" << old_mount_id << "and client raised "
                "unexpected exception on this: " << utils::dump_exc_with_nested(e);
        }
    }

    try {
        m_next_layer->mount_changes_done(ns_data.m_mnt_ns_id, mask_setter, /*is_namespace_dead*/ remove_all);
    } catch (const std::exception& e) {
        TRACE_L1_ERROR() << "finished with updated mountinfo "
            "but client raised unexpected exception at the end: " << utils::dump_exc_with_nested(e);
    }

    // If this method has been called as a result of failure on initializing fanotify subsystem, the
    // fanotify fd is not initialized and nothing to flush into fanotify evidently.
    if (ns_data.m_fan_fd)
        flush_masks(ns_data, mount_list);
}

void interceptor_l1_impl::flush_masks(mnt_namespace& ns_data, std::unordered_map<int, mount_data>& new_list) {
    auto conv_flags = [](std::uint32_t flags){
        unsigned res = (flags & (std::uint32_t)fs_event_type::open) ? FAN_OPEN : 0;
        res |= (flags & (std::uint32_t)fs_event_type::open_perm) ? FAN_OPEN_PERM : 0;
        res |= (flags & (std::uint32_t)fs_event_type::open_exec) ? FAN_OPEN_EXEC : 0;
        res |= (flags & (std::uint32_t)fs_event_type::open_exec_perm) ? FAN_OPEN_EXEC_PERM : 0;
        res |= (flags & (std::uint32_t)fs_event_type::close) ? FAN_CLOSE_NOWRITE : 0;
        res |= (flags & (std::uint32_t)fs_event_type::close_modified) ? FAN_CLOSE_WRITE : 0;
        res |= (flags & (std::uint32_t)fs_event_type::access) ? FAN_ACCESS : 0;
        res |= (flags & (std::uint32_t)fs_event_type::access_perm) ? FAN_ACCESS_PERM : 0;
        res |= (flags & (std::uint32_t)fs_event_type::modify) ? FAN_MODIFY : 0;
        return res;
    };

    // It's expected that any fanotify marks for removed mount point are disappeared also. Thus no
    // other interactions with fanotify subsystem required. But crude design of fanotify brings many
    // race conditions here. For example, let's consider next sequence of steps:
    //
    //   1. Something changed in current mountinfo and we are processing the mounts table, building
    //   masks for various mount points.
    //   2. Something changed again and a mount point '/a/b/' has been removed from the system. but
    //   we still processing previous table view (for example, near the end of update_mountinfo
    //   method). Later we try to set a mask for '/a/b/' which doesn't exist. And the mask goes
    //   to... parent mount point '/'.
    //   3. The last mountinfo change comes to this algorithm and we build masks for any live mount
    //   points again. But nothing changed for '/' and it's useless to update it. But it's wrong. It
    //   was corrupted (set to wrong state) at previous step.
    //
    // Thanks to fanotify authors, let's flush and re-load all mount point masks on every change.
    // Even if we set unexpected mask for '/' instead of removed recently '/a/b/', it will be fixed
    // in a moment when next mountinfo update is procesed.

    int res = ::fanotify_mark(ns_data.m_fan_fd.handle(), FAN_MARK_FLUSH | FAN_MARK_MOUNT,
        /*mask*/ 0, ns_data.m_root_fd.handle(), nullptr);
    if (res < 0) {
        auto e = errno;
        TRACE_L1_ERROR() << "unable to flush all marks for mount namespace id=" << ns_data.m_mnt_ns_id
            << "; unexpected events may come further; error: " << std::generic_category().message(e);
    } else
        TRACE_L1_INFO() << "flushed marks for mount namespace id=" << ns_data.m_mnt_ns_id;

    for (auto& [mount_id, mnt] : new_list) {
        if (! mnt.m_new_tracking_mask) {
            mnt.m_tracking_mask = 0;
            continue;
        }

        const char* mp_path = mnt.m_mountpoint_path.c_str();

        // As long as we using mount point paths from different mount namespaces,
        // they should be interpreted as relative to root directory of particular namespace.
        if (mp_path[0] == '/')
            ++mp_path;

        if (mp_path[0] == '\0')
            mp_path = ".";

        res = ::fanotify_mark(ns_data.m_fan_fd.handle(), FAN_MARK_ADD | FAN_MARK_MOUNT,
            /*FAN_ONDIR |*/ conv_flags(mnt.m_new_tracking_mask), ns_data.m_root_fd.handle(), mp_path);
        if (res < 0) {
            auto e = errno;
            TRACE_L1_ERROR() << "unable to add subscription flags=0b"
                << std::bitset<16>(mnt.m_new_tracking_mask)
                << " for mountpoint '" << mp_path << "' id="
                << mnt.m_mount_id << ", mount namespace id=" << ns_data.m_mnt_ns_id
                << ": " << std::generic_category().message(e);
            mnt.m_new_tracking_mask = mnt.m_tracking_mask;
        } else {
            mnt.m_tracking_mask = mnt.m_new_tracking_mask;
            TRACE_L1_INFO() << "added subscription flags=0b"
                << std::bitset<16>(mnt.m_new_tracking_mask) << " for mountpoint '"
                << mp_path << "' id=" << mnt.m_mount_id << ", mount namespace id="
                << ns_data.m_mnt_ns_id;
        }
    }

    ns_data.m_mount_list.swap(new_list);
}

void interceptor_l1_impl::read_fanotify(void* ctx, const mnt_namespace& ns_data) {
    // Design note for this method: it should be least number of operations / system calls
    // here so it must be as fast as possible. If something is needed for the next layer, that
    // layer should do it itself.

    // TODO: is it better to use bulk reading when more than 1 record is read at once? Think, it's
    //       not good idea because having processed the first record for a long time we don't give a
    //       chance to another thread to handle the second one faster.
    //const int bulk_size = 4;
    const int bulk_size = 1;
    ::fanotify_event_metadata ev[bulk_size];
    int pos = 0, items = 0;

    // TODO: spawn thread for adding more threads?
    while (true) {
        if (pos >= items) {
            ssize_t res = ::read(ns_data.m_fan_fd.handle(), ev, sizeof(ev));
            if (res < 0) {
                if (errno == EAGAIN)
                    break;

                throw std::system_error(errno, std::generic_category(), "unable to read fanotify event");
            }

            // Current design assumes that there couldn't be partial reading though many threads are
            // reading from the same fd simultaneously. If this happens, the poller scheme should be
            // redesigned.
            if ((size_t)res % sizeof(ev[0]) != 0)
                throw std::logic_error("partial reading from fanotify fd - read "
                    + std::to_string(res) + " bytes instead of " + std::to_string(sizeof(ev)));

            if (res == 0)
                throw std::logic_error("zero reading from fanotify fd");

            pos = 0;
            items = static_cast<int>(res / sizeof(ev[0]));
        }

        // Short-cut for this process - all permission-related fs activities are permitted
        if (ev[pos].pid == g_this_pid) {
            if (ev[pos].mask & (FAN_ACCESS_PERM | FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM)) {
                ::fanotify_response res = {ev[pos].fd, FAN_ALLOW};
                std::ignore = ::write(ns_data.m_fan_fd.handle(), &res, sizeof(res));
            }
            if (ev[pos].fd != FAN_NOFD)
                ::close(ev[pos].fd);
            continue;
        }

        l1_fs_event out_ev;

        out_ev.m_mnt_ns_id = ns_data.m_mnt_ns_id;
        out_ev.m_event_types = (ev[pos].mask & FAN_OPEN) ? (std::uint32_t)fs_event_type::open : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_OPEN_PERM) ? (std::uint32_t)fs_event_type::open_perm : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_OPEN_EXEC) ? (std::uint32_t)fs_event_type::open_exec : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_OPEN_EXEC_PERM) ? (std::uint32_t)fs_event_type::open_exec_perm : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_CLOSE_NOWRITE) ? (std::uint32_t)fs_event_type::close : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_CLOSE_WRITE) ? (std::uint32_t)fs_event_type::close_modified : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_ACCESS) ? (std::uint32_t)fs_event_type::access : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_ACCESS_PERM) ? (std::uint32_t)fs_event_type::access_perm : 0;
        out_ev.m_event_types |= (ev[pos].mask & FAN_MODIFY) ? (std::uint32_t)fs_event_type::modify : 0;
        if (ev[pos].fd != FAN_NOFD)
            out_ev.m_fd.reset(ev[pos].fd);
        out_ev.m_pid = ev[pos].pid;
        out_ev.m_event_id = m_event_id_gen.fetch_add(1, std::memory_order_relaxed);

        m_next_layer->on_fs_event(ctx, std::move(out_ev));

        ++pos;
    }
}

void interceptor_l1_impl::post_verdict(::ino_t mnt_ns_id, int fd, verdict vrd) {
    assert(fd >= 0);
    std::shared_lock l{m_namespace_list_mutex};
    if (auto it = m_namespaces.find(mnt_ns_id); it != m_namespaces.end()) {
        ::fanotify_response res = {fd, std::uint32_t(vrd == verdict::allow ? FAN_ALLOW : FAN_DENY)};
        std::ignore = ::write(it->second.m_fan_fd.handle(), &res, sizeof(res));
    }
}

} // ns fan_interceptor
