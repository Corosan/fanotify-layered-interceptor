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

// This file declares only types required for external users of the interceptor library. Should be
// considered as the only public header of it. No internals should leak via this header.

#include <cstdint>
#include <memory>
#include <utility>
#include <exception>
#include <string_view>
#include <string>
#include <optional>
#include <functional>
#include <type_traits>

#include <sys/types.h>

namespace fan_interceptor {

namespace details {

// Trivial file descriptor RAII-holder with duplicating fds by POSIX calls
class fd_dup_holder {
public:
    explicit fd_dup_holder(int fd = -1) noexcept
        : m_fd(fd) {
    }

    fd_dup_holder(const fd_dup_holder&);
    fd_dup_holder(fd_dup_holder&& r) noexcept
        : m_fd(r.m_fd) {
        r.m_fd = -1;
    }

    fd_dup_holder& operator=(const fd_dup_holder& r) {
        auto tmp(r);
        swap(tmp);
        return *this;
    }

    fd_dup_holder& operator=(fd_dup_holder&& r) noexcept {
        auto tmp(std::move(r));
        swap(tmp);
        return *this;
    }

    ~fd_dup_holder() { close(); }

    void swap(fd_dup_holder& r) noexcept {
        using std::swap;
        swap(m_fd, r.m_fd);
    }

    explicit operator bool() const noexcept { return m_fd >= 0; }
    bool empty() const noexcept { return m_fd < 0; }
    int release() noexcept { int t = m_fd; m_fd = -1; return t; }
    void reset(int fd) noexcept { close(); m_fd = fd; }
    void close() noexcept;

    // Yes, return internal fd value by this unconvenient method, not by operator int(),
    // else we end up with bugs like "close(my_fd_holder)" which shouldn't compile!
    int handle() const noexcept { return m_fd; }

private:
    int m_fd;
};

// Trivial file descriptor RAII-holder with storing the only file descriptor instance
// in a controlling block (the same approach as in shared_ptr). Allows to eliminate unneeded
// sys calls on copying the holder.
class fd_shared_holder {
    struct cb;

public:
    explicit fd_shared_holder(int fd = -1);
    fd_shared_holder(const fd_shared_holder& r) noexcept;
    fd_shared_holder(fd_shared_holder&& r) noexcept
        : m_cb(r.m_cb) {
        r.m_cb = nullptr;
    }

    fd_shared_holder& operator=(const fd_shared_holder& r) noexcept {
        auto tmp(r);
        swap(tmp);
        return *this;
    }

    fd_shared_holder& operator=(fd_shared_holder&& r) noexcept {
        auto tmp(std::move(r));
        swap(tmp);
        return *this;
    }

    ~fd_shared_holder() { close(); }

    void swap(fd_shared_holder& r) noexcept {
        using std::swap;
        swap(m_cb, r.m_cb);
    }

    explicit operator bool() const noexcept { return m_cb; }
    bool empty() const noexcept { return ! m_cb; }
    int release() noexcept;
    void reset(int fd) { fd_shared_holder tmp(fd); swap(tmp); }
    void close() noexcept;

    int handle() const noexcept;

private:
    cb* m_cb = nullptr;
};

}  // ns details

// Switch between {dup syscall}-based fd holder and reference-counting-based fd holder
//typedef details::fd_dup_holder fd_holder;
typedef details::fd_shared_holder fd_holder;

struct intrusive_add_ref {};

// Trivial intrusive shared pointer just to not use 3rd-party libraries.
template <class T> class intrusive_ptr final {
public:
    static_assert(noexcept(std::declval<T>().add_ref()));
    static_assert(noexcept(std::declval<T>().release()));

    typedef T element_type;

    template <class> friend class intrusive_ptr;

    intrusive_ptr() = default;

    explicit intrusive_ptr(T* obj) noexcept
        : m_obj(obj) {
    }

    explicit intrusive_ptr(T* obj, intrusive_add_ref) noexcept
        : m_obj(obj) {
        m_obj->add_ref();
    }

    intrusive_ptr(const intrusive_ptr& r) noexcept
        : m_obj(r.m_obj) {
        if (m_obj)
            m_obj->add_ref();
    }

    template <class U> intrusive_ptr(const intrusive_ptr<U>& r) noexcept
        : m_obj(r.m_obj) {
        if (m_obj)
            m_obj->add_ref();
    }

    intrusive_ptr(intrusive_ptr&& r) noexcept
        : m_obj(r.m_obj) {
        r.m_obj = nullptr;
    }

    template <class U> intrusive_ptr(intrusive_ptr<U>&& r) noexcept
        : m_obj(r.m_obj) {
        r.m_obj = nullptr;
    }

    intrusive_ptr& operator=(const intrusive_ptr& r) noexcept {
        auto t = r;
        swap(t);
        return *this;
    }

    intrusive_ptr& operator=(intrusive_ptr&& r) noexcept {
        auto t = std::move(r);
        swap(t);
        return *this;
    }

    void swap(intrusive_ptr& r) noexcept {
        using std::swap;
        swap(m_obj, r.m_obj);
    }

    T* operator->() const noexcept { return m_obj; }
    T& operator*() const noexcept { return *m_obj; }

    T* get() const noexcept { return m_obj; }

    explicit operator bool() const noexcept { return m_obj; }

    void reset() noexcept {
        if (m_obj)
            m_obj->release();
        m_obj = nullptr;
    }

    ~intrusive_ptr() {
        if (m_obj)
            m_obj->release();
    }

private:
    T* m_obj = nullptr;
};

// A mount namespace detector interface. Any implementation aware about the namespaces
// can exist behind this interface even trivial one which knows about the process owning
// namespace only.
struct mnt_namespace_detector {
    struct subscription {
        virtual void namespace_found(::ino_t mnt_ns_id, fd_holder root_fd, fd_holder base_proc_dir_fd) = 0;
        virtual void namespace_have_gone(::ino_t mnt_ns_id) = 0;
    protected:
        ~subscription() = default;  // no deletion via this interface
    };

    virtual ~mnt_namespace_detector() = default;

    // On subscription a client should be informed about every already found namespace
    virtual void subscribe(subscription& client) = 0;

    // On unsubscription a client should be notified as if all the namespaces have gone
    virtual void unsubscribe(subscription& client) = 0;
};

typedef std::shared_ptr<mnt_namespace_detector> mnt_namespace_detector_ptr;

enum class fs_event_type_bit : std::uint8_t {
    open = 0, open_perm, open_exec, open_exec_perm, close, close_modified,
        access, access_perm, modify, total_count
};

enum class fs_event_type : std::uint32_t {
    open = 1 << (int)fs_event_type_bit::open,
    open_perm = 1 << (int)fs_event_type_bit::open_perm,
    open_exec = 1 << (int)fs_event_type_bit::open_exec,
    open_exec_perm = 1 << (int)fs_event_type_bit::open_exec_perm,
    close = 1 << (int)fs_event_type_bit::close,
    close_modified = 1 << (int)fs_event_type_bit::close_modified,
    access = 1 << (int)fs_event_type_bit::access,
    access_perm = 1 << (int)fs_event_type_bit::access_perm,
    modify = 1 << (int)fs_event_type_bit::modify,
    perm_events = open_perm | open_exec_perm | access_perm
};

inline const char* fs_event_type_to_str(fs_event_type v) {
    switch (v) {
    case fs_event_type::open: return "[open]";
    case fs_event_type::open_perm: return "[open_perm]";
    case fs_event_type::open_exec: return "[open_exec]";
    case fs_event_type::open_exec_perm: return "[open_exec_perm]";
    case fs_event_type::close: return "[close]";
    case fs_event_type::close_modified: return "[close_modified]";
    case fs_event_type::access: return "[access]";
    case fs_event_type::access_perm: return "[access_perm]";
    case fs_event_type::modify: return "[modify]";
    default: return "[???]";
    }
}

template <class S>
S& operator<<(S& os, fs_event_type v) {
    return os << fs_event_type_to_str(v);
}

enum class verdict : std::uint8_t { allow, deny };

// Event issued by interceptor layer 1. One event per one fanotify reading, the only receiver of the
// event is layer 2. Can contain a few event types if fanoify subsystem decided to glue them. m_fd
// is a file descriptor opened by a kernel for our process.
struct l1_fs_event {
    std::uint32_t m_event_types;
    fd_holder m_fd;
    ::pid_t m_pid;
    ::ino_t m_mnt_ns_id;
    std::uint64_t m_event_id;
};

// Layer 1 interceptor is designed to have it's internal lifecycle and to live its own live. It
// doesn't accept actions from an external side except start/stop and a few requests for pending
// operations. All the interaction is made via a callback interface 'l1_client' through which the
// interceptor notifies somebody about some changes or events and expects that somebody responses
// correspondingly.
struct interceptor_l1 {
    struct l1_client {
        typedef std::function<void(int, std::uint32_t)> mask_setter_t;

        // Interceptor layer 1 manages a pool of threads responsible for processing events from
        // fanotify subsystem. It's expected that a client of the layer 1 may want to store some
        // thread-specific data. This method is called at the beginning of life of new thread thus
        // the client can create some context and store it in provided pointer. This pointer will be
        // provided in every next call.
        virtual void thread_started(void** ctx_ptr) {}
        // This is the last method called on the client when a layer 1 thread going to die. If the
        // client created something and stored via provided pointer on 'thread_started' invocation,
        // this call is the right place for destroying that 'something'.
        virtual void thread_finishing(void* ctx) {}

        // There can be one or more changes in mount info in any mount namespace. When the changes
        // are detected, a lock around the namespace data structures acquired and for every new
        // found mount point the method "on_mount" is called; for every lost mount point the method
        // "on_umount" is called". An implementor can do whatever changes and request to change a
        // subscription mask for any mount point in the namespace via provided setter functor. At
        // the end a method "mount_changes_done" is called and it's guaranteed that all fanotify
        // subscription masks will be updated on the system. After which the lock is released. The
        // sequence of these calls is guaranteed to be run sequentially from the same thread for
        // one particular mount namespace. Calls for different namespaces can interleave with each
        // other.
        //
        // It's up to implementer when to change mount subscription mask - via a setter in
        // on_mount/on_umount or via a setter in mount_changes_done for particular namespace.
        virtual void on_mount(::ino_t namespace_id, ::dev_t dev_id, int mount_id,
            std::string_view mountpoint_path, const mask_setter_t& set_event_type_mask) = 0;
        virtual void on_umount(::ino_t namespace_id, ::dev_t dev_id, int mount_id,
            std::string_view mountpoint_path, const mask_setter_t& set_event_type_mask) = 0;
        virtual void mount_changes_done(::ino_t namespace_id,
            const mask_setter_t& set_event_type_mask, bool is_namespace_dead) = 0;

        virtual void update_masks(::ino_t namespace_id, void* ctx, const mask_setter_t& mask_setter) = 0;
        virtual void update_masks_done(void* ctx) = 0;

        // The main notification callback about filesystem changes
        virtual void on_fs_event(void* ctx, l1_fs_event&& event) noexcept = 0;

        // It's unexpected that any code executing in the layer 1 thread pool would throw an
        // exception. But if it happens, this method is called with the exception pointer before the
        // thread going to die ('thread_finishing' will be called too anyway).
        virtual void failure(void* ctx, std::exception_ptr) = 0;

    protected:
        ~l1_client() = default;     // no deletion via this interface - l1 client implementation is an
                                    // interceptor layer 2 which holds the layer 1 as a part of
                                    // implementation.
    };

    virtual ~interceptor_l1() = default;

    // A client should be set before any other operation on the interceptor. The client
    // can set set only once at the beginning.
    virtual void set_client(l1_client*) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;

    // Request to update mount tracking mask(s) in deferred manner. Specified namespace will be
    // locked and the method "mount_changes_done" called later in an arbitrary thread.
    virtual void request_update_masks_async(::ino_t mnt_ns_id, void* ctx) = 0;

    // Request to update mount tracking mask(s) synchronously. "update_masks" method of a client
    // will be called in context of this method after proper locks taken. It's guaranteed that all
    // mask changes will be propagated to fanotify subsystem. "update_masks_done" method of a client
    // is called at the end if no exception raised by user code. Still under lock.
    virtual void request_update_masks(std::optional<::ino_t> mnt_ns_id, void* ctx) = 0;

    virtual void post_verdict(::ino_t mnt_ns_id, int fd, verdict vrd) = 0;
};


// Event issued by interceptor layer 2. One event per each subscriber. A subscriber strictly
// discouraged to make a few copies of the event - as long as it's alive and no verdict posted,
// corresponding fanotify operation is blocked.
struct fs_event {
    fs_event() = default;

    fs_event(const fs_event&) = delete;
    fs_event& operator=(const fs_event&) = delete;

    virtual ~fs_event() = default;

    virtual fs_event_type type() const = 0;
    virtual int fd() const = 0;
    virtual ::pid_t pid() const = 0;
    virtual ::ino_t mnt_ns_id() const = 0;
    // virtual int mnt_id() const = 0;

    // The path is related to a root directory of some process executed in a mount namespace
    // having the mount which fanotify subsystem adopted
    virtual const char* path() const = 0;

    virtual void post_verdict(verdict vdr, bool cache_it = false) = 0;

private:
    virtual void add_ref() noexcept = 0;
    virtual void release() noexcept = 0;

    friend intrusive_ptr<fs_event>;
};

typedef intrusive_ptr<fs_event> fs_event_ptr;

struct mu_subscriber {
    // Called when some interesting filesystem event happened. The subscriber can hold the event
    // pointer as long as it needs so (but assuming that it consumes resources). If the subscriber
    // was adoped for any synchronous (blocking) event, it must post a verdict for the event via the
    // event's method ('allow' is assumed if it forgot).
    virtual void on_fs_event(fs_event_ptr) = 0;
    virtual std::string_view name() = 0;

protected:
    ~mu_subscriber() = default; // prohibit to delete a subscriber via this interface. It's lifetime
                                // managed externally.
};

struct subscription_params {
    std::uint32_t m_event_types;
    std::string m_prefix_path;
    bool m_cache_enabled = true;
};

struct mu_interceptor {
    virtual ~mu_interceptor() = default;

    virtual void start() = 0;

    // Stop all functionality but do not unsubscribe already adopted clients
    virtual void stop() = 0;

    // Adopt provided subscriber as a receiver of futher filesystem events in according with
    // parameters provided. The subscriber can receive first events in an arbitrary thread even
    // before this method returns (if the interceptor has been started already).
    virtual void subscribe(mu_subscriber& subscriber, const subscription_params& params) = 0;

    // Wait if a subscriber executing 'on_fs_event' method and unbinds the subscriber from the
    // interceptor safely after this. If the subscriber holds an event pointer, it will still be
    // connected to internal event structure and can be used to get various event properties, but
    // not sending a verdict. In case of subscribing to synchronous (blocking) event this method
    // effectively issues a verdict 'allow' in name of the subscriber if the latter didn't post
    // anything before. Note that it's expected that subscriber will release its event pointer
    // eventually to release internal event structure.
    virtual bool unsubscribe(mu_subscriber& subscriber) = 0;

    virtual void invalidate_cache() {}
};

struct l1_params {
    unsigned m_worker_thread_count = 10;
};

struct l2_params {
    l1_params m_l1_params;
    bool m_delay_fd_on_close = true;
    bool m_print_stat = true;
};

std::unique_ptr<interceptor_l1> create_interceptor(const l1_params& params, mnt_namespace_detector_ptr p = {});
std::unique_ptr<mu_interceptor> create_mu_interceptor(const l2_params& params, std::unique_ptr<interceptor_l1> p = {});

} // ns fan_interceptor
