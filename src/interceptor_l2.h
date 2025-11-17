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

#include "interceptor_types.h"
#include "l2_cache.h"

#include <memory>
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <string_view>
#include <string>
#include <vector>
#include <list>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <condition_variable>
#include <thread>

#include <sys/types.h>
#include <sys/stat.h>

namespace fan_interceptor {

// Design of this class from subscriptions management point of view assumes that we don't expect
// more than dozen of subscriptions. So linear lookup should be good enough. Adding/removing mount
// points can use a memory allocator and thus can be not extremely fast. An event processing cycle
// must be most optimized hopefully without any memory allocations (trying to reuse previously
// allocated buffers) and with minimum of system calls.
class mu_interceptor_impl : public mu_interceptor, interceptor_l1::l1_client {
    class thread_context;
    class subscription;
    class fs_event_impl;

    // An event view for one particular subscriber which is selected for delivering an event
    class fs_event_for_subscription_impl final : public fs_event {
        fs_event_impl& m_parent_event;
        subscription& m_subscription;
        fs_event_type m_event_type;
        std::atomic<int> m_ref{0};
        std::atomic<bool> m_verdict_should_be_posted;
        std::optional<l2_cache::rce> m_cache_entry;

    public:
        fs_event_for_subscription_impl(
            fs_event_impl& parent,
            subscription& s,
            bool verdict_should_be_posted,
            std::optional<l2_cache::rce> r) noexcept;

        // A bunch of these objects represending all related subscribers are stored in a vector by
        // value. Storing in a vector requires us to be able to copy (move) items being stored.
        // Default copy (move) constructor is deleted due to inability to copy atomic objects.
        // Though we don't plan to copy this object during active phase of event processing, but
        // only during building a list of these event views for particular event. At this phase the
        // object can be considered as a carcass. Let's allow to move carcasses (moving should be
        // enough for std::vector requirements and produce beter code for the vector, though we
        // understand that we not move anything here, just copy bytes).
        fs_event_for_subscription_impl(fs_event_for_subscription_impl&& r) noexcept;

        bool is_verdict_expected() const noexcept {
            return m_verdict_should_be_posted.load(std::memory_order_relaxed);
        }

        // Atomically increments a usage counter on associated subscription if the latter is not
        // marked for deletion, returns status whether it can be used.
        bool try_mark_subscription_used() noexcept {
            return m_subscription.try_mark_used();
        }

        void call_client(fs_event_ptr&& event) const {
            m_subscription.call_client(std::move(event));
        }

        void finished_calling_client() const {
            if (m_subscription.finished_calling_client_check_last())
                m_parent_event.finish_with_subscription(m_subscription);
        }

        std::string_view client_name() const {
            return m_subscription.get_client_name();
        }

        void add_ref() noexcept override {
            m_ref.fetch_add(1, std::memory_order_relaxed);
        }

        void release() noexcept override;

        // fs_event interface implementation - a part observable by an external code
        //

        fs_event_type type() const override { return m_event_type; }
        int fd() const override { return m_parent_event.m_fd.handle(); }
        ::pid_t pid() const override { return m_parent_event.m_pid; }
        ::ino_t mnt_ns_id() const override { return m_parent_event.m_mnt_ns_id; }
        // int mnt_id() const override { return m_state.m_parent_event->m_mount_id; }
        const char* path() const override { return m_parent_event.m_path.c_str(); }
        void post_verdict(verdict v, bool cache_it) override;
    };

    // The object of this class represents internal state for every filesystem event coming from
    // Layer 1. These objects are not created/destroyed for every signal from the Layer 1, they are
    // reused instead. The final point before considering the object as released and ready to be put
    // into a cache for future usage is a call to its "release" method.
    class fs_event_impl {
    public:
        typedef std::vector<std::pair<fs_event_for_subscription_impl, fs_event_ptr>>
            receiver_and_ptr_list_t;

    private:
        mu_interceptor_impl& m_interceptor;
        std::atomic<unsigned> m_ref{0};
        std::chrono::steady_clock::time_point m_last_used;
        std::atomic<int> m_wait_for_verdict_count{0};

        // One of design goals is to minimize usage of memory allocator during processing each
        // event. This fs_event_impl object is reused for following events coming from layer 1. A
        // list of receivers (active subscriptions selected for the event) is built in the vector
        // which's memory is reused too. Moreover an intrusive pointer for every receiver will be
        // needed soon - this vector is a good place for storing them here too instead of creating
        // temporary vectors each time.
        receiver_and_ptr_list_t m_receivers;

        verdict m_final_verdict;
    public:
        class receiver_unlocker final {
            fs_event_impl* m_parent = nullptr;

            void unlock() noexcept {
                if (m_parent)
                    for (auto& [r, ptr] : m_parent->m_receivers)
                        ptr.reset();
                m_parent = nullptr;
            }

        public:
            receiver_unlocker() = default;
            explicit receiver_unlocker(fs_event_impl* parent) noexcept
                : m_parent(parent) {
            }

            receiver_unlocker(receiver_unlocker&& r) noexcept
                : m_parent(r.m_parent) {
                r.m_parent = nullptr;
            }

            receiver_unlocker& operator=(receiver_unlocker&& r) noexcept {
                using std::swap;

                unlock();
                swap(m_parent, r.m_parent);
                return *this;
            }

            ~receiver_unlocker() { unlock(); }
        };

        class rcv_key {
            rcv_key() = default;    // note! it's private. Pass-key idiom
            friend fs_event_for_subscription_impl;
        };

        fs_event_type m_event_type;
        struct ::stat m_fd_stat;
        std::string m_path;
        ::pid_t m_pid;
        ::ino_t m_mnt_ns_id;

        // int m_mount_id;
        unsigned m_mount_ns_unique_id;

        // Latest version of changes of the interceptor's m_mountpoints container at the
        // moment when this object has been initialized. If an actual change sequence number is not
        // equal the stored value, additional lookup is needed to re-check that we still assume the
        // same mount namespace here by m_mnt_ns_id and m_mount_ns_unique_id numbers;
        unsigned m_mount_ns_id_ver;

        fd_holder m_fd;

        // I'm not sure can duplicated file descriptor be used for sending permission events,
        // so this field contains the value exclusively dedicated for sending the events.
        int m_fd_for_permission_event;

        std::atomic<bool> m_is_in_nursing_home{false};

        fs_event_impl(mu_interceptor_impl& interceptor) noexcept
            : m_interceptor(interceptor) {
        }

        void init_verdict() noexcept { m_final_verdict = verdict::allow; }
        void join_verdict(verdict v) noexcept {
            if (v == verdict::deny)
                m_final_verdict = v;
        }
        verdict get_verdict() const noexcept { return m_final_verdict; }

        auto get_last_used_time() const noexcept { return m_last_used; }

        bool is_free(bool do_acquire = false) const noexcept {
            return m_ref.load(do_acquire ? std::memory_order_acquire : std::memory_order_relaxed) == 0;
        }

        void add_ref() noexcept {
            m_ref.fetch_add(1, std::memory_order_relaxed);
        }

        void release() noexcept;

        bool will_verdict_be_posted() const noexcept {
            return m_wait_for_verdict_count.load(std::memory_order_relaxed);
        }

        void post_verdict(verdict v, rcv_key);

        fs_event_for_subscription_impl& add_receiver(subscription&, bool, std::optional<l2_cache::rce>);

        void finish_with_subscription(subscription& s);

        // This object (fs_event_impl) has a reference counter and an intrusive smart pointer
        // returned by thread_context::allocate_event method manages a lifetime of this object as
        // usual. At a preparation step a number of receivers (fs_event_for_subscription_impl
        // instance) is created for this object - one per each affected subscription. Originally
        // they are considered a separate entities, but finally they participate in a life time of
        // this object. After this method called all the receivers are considered "connected" to
        // this object and the intrusive reference counter is biased accordingly. Returned object is
        // a "locker" which releases all the smart pointers to the receivers on destruction. It's
        // expected that each called subscriber will grab the pointer and hold it as long as it
        // needed.
        receiver_unlocker activate_receivers();

        receiver_and_ptr_list_t& get_receivers() { return m_receivers; }
    };

    struct mountpoint_state final {
        const ::ino_t m_mnt_ns_id;
        const int m_mount_id;
        const unsigned m_mount_unique_id;
        const std::string m_mountpoint_path;    // should finish on '/'
        std::uint32_t m_event_types;

        // For blocked (-perm) types strong count takes into account a subscriber which directly
        // wants to receive blocked events. Weak count (or more preciselly a vector of weak refs)
        // reflects a subscriber which wants to get non-blocking events assuming that a bloked-type
        // event subscriber also exists.
        // For unblocked event types which have a 'blocked type pair' m_weaks are populated with
        // with all non-blocking subscribers until at least one blocked subscriber found.
        struct counters {
            unsigned m_strong_counter;
            std::vector<subscription*> m_weaks;
        } m_counters[(std::size_t)fs_event_type_bit::total_count];

        bool recalc_event_types();
    };

    typedef std::shared_ptr<mountpoint_state> mountpoint_ptr_t;

    struct mountpoint_ns_state final {
        std::shared_mutex m_mutex;
        const unsigned m_mount_ns_unique_id;
        std::vector<mountpoint_ptr_t> m_mounts;

        mountpoint_ns_state(unsigned mount_ns_unique_id)
            : m_mount_ns_unique_id(mount_ns_unique_id) {
        }
    };

    // mountpoint_state items are sorded lexicographically by their mount point paths. See comment
    // for mp_compare below. The list can be accessed under shared lock from a few threads each
    // of which can work with different namespaces. Personal mount list mutex must be taken in this
    // case.
    typedef std::unordered_map<::ino_t, mountpoint_ns_state> mountpoint_list_t;

    class subscription {
    public:
        std::mutex m_mutex;
        std::unordered_map<::ino_t, std::vector<mountpoint_ptr_t>> m_bind_mountpoints;

        std::condition_variable m_cv;

        // It should be opaque field from this class point of view. The subscription doesn't
        // care what's stored here. It's just a place for whatever a cache supporting code wants
        // to store per subscription instance.
        cache_rce_storage m_cache_rce_storage;

        subscription(
            mu_subscriber& client,
            std::uint32_t requested_event_types,
            std::uint32_t mask_event_types,
            std::string prefix_path,
            unsigned id,
            bool cache_enabled)
            : m_client(client)
            , m_requested_event_types(requested_event_types)
            , m_mask_event_types(mask_event_types)
            , m_prefix_path(std::move(prefix_path))
            , m_id(id)
            , m_cache_enabled(cache_enabled)
            , m_state(0) {
            m_referencing_threads.reserve(std::thread::hardware_concurrency());
        }

        bool is_cache_enabled() const noexcept { return m_cache_enabled; }

        // Returns true if the subscription is not marked as going to be deleted. Else the
        // subscription can't be used for further delivery of events
        bool try_mark_used() noexcept;

        // Returns true if the subscription must be deleted by a caller after all - it's marked as
        // pending deleted and it's not used anymore by a delivery event cycle
        bool finished_to_use();

        // Called by unsubscribe sequence - raises PENDING_DELETED flag and increments USAGE counter
        // to prohibit unexpected deletion of this object.
        // Return false in case if the object is already marked for deletion.
        bool mark_for_deletion_and_lock(bool is_from_cb_handler_thread) noexcept;

        // return {true} if the subscription object can be deleted by the caller of this method
        bool unlock_marked_for_deletion() noexcept;

        bool are_no_events_delivered(bool is_from_cb_handler_thread) noexcept;

        void call_client(fs_event_ptr&& event) {
            m_state.fetch_add(STATE_THREAD_COUNTER_INC, std::memory_order_relaxed);

            {
                std::unique_lock l{m_referencing_thread_mutex};
                m_referencing_threads.push_back(std::this_thread::get_id());
            }

            m_client.on_fs_event(std::move(event));
        }

        bool is_client_called_in_this_thread() const;

        // Returns true if the subscription must be deleted by a delivery event cycle
        bool finished_calling_client_check_last();

        std::string_view get_client_name() const {
            return m_client.name();
        }

        bool is_pending_deleted() const noexcept {
            return m_state.load(std::memory_order_relaxed) & STATE_PENDING_DELETED;
        }

        bool is_same_client(const mu_subscriber& s) const noexcept {
            return std::addressof(m_client) == std::addressof(s);
        }

        std::uint32_t get_requested_event_types() const noexcept { return m_requested_event_types; }
        std::uint32_t get_mask_event_types() const noexcept { return m_mask_event_types; }
        const std::string& get_prefix_path() const noexcept { return m_prefix_path; }

        unsigned id() const noexcept { return m_id; }

    private:
        mu_subscriber& m_client;
        // Which event types had been requested when this subscription was created. The variable
        // affects which low-level FAN_XXX constants will be provided to fanotify subsystem
        const std::uint32_t m_requested_event_types;
        // Which event types can drive this subscription. In most cases they are the same as
        // m_requested_event_types, but can be slightly different for instance when a blocking event
        // type (like {open_perm}) drives a subscription which wanted to get non-blocking event
        // (like {open}).
        const std::uint32_t m_mask_event_types;
        const std::string m_prefix_path;        // should finish on '/'
        const unsigned m_id;
        // Whether the subscription pretends to use caching verdict mechanism during its lifetime.
        const bool m_cache_enabled;

        mutable std::mutex m_referencing_thread_mutex;
        std::vector<std::thread::id> m_referencing_threads;

        static_assert(sizeof(unsigned) >= 4);

        // The subscription object is marked for deletion in the near future. It shouldn't be used
        // for delivering events. The flag is set by 'unsubscribe' action directly or indirectly.
        static constexpr unsigned STATE_PENDING_DELETED             = 0x80000000;

        static constexpr unsigned STATE_NEED_NOTIFY                 = 0x40000000;

        // 'pending deleted' was set in a context of a worker thread currently delivering an event
        // related to this subscription. It means that 'unsubscribe' can't just remove the
        // subscription object at the end of its sequence and must delegate this work to an epilogue
        // of an event delivering code
        static constexpr unsigned STATE_DELETE_RQ_FROM_CB_THREAD    = 0x20000000;
        static constexpr unsigned STATE_CONTROL_MASK                = 0xE0000000;

        // A mask and a counter for counting how many threads delivering events right now which are
        // linked to this subscription object. "Delivering" means calling user code via a callback.
        // One event (or more preciselly - event view for the subscription) can be delivered in the
        // only thread, but a few different events can be processed by different threads.
        static constexpr unsigned STATE_THREAD_COUNTER_MASK         = 0x1F800000;
        static constexpr unsigned STATE_THREAD_COUNTER_INC          = 0x00800000;

        // A mask and a counter for counting references to this subscription object from an fs event
        // wrapper seen from the external world. One fs event is counted only once here, it doesn't
        // matter how many copies of a user-visible pointer (fs_event_ptr type) exist. All of they
        // are counted by their own counter fs_event_for_subscription_impl::m_ref.
        static constexpr unsigned STATE_USAGE_COUNTER_MASK          = 0x007FFFFF;
        static constexpr unsigned STATE_USAGE_COUNTER_INC           = 0x00000001;
        std::atomic<unsigned> m_state;
    };

    typedef std::list<subscription> subscription_list_t;

    // All mountpoint_state arrays are ordered by mount point paths, so they look like:
    //  * mp{path="/"}
    //  * mp{path="/a/"}
    //  * mp{path="/a/b/"}
    //  * mp{path="/a/b/c/"}
    //  * mp{path="/b/"}
    //  ...
    // It allows to search for a range of mount points related to desired path prefix with log(N)
    // operations.
    struct mp_compare final {
        bool operator()(const mountpoint_ptr_t& p1, const mountpoint_ptr_t& p2) const {
            return p1->m_mountpoint_path < p2->m_mountpoint_path;
        }

        bool operator()(const mountpoint_ptr_t& p1, std::string_view p2) const {
            return p1->m_mountpoint_path < p2;
        }
    };

    struct update_masks_worker {
        virtual void run(::ino_t namespace_id, const mask_setter_t& mask_setter) = 0;
        virtual void done() = 0;
    protected:
        ~update_masks_worker() = default;
    };

public:
    explicit mu_interceptor_impl(
        const l2_params& params,
        std::unique_ptr<interceptor_l1> layer1,
        std::shared_ptr<utils::trivial_timer> service_timer);
    ~mu_interceptor_impl();

    void start() override;
    void stop() override;

    void subscribe(mu_subscriber& subscriber, const subscription_params& params) override;
    bool unsubscribe(mu_subscriber& subscriber) override;

    // The methods are dedicated primarily for testing... better to not have all them at all because
    // the tests should check how this code works for clients, without examining its internal state.
    unsigned long get_processed_events_count(void* thread_ctx) const noexcept;
    unsigned long get_failed_events_count(void* thread_ctx) const noexcept;
    std::size_t get_event_cache_size(void* thread_ctx) const noexcept;
    std::size_t get_event_nursing_home_size() const;

private:
    const l2_params& m_params;

    // After working thread is destroyed, there could be a number of not-finished events which are
    // still referenced by user-visible pointers - they will be moved here
    std::list<fs_event_impl> m_events_nursing_home;
    mutable std::mutex m_nursing_home_mutex;

    // Synchronization rules:
    //
    // Any modifications in a list of subscriptions or in a single subscription object are subject
    // to acquire exclusive lock using m_subscription_mutex primitive. If there is no intention to
    // modify the list but only one subscription object, a shared lock can be taken together with
    // a mutex inside the subscription object.
    std::shared_mutex m_subscription_mutex;
    subscription_list_t m_subscriptions;
    std::atomic<unsigned> m_subscription_id_gen{1};

    // Synchronization rules:
    //
    // Any modifications in a list of lists of mount points (one list per mount namespace) are
    // subject to acquire exclusive lock using m_mountpoint_mutex primitive. If there is no
    // intention to modify the outer list (add or remove mount namespaces) but only an inner list of
    // mount points per concrete namespace, a shared lock can be taken together with a mutex inside
    // the inner list.
    std::shared_mutex m_mountpoint_mutex;
    mountpoint_list_t m_mountpoints;
    std::atomic<unsigned> m_mount_unique_id_gen{1};     // generator for unique mount IDs
    std::atomic<unsigned> m_mount_ns_unique_id_gen{1};  // generator for unique mount namespace IDs

    std::shared_mutex m_disk_last_mp_change_mutex;
    std::unordered_map<::dev_t, unsigned> m_disk_last_mp_changes;

    std::mutex m_fds_to_close_mutex;
    std::list<std::pair<std::chrono::steady_clock::time_point, fd_holder>> m_free_fds_to_close;
    std::list<std::pair<std::chrono::steady_clock::time_point, fd_holder>> m_fds_to_close;
    int m_closing_task_id = 0;

    std::shared_ptr<utils::trivial_timer> m_service_timer;

    std::mutex m_thread_context_mutex;
    std::vector<thread_context*> m_all_thread_contexts;

    int m_print_stat_task_id = 0;

    l2_cache m_l2_cache;

    // It's better to remove the layer 1 holder before any other data of this class - that's why
    // it's placed after mounts' and subscriptions' containers located above.
    std::unique_ptr<interceptor_l1> m_layer1;

    // Implementation of interceptor_l1::l1_client interface
    //

    void thread_started(void** ctx_ptr) override;
    void thread_finishing(void* ctx) override;

    void on_mount(::ino_t namespace_id, ::dev_t dev_id, int mount_id,
        std::string_view mountpoint_path, const mask_setter_t& set_event_type_mask) override;
    void on_umount(::ino_t namespace_id, ::dev_t dev_id, int mount_id,
        std::string_view mountpoint_path, const mask_setter_t& set_event_type_mask) override;
    void mount_changes_done(::ino_t namespace_id,
        const mask_setter_t& set_event_type_mask, bool is_namespace_dead) override;

    void update_masks(::ino_t namespace_id, void* ctx, const mask_setter_t& mask_setter) override {
        static_cast<update_masks_worker*>(ctx)->run(namespace_id, mask_setter);
    }

    void update_masks_done(void* ctx) override {
        static_cast<update_masks_worker*>(ctx)->done();
    }

    void on_fs_event(void* ctx, l1_fs_event&& event) noexcept override;
    void failure(void* ctx, std::exception_ptr) override;

    //
    // End of interceptor_l1::l1_client interface implementation

    void purge_nursing_home() {
        std::list<fs_event_impl> tmp;
        std::lock_guard l{m_nursing_home_mutex};
        for (auto it = m_events_nursing_home.begin(); it != m_events_nursing_home.end(); ) {
            if (it->is_free())
                tmp.splice(tmp.end(), m_events_nursing_home, it++);
            else
                ++it;
        }
        // all moved to tmp list objects will be destroyed after the mutex is unlocked
    }

    void finish_with_subscription(subscription&);
    void add_fd_to_delayed_close(fd_holder fd);
    void close_fds();
    void dump_stat();

    static std::vector<mountpoint_ptr_t> get_interested_mounts(
        const subscription& s, const std::vector<mountpoint_ptr_t>& lst);

    static void bind_mountpoint_subscriber(
        mountpoint_state& mp, subscription& s, bool do_bind = true);
};

// A per-thread storage which is created for each fanotify-processing thread provided by
// l1 interceptor
class mu_interceptor_impl::thread_context final {
public:
    thread_context() = default;
    thread_context(const thread_context&) = delete;
    thread_context& operator=(const thread_context&) = delete;

    std::vector<char> m_buffer;
    std::string m_current_fd_path;

    intrusive_ptr<fs_event_impl> allocate_event(mu_interceptor_impl& interceptor);

    void event_processed() noexcept {
        m_processed_events.fetch_add(1, std::memory_order_relaxed);
    }

    void event_failed() noexcept {
        m_failed_events.fetch_add(1, std::memory_order_relaxed);
    }

    // Returns a number of events read from fanotify without splitting them
    unsigned long get_processed_events_count() const noexcept {
        return m_processed_events.load(std::memory_order_relaxed);
    }

    unsigned long get_failed_events_count() const noexcept {
        return m_failed_events.load(std::memory_order_relaxed);
    }

    std::size_t get_inprogress_events_count() const noexcept { return m_busy_events.size(); }
    std::size_t get_event_placeholders_count() const noexcept { return m_free_events.size(); }

    void grab_busy_events_info(std::list<fs_event_impl>& target) {
        // As long as this cycle is not synchronized with modifying fs_event_impl.m_ref counter
        // indirectly by a user code executing in an arbitrary thread, we may found some "busy"
        // event which will be marked as freed in a moment. Thus we move busy and almost-freed
        // events into the target list. It should be examined later by some other code. One can
        // think this cycle is not needed because anyway the target list must be examined later.
        // But don't forget, that current cycle is executed in a context of a thread to be
        // destroyed in a moment - maybe we can reduce work for further examining.
        for (auto it = m_busy_events.begin(); it != m_busy_events.end(); ) {
            if (! it->is_free()) {
                it->m_is_in_nursing_home.store(true, std::memory_order_relaxed);
                target.splice(target.end(), m_busy_events, it++);
            } else
                ++it;
        }
    }

private:
    std::list<fs_event_impl> m_free_events;
    std::list<fs_event_impl> m_busy_events;
    std::atomic<unsigned long> m_processed_events = 0;
    std::atomic<unsigned long> m_failed_events = 0;
};

inline unsigned long mu_interceptor_impl::get_processed_events_count(void* thread_ctx) const noexcept {
    return static_cast<const thread_context*>(thread_ctx)->get_processed_events_count();
}

inline unsigned long mu_interceptor_impl::get_failed_events_count(void* thread_ctx) const noexcept {
    return static_cast<const thread_context*>(thread_ctx)->get_failed_events_count();
}

inline std::size_t mu_interceptor_impl::get_event_cache_size(void* thread_ctx) const noexcept {
    return static_cast<const thread_context*>(thread_ctx)->get_inprogress_events_count()
        + static_cast<const thread_context*>(thread_ctx)->get_event_placeholders_count();
}

inline std::size_t mu_interceptor_impl::get_event_nursing_home_size() const {
    std::lock_guard l{m_nursing_home_mutex};
    return m_events_nursing_home.size();
}

} // ns fan_interceptor
