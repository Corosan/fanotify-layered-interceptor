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

#include "interceptor_l2.h"
#include "utils.h"

#include <cassert>
#include <cstring>
#include <cstdio>
#include <type_traits>
#include <exception>
#include <system_error>
#include <iterator>
#include <algorithm>

#include <unistd.h>

#define TRACE_L2_INFO() TRACE_INFO() << "interceptor_l2(" << (void*)this << ") "
#define TRACE_L2_ERROR() TRACE_INFO() << "interceptor_l2(" << (void*)this << ") "

namespace fan_interceptor {

namespace {

std::uint32_t calc_mask_event_types(std::uint32_t requested_event_types) {
    auto mask_event_types = requested_event_types;

    // Though the subscriber may want to get a non-blocking event only, it could be other
    // subscribers who requested blocking a event of the same type. Let's drive this subscriber from
    // both blocking and non-blocking events (assuming that a fanotify mask selector wouldn't
    // request both types from fanotify subsystem - it's redundant).
    if (mask_event_types & (std::uint32_t)fs_event_type::open)
        mask_event_types |= (std::uint32_t)fs_event_type::open_perm;
    if (mask_event_types & (std::uint32_t)fs_event_type::open_exec)
        mask_event_types |= (std::uint32_t)fs_event_type::open_exec_perm;
    if (mask_event_types & (std::uint32_t)fs_event_type::access)
        mask_event_types |= (std::uint32_t)fs_event_type::access_perm;

    return mask_event_types;
}

}

thread_local int mu_interceptor_impl::s_executing_on_thread = 0;

//------------------------------------- fs_event_for_subscription_impl

mu_interceptor_impl::fs_event_for_subscription_impl::fs_event_for_subscription_impl(
        fs_event_impl& parent,
        subscription& s,
        bool verdict_should_be_posted,
        std::optional<l2_cache::rce> r) noexcept
    : m_parent_event{parent}
    , m_subscription{s}
    , m_event_type{parent.m_event_type}
    , m_verdict_should_be_posted{verdict_should_be_posted}
    , m_cache_entry(std::move(r)) {

    const std::uint32_t orig_requested_event_types = s.is_cache_enabled()
        ? l2_cache::get_orig_requested_event_types(s.m_cache_rce_storage)
        : s.get_requested_event_types();

    // To tell the truth, a type of this particular event is stored in parent
    // fs_event_impl object. Why to store it here additionally? Well, ...
    // it can be blocking event being processed now but the subscriber wanted an
    // unblocking event - let's respect its expectations. Prepare an event type
    // visible for the subscriber here in this event-for-subscription object.
    switch (m_event_type) {
    case fs_event_type::open_perm:
        if (orig_requested_event_types & (std::uint32_t)fs_event_type::open)
            m_event_type = fs_event_type::open;
        break;
    case fs_event_type::open_exec_perm:
        if (orig_requested_event_types & (std::uint32_t)fs_event_type::open_exec)
            m_event_type = fs_event_type::open_exec;
        break;
    case fs_event_type::access_perm:
        if (orig_requested_event_types & (std::uint32_t)fs_event_type::access)
            m_event_type = fs_event_type::access;
        break;
    default:
        break;
    }
}

mu_interceptor_impl::fs_event_for_subscription_impl::fs_event_for_subscription_impl(
        fs_event_for_subscription_impl&& r) noexcept
    : m_parent_event{r.m_parent_event}
    , m_subscription{r.m_subscription}
    , m_event_type{r.m_event_type}
    , m_cache_entry{std::move(r.m_cache_entry)}{
    m_ref.store(r.m_ref.load(std::memory_order_relaxed), std::memory_order_relaxed);
    m_verdict_should_be_posted.store(
        r.m_verdict_should_be_posted.load(std::memory_order_relaxed), std::memory_order_relaxed);
}

void mu_interceptor_impl::fs_event_for_subscription_impl::post_verdict(verdict v, bool cache_it) {
    if (m_verdict_should_be_posted.exchange(false, std::memory_order_relaxed)) {
        m_parent_event.post_verdict(v, {});
        if (cache_it && m_cache_entry)
            m_cache_entry->set_verdict(v);
    }
}

void mu_interceptor_impl::fs_event_for_subscription_impl::release() noexcept {
    if (m_ref.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        post_verdict(verdict::allow, /*cache it*/ false);
        m_cache_entry.reset();
        if (m_subscription.finished_to_use())
            m_parent_event.finish_with_subscription(m_subscription);
        m_parent_event.release();
    }
}

//------------------------------------- fs_event_impl

auto mu_interceptor_impl::fs_event_impl::add_receiver(
        subscription& s, bool need_to_post_verdict, std::optional<l2_cache::rce> r)
    -> fs_event_for_subscription_impl& {
    // Can't fill intrusive ptrs pointing to fs_event_for_subscription_impl structures right now
    // because the fs_event_for_subscription_impl structures (a-k-a 'receivers') live in a vector
    // which can invalidate any pointers while we extend it. And the intrusive ptrs will become
    // invalid also.
    return m_receivers.emplace_back(std::piecewise_construct,
        std::forward_as_tuple(*this, s, need_to_post_verdict, std::move(r)),
        std::forward_as_tuple(fs_event_ptr{})).first;
}

auto mu_interceptor_impl::fs_event_impl::activate_receivers() -> receiver_unlocker {
    int active_receivers_count = 0;
    int waiting_for_verdict_count = 0;

    for (auto& [receiver, ptr] : m_receivers) {
        if (receiver.try_mark_subscription_used()) {
            ++active_receivers_count;
            ptr = fs_event_ptr{&receiver, intrusive_add_ref{}};
            if (receiver.is_verdict_expected())
                ++waiting_for_verdict_count;
        }
    }

    m_ref.fetch_add(active_receivers_count, std::memory_order_relaxed);
    m_wait_for_verdict_count.store(waiting_for_verdict_count, std::memory_order_relaxed);
    return receiver_unlocker{this};
}

void mu_interceptor_impl::fs_event_impl::post_verdict(verdict v, rcv_key) {
    join_verdict(v);

    if (m_wait_for_verdict_count.fetch_sub(1, std::memory_order_acq_rel) == 1 && m_fd) {
        if (m_interceptor.m_mount_ns_unique_id_gen.load(std::memory_order_relaxed)
            != m_mount_ns_id_ver) {
            // While the event object walked somewhere in user (subscribers) code, the mount
            // namespace this event is related to could disappear and the mount namespace ID is now
            // obsolete. This statement re-checks that mount namespace unique ID is still the same
            // as it was when the event was initialized.
            // TODO: it can be overdesign here - how a mount namespace can disapper while we still
            // have an ongoing event being handled thus effectively blocking some user process
            // (belonging to the mount namespace) on FS action.
            std::shared_lock l{m_interceptor.m_mountpoint_mutex};
            if (auto it = m_interceptor.m_mountpoints.find(m_mnt_ns_id);
                it == m_interceptor.m_mountpoints.end()
                || it->second.m_mount_ns_unique_id != m_mount_ns_unique_id)
                return;
        }
        m_interceptor.m_layer1->post_verdict(m_mnt_ns_id, m_fd_for_permission_event, m_final_verdict);
    }
}

void mu_interceptor_impl::fs_event_impl::release() noexcept {
    if (m_ref.fetch_sub(1, std::memory_order_acq_rel) == 2) {
        m_receivers.clear();
        m_fd.close();
        m_last_used = std::chrono::steady_clock::now();
        m_ref.store(0, std::memory_order_release);
        if (m_is_in_nursing_home.load(std::memory_order_relaxed))
            m_interceptor.purge_nursing_home();
    }
}

void mu_interceptor_impl::fs_event_impl::finish_with_subscription(subscription& s) {
    m_interceptor.finish_with_subscription(s);
}

//------------------------------------- subscription

bool mu_interceptor_impl::subscription::try_mark_used() noexcept {
    unsigned val;
    do {
        val = m_state.load(std::memory_order_relaxed);
        if (val & STATE_PENDING_DELETED)
            return false;
    } while (! m_state.compare_exchange_weak(val, val + STATE_USAGE_COUNTER_INC,
        std::memory_order_relaxed));

    return true;
}

bool mu_interceptor_impl::subscription::finished_to_use() {
    unsigned val = m_state.fetch_sub(STATE_USAGE_COUNTER_INC, std::memory_order_relaxed);
    return (val & STATE_PENDING_DELETED)
        && ((val & STATE_USAGE_COUNTER_MASK) == 1)
        && ((val & STATE_THREAD_COUNTER_MASK) == 0);
}

bool mu_interceptor_impl::subscription::finished_calling_client_check_last() {
    const unsigned val = m_state.fetch_sub(STATE_THREAD_COUNTER_INC, std::memory_order_relaxed);

    if (val & STATE_NEED_NOTIFY) {
        const unsigned t_counter = val & STATE_THREAD_COUNTER_MASK;
        if (((val & STATE_DELETE_RQ_FROM_WORKING_THREAD) && t_counter == STATE_THREAD_COUNTER_INC * 2)
            || (!(val & STATE_DELETE_RQ_FROM_WORKING_THREAD) && t_counter == STATE_THREAD_COUNTER_INC)) {
            m_mutex.lock();
            m_mutex.unlock();
            m_cv.notify_all();
        }
    }

    // So, {true} is returned only if an 'unsubscribe' sequence has been executed, it was executed
    // from a working thread calling a user callback, no references exist on this subscription
    // object and no other outstanding events in other threads are delivered to clients.
    return (val & STATE_PENDING_DELETED)
        && (val & STATE_DELETE_RQ_FROM_WORKING_THREAD)
        && (val & STATE_USAGE_COUNTER_MASK) == 0
        && (val & STATE_THREAD_COUNTER_MASK) == STATE_THREAD_COUNTER_INC;
}

void mu_interceptor_impl::subscription::mark_for_deletion_and_lock(
        bool is_from_cb_handler_thread) noexcept {
    // Though USAGE_COUNTER is originally used by extern fs event wrappers, we use it here also to
    // add a lock so nobody removes the subscription object until the 'unsubscribe' sequence
    // finishes with it.
    unsigned state, new_state;
    m_state.fetch_add(STATE_USAGE_COUNTER_INC, std::memory_order_relaxed);
    do {
        state = m_state.load(std::memory_order_relaxed);
        new_state = state | STATE_PENDING_DELETED;
        if ((state & STATE_THREAD_COUNTER_MASK)
            != (is_from_cb_handler_thread ? STATE_THREAD_COUNTER_INC : 0)) {
            new_state |= STATE_NEED_NOTIFY;
            new_state |= is_from_cb_handler_thread ? STATE_DELETE_RQ_FROM_WORKING_THREAD : 0;
        }
    } while (! m_state.compare_exchange_weak(state, new_state, std::memory_order_relaxed));
}

bool mu_interceptor_impl::subscription::are_no_events_delivered(bool is_from_cb_handler_thread) noexcept {
    return
        (m_state.load(std::memory_order_relaxed) & STATE_THREAD_COUNTER_MASK)
        == (is_from_cb_handler_thread ? STATE_THREAD_COUNTER_INC : 0);
}

bool mu_interceptor_impl::subscription::unlock_marked_for_deletion() noexcept {
    const auto state = m_state.fetch_sub(STATE_USAGE_COUNTER_INC, std::memory_order_relaxed);

    return (state & STATE_USAGE_COUNTER_MASK) == STATE_USAGE_COUNTER_INC
        && !(state & STATE_DELETE_RQ_FROM_WORKING_THREAD)
        && (state & STATE_THREAD_COUNTER_MASK) == 0;
}

//-------------------------------------

mu_interceptor_impl::mu_interceptor_impl(
        const l2_params& params,
        std::unique_ptr<interceptor_l1> layer1,
        std::shared_ptr<utils::trivial_timer> service_timer)
    : m_params(params)
    , m_service_timer(std::move(service_timer))
    , m_l2_cache(m_params.m_delay_fd_on_close)
    , m_layer1(std::move(layer1)) {
    m_layer1->set_client(this);

    TRACE_L2_INFO() << "created";
}

mu_interceptor_impl::~mu_interceptor_impl() {
    TRACE_L2_INFO() << "destroying";
}

void mu_interceptor_impl::subscribe(mu_subscriber& subscriber, const subscription_params& params) {
    auto requested_event_types = params.m_event_types;

    // It's rediculous to ask to get both blocking and non-blocking events of the same type, for
    // instance, [open] and [open_perm]. Let's clear non-blocking ones if blocking exist.
    if ((requested_event_types & ((std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::open_perm))
        == ((std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::open_perm))
        requested_event_types &= ~(std::uint32_t)fs_event_type::open;

    if ((requested_event_types & ((std::uint32_t)fs_event_type::open_exec | (std::uint32_t)fs_event_type::open_exec_perm))
        == ((std::uint32_t)fs_event_type::open_exec | (std::uint32_t)fs_event_type::open_exec_perm))
        requested_event_types &= ~(std::uint32_t)fs_event_type::open_exec;

    if ((requested_event_types & ((std::uint32_t)fs_event_type::access | (std::uint32_t)fs_event_type::access_perm))
        == ((std::uint32_t)fs_event_type::access | (std::uint32_t)fs_event_type::access_perm))
        requested_event_types &= ~(std::uint32_t)fs_event_type::access;

    const auto orig_requested_event_types = requested_event_types;
    cache_rce_storage tmp_cache_storage;

    if (params.m_cache_enabled)
        m_l2_cache.on_subscribe(tmp_cache_storage, requested_event_types, &calc_mask_event_types);

    std::string prefix_path{params.m_prefix_path};
    if ((! prefix_path.empty() && *(prefix_path.end() - 1) != '/') || prefix_path.empty())
        prefix_path += '/';

    if (prefix_path[0] != '/')
        throw std::invalid_argument("invalid prefix path provided for registering a "
            "subscriber \"" + std::string(subscriber.name()) + "\"; it should start from '/'");

    {
        std::string s;
        for (std::uint8_t i = 0; i < (std::uint8_t)fs_event_type_bit::total_count; ++i) {
            if (orig_requested_event_types & (1 << i)) {
                if (! s.empty())
                    s += '|';
                s += fs_event_type_to_str((fs_event_type)(1 << i));
            }
        }

        TRACE_L2_INFO() << "adds a subscription "
            << (void*)&subscriber << " \"" << subscriber.name() << "\", path \""
            << prefix_path << "\", event types: " << s;
    }

    // Using temporary list in order to at least create outer object not under locks
    subscription_list_t tmp_s_list;

    tmp_s_list.emplace_back(
        subscriber, requested_event_types, calc_mask_event_types(requested_event_types), std::move(prefix_path),
        m_subscription_id_gen.fetch_add(1, std::memory_order_relaxed), params.m_cache_enabled);

    tmp_s_list.front().m_cache_rce_storage = tmp_cache_storage;

    std::unique_lock subscr_lock{m_subscription_mutex, std::defer_lock};
    std::unique_lock mnt_lock{m_mountpoint_mutex, std::defer_lock};

    struct worker final : update_masks_worker {
        decltype(subscr_lock)& m_subscr_lock;
        decltype(mnt_lock)& m_mnt_lock;
        subscription_list_t& m_subscriptions;
        subscription_list_t& m_tmp_subscr;
        mountpoint_list_t& m_mountpoints;

        worker(decltype(subscr_lock)& a1, decltype(mnt_lock)& a2,
            subscription_list_t& a3, subscription_list_t& a4, mountpoint_list_t& a5)
            : m_subscr_lock(a1), m_mnt_lock(a2), m_subscriptions(a3)
            , m_tmp_subscr(a4), m_mountpoints(a5) {
        }

        void run(::ino_t namespace_id, const mask_setter_t& set_event_type_mask) override {
            if (! m_subscr_lock) {
                m_subscr_lock.lock();
                m_subscriptions.splice(m_subscriptions.end(), m_tmp_subscr);
                m_mnt_lock.lock();
            }

            auto& s = m_subscriptions.back();
            // No need to lock namespace mutex because the whole mount list is unique locked
            auto& mounts = m_mountpoints.find(namespace_id)->second.m_mounts;
            auto& interested_mounts =
                s.m_bind_mountpoints[namespace_id] = get_interested_mounts(s, mounts);

            for (auto& mp_ptr : interested_mounts) {
                bind_mountpoint_subscriber(*mp_ptr, s);
                if (mp_ptr->recalc_event_types())
                    set_event_type_mask(mp_ptr->m_mount_id, mp_ptr->m_event_types);
            }
        }

        void done() override {
            if (! m_subscr_lock) {
                m_subscr_lock.lock();
                m_subscriptions.splice(m_subscriptions.end(), m_tmp_subscr);
            }
        }
    } w{subscr_lock, mnt_lock, m_subscriptions, tmp_s_list, m_mountpoints};

    // When mounts are updated, layer 1 locks are acquired firstly. And layer 2 locks - only after
    // the layer 1. Subscribing/unsubscribing should follow the same pattern else we will end up
    // with classic deadlock. That's why a part of the logic is moved under an auxiliary local class
    // "worker".
    m_layer1->request_update_masks({}, &w);
}

bool mu_interceptor_impl::unsubscribe(mu_subscriber& subscriber) {
    // As long as this code is not intended to remove the same subscriber a few times from a few
    // threads, an iterator to a subscription shouldn't be invalidated even between locked parts of
    // the code.
    subscription_list_t::iterator subscr_it;

    TRACE_L2_INFO() << "removes a subscription "
        << (void*)&subscriber << " \"" << subscriber.name() << "\"";

    // Waiting for finalizing execution of all subscribers (maybe except one which invokes this
    // method indirectly - if this method is executed in a context of interceptor's working thread)
    {
        std::shared_lock subscr_lock{m_subscription_mutex};

        subscr_it = find_if(m_subscriptions.begin(), m_subscriptions.end(),
            [&subscriber](auto& v){ return v.is_same_client(subscriber); });
        if (subscr_it == m_subscriptions.end())
            return false;

        const bool on_work_thread = s_executing_on_thread > 0;
        std::unique_lock l{subscr_it->m_mutex};

        subscr_it->mark_for_deletion_and_lock(on_work_thread);

        subscr_it->m_cv.wait(l,
            [&subscr_it, on_work_thread](){
                return subscr_it->are_no_events_delivered(on_work_thread);
            }
        );
    }

    // Using temporary list in order to move a subscription being deleted into it,
    // so the object together with its content will be destroyed not under lock.
    subscription_list_t tmp_s_list;

    std::unique_lock subscr_lock{m_subscription_mutex, std::defer_lock};
    std::unique_lock mnt_lock{m_mountpoint_mutex, std::defer_lock};

    struct worker final : update_masks_worker {
        decltype(subscr_lock)& m_subscr_lock;
        decltype(mnt_lock)& m_mnt_lock;
        subscription_list_t& m_subscriptions;
        mountpoint_list_t& m_mountpoints;
        subscription& m_subscription;

        worker(decltype(subscr_lock)& l1, decltype(mnt_lock)& l2,
            subscription_list_t& subscr_list, mountpoint_list_t& mnts,
            subscription& s)
            : m_subscr_lock(l1), m_mnt_lock(l2), m_subscriptions(subscr_list)
            , m_mountpoints(mnts), m_subscription(s) {
        }

        void run(::ino_t namespace_id, const mask_setter_t& set_event_type_mask) override {
            if (! m_subscr_lock) {
                m_subscr_lock.lock();
                m_mnt_lock.lock();
            }

            assert(! m_subscriptions.empty());

            for (auto& mp_ptr : m_subscription.m_bind_mountpoints[namespace_id]) {
                bind_mountpoint_subscriber(*mp_ptr, m_subscription, /*do_bind*/ false);
                if (mp_ptr->recalc_event_types())
                    set_event_type_mask(mp_ptr->m_mount_id, mp_ptr->m_event_types);
            }
        }

        void done() override {
        }
    } w{subscr_lock, mnt_lock, m_subscriptions, m_mountpoints, *subscr_it};

    // When mounts are updated, layer 1 locks are acquired firstly. And layer 2 locks - only after
    // the layer 1. Subscribing/unsubscribing should follow the same pattern else we will end up
    // with classic deadlock. That's why a part of the logic is moved under an auxiliary local class
    // "worker".
    m_layer1->request_update_masks({}, &w);

    if (mnt_lock)
        mnt_lock.unlock();

    if (subscr_it->unlock_marked_for_deletion()) {
        if (! subscr_lock)
            subscr_lock.lock();

        tmp_s_list.splice(tmp_s_list.begin(), m_subscriptions, subscr_it);
    }

    return true;
}

void mu_interceptor_impl::finish_with_subscription(subscription& s) {
    subscription_list_t tmp_s_list;

    {
        assert(s.is_pending_deleted());

        std::unique_lock subscr_lock{m_subscription_mutex};
        if (auto it = find_if(m_subscriptions.begin(), m_subscriptions.end(),
                [&s](auto& v){ return &v == &s; });
            it != m_subscriptions.end())
            tmp_s_list.splice(tmp_s_list.begin(), m_subscriptions, it);
    }
}

void mu_interceptor_impl::on_mount(::ino_t namespace_id, ::dev_t dev_id, int mount_id,
    std::string_view mountpoint_path, const mask_setter_t&) {
    std::string mountpoint_path_str{mountpoint_path};

    if (! mountpoint_path_str.empty() && *(mountpoint_path_str.end() - 1) != '/')
        mountpoint_path_str += '/';

    auto mp_ptr = std::make_shared<mountpoint_state>(
        mountpoint_state{namespace_id, mount_id,
            m_mount_unique_id_gen.fetch_add(1, std::memory_order_relaxed),
            std::move(mountpoint_path_str)});

    std::shared_lock l1{m_mountpoint_mutex};
    std::unique_lock l2{m_mountpoint_mutex, std::defer_lock};
    std::unique_lock<std::shared_mutex> mtx_l;
    std::vector<mountpoint_ptr_t>* mounts;

    if (auto it = m_mountpoints.find(namespace_id); it != m_mountpoints.end()) {
        mtx_l = std::unique_lock{it->second.m_mutex};
        mounts = &it->second.m_mounts;
    } else {
        l1.unlock();
        l2.lock();
        // Second lookup is needed because somebody else could create the object
        // while we switched the lock above
        if (it = m_mountpoints.find(namespace_id); it == m_mountpoints.end()) {
            const auto unique_ns_id =
                m_mount_ns_unique_id_gen.fetch_add(1, std::memory_order_relaxed);
            it = m_mountpoints.emplace(namespace_id, unique_ns_id).first;
        }
        mounts = &it->second.m_mounts;
    }

    {
        std::unique_lock l3{m_disk_last_mp_change_mutex};
        m_disk_last_mp_changes[dev_id] = mp_ptr->m_mount_unique_id;
    }

    mounts->insert(
        lower_bound(mounts->begin(), mounts->end(), mp_ptr->m_mountpoint_path, mp_compare{}),
        std::move(mp_ptr));

}

void mu_interceptor_impl::on_umount(::ino_t namespace_id, ::dev_t dev_id, int mount_id,
    std::string_view mountpoint_path, const mask_setter_t&) {
//    bool try_to_rm_ns = false;
//    unsigned mnt_ns_sault;
    std::string mountpoint_path_str{mountpoint_path};

    if (! mountpoint_path_str.empty() && *(mountpoint_path_str.end() - 1) != '/')
        mountpoint_path_str += '/';

    {
        std::shared_lock l{m_mountpoint_mutex};

        auto mounts_it = m_mountpoints.find(namespace_id);
        if (mounts_it == m_mountpoints.end())
            return;

        {
            std::lock_guard l{mounts_it->second.m_mutex};
            auto& mounts = mounts_it->second.m_mounts;

            if (auto it = lower_bound(mounts.begin(), mounts.end(), mountpoint_path_str, mp_compare{});
                it != mounts.end() && (*it)->m_mountpoint_path == mountpoint_path_str)
                mounts.erase(it);

            // Actually this method doesn't know whether the namespace has gone totally or just a
            // few (possibly all) mounts disappeared in the namespace. Instead of removing
            // corresponding structures on empty mount set let's just wait for 'is_namespace_dead'
            // flag in a 'mount_changes_done' callback.
/*
            if (mounts.empty()) {
                try_to_rm_ns = true;
                mnt_ns_sault = mounts_it->second.m_sault;
            }
*/
        }

        std::unique_lock l2{m_disk_last_mp_change_mutex};
        // No need to get the next unique mount ID but the same generator is used as logical clock
        // for any mount point changes. As long as a mount point picture for particular disk device
        // changed, it's 'last change ver' numbeer should be updated.
        m_disk_last_mp_changes[dev_id] = m_mount_unique_id_gen.fetch_add(1, std::memory_order_relaxed);
    }
/*
    if (try_to_rm_ns) {
        std::lock_guard l{m_mountpoint_mutex};

        auto mounts_it = m_mountpoints.find(namespace_id);
        if (mounts_it == m_mountpoints.end() || mounts_it->second.m_sault != mnt_ns_sault)
            return;

        if (! mounts_it->second.m_mounts.empty())
            return;

        m_mountpoints.erase(mounts_it);
    }
*/
}

void mu_interceptor_impl::mount_changes_done(::ino_t namespace_id,
    const mask_setter_t& set_event_type_mask, bool is_namespace_dead) {
    std::shared_lock subscr_lock{m_subscription_mutex};
    std::shared_lock mnt_lock{m_mountpoint_mutex};

    // Previous design solution was to remove an internal namespace structure when no mounts exist
    // in it. Thus the next statement was written for the case that this callback is called for
    // already removed namespace structures. Currently I've changed my mind to get explicit flag
    // from the layer 1 about dead namespace.
/*
    std::unique_lock<std::mutex> lock_for_mps;
    std::vector<mountpoint_ptr_t> dummy_mounts;
    auto mounts = &dummy_mounts;
    auto mounts_it = m_mountpoints.find(namespace_id);
    if (mounts_it != m_mountpoints.end()) {
        lock_for_mps = std::unique_lock{mounts_it->second.m_mutex};
        mounts = &mounts_it->second.m_mounts;
    }
*/
    auto mounts_it = m_mountpoints.find(namespace_id);
    // assert(mounts_it != m_mountpoints.end());
    if (mounts_it == m_mountpoints.end())
        return;

    std::unique_lock ml{mounts_it->second.m_mutex};
    auto* mounts = &mounts_it->second.m_mounts;

    for (auto& s : m_subscriptions) {
        std::lock_guard l{s.m_mutex};
        auto& old_interested_mounts = s.m_bind_mountpoints[namespace_id];
        auto new_interested_mounts = get_interested_mounts(s, *mounts);
        std::vector<mountpoint_ptr_t> res;

        set_difference(old_interested_mounts.begin(), old_interested_mounts.end(),
            new_interested_mounts.begin(), new_interested_mounts.end(),
            std::back_inserter(res));
        for (auto& mp_ptr : res) {
            bind_mountpoint_subscriber(*mp_ptr, s, /*do_bind*/ false);
            if (mp_ptr->recalc_event_types())
                set_event_type_mask(mp_ptr->m_mount_id, mp_ptr->m_event_types);
        }

        res.clear();
        set_difference(new_interested_mounts.begin(), new_interested_mounts.end(),
            old_interested_mounts.begin(), old_interested_mounts.end(),
            std::back_inserter(res));
        for (auto& mp_ptr : res) {
            bind_mountpoint_subscriber(*mp_ptr, s);
            if (mp_ptr->recalc_event_types())
                set_event_type_mask(mp_ptr->m_mount_id, mp_ptr->m_event_types);
        }
/*
        if (mounts != &dummy_mounts) {
            s.m_bind_mountpoints[namespace_id] = std::move(new_interested_mounts);
        } else {
            assert(new_interested_mounts.empty());
            s.m_bind_mountpoints.erase(namespace_id);
        }
*/
        if (is_namespace_dead) {
            assert(new_interested_mounts.empty());
            s.m_bind_mountpoints.erase(namespace_id);
        } else
            s.m_bind_mountpoints[namespace_id] = std::move(new_interested_mounts);
    }

    ml.unlock();
    mnt_lock.unlock();
    subscr_lock.unlock();

    if (is_namespace_dead) {
        mountpoint_list_t::node_type tmp;
        {
            std::lock_guard l{m_mountpoint_mutex};
            // no need to really to get the next unique mount namespace ID... but this generator is
            // also used for tracking changes in m_mountpoints container as logical clock.
            m_mount_ns_unique_id_gen.fetch_add(1, std::memory_order_relaxed);
            tmp = m_mountpoints.extract(namespace_id);
        }
        // as usual, deletion of extracted mount state item is not under the lock for speed
    }
}

auto mu_interceptor_impl::get_interested_mounts(
    const subscription& s, const std::vector<mountpoint_ptr_t>& lst) -> std::vector<mountpoint_ptr_t> {
    // A subscription is interested in getting file system notifications from next mounts:
    //
    //    1. Which have mount point paths having the same prefix as the subscription prefix. For
    // example, a subscription prefix is "/a/". If there are next mounts: mp{path="/a/"},
    // mp{path="/a/b/"}, mp{path="/a/b/c/"} - all of them are interesting. mp{path="/b/"} is not
    // interesting for the subscription.
    //
    //    2. Which have longest path which is a prefix of a subscription prefix. For example, if a
    // subscription prefix is "/a/b/c/", next mount is interesting: mp{path="/a/b/"}. But not
    // mp{path="/a/"}
    std::vector<mountpoint_ptr_t> res;

    auto beg = lower_bound(lst.begin(), lst.end(), s.get_prefix_path(), mp_compare{});
    decltype(beg) end;

    if (s.get_prefix_path() == "/")
        end = lst.end();
    else {
        std::string next_path_key = s.get_prefix_path();
        ++next_path_key[next_path_key.size()-2];
        end = lower_bound(lst.begin(), lst.end(), next_path_key, mp_compare{});
    }

    copy(beg, end, std::back_inserter(res));

    if (! res.empty() && res[0]->m_mountpoint_path == s.get_prefix_path())
        return res;

    std::string_view longest_path = s.get_prefix_path();
    do {
        if (longest_path.size() <= 1)
            break;

        longest_path.remove_suffix(
            longest_path.size() - longest_path.rfind('/', longest_path.size() - 2) - 1);

        if (auto it = lower_bound(lst.begin(), lst.end(), longest_path, mp_compare{});
            it != lst.end() && (*it)->m_mountpoint_path == longest_path) {
            // The path to insert is definitely shorter than all we inserted before and has the same
            // prefix - so it's ordered before already inserted paths lexicographically
            res.insert(res.begin(), *it);
            break;
        }
    } while (true);

    return res;
}

// Precondition - arguments should be properly locked
void mu_interceptor_impl::bind_mountpoint_subscriber(
    mountpoint_state& mp, subscription& s, bool do_bind) {
    struct ev_type_bits_ {
        fs_event_type_bit orig;
        fs_event_type_bit replaced;
    } const ev_type_bits[] = {
        { fs_event_type_bit::open, fs_event_type_bit::open_perm },
        { fs_event_type_bit::open_perm, fs_event_type_bit::open },
        { fs_event_type_bit::open_exec, fs_event_type_bit::open_exec_perm },
        { fs_event_type_bit::open_exec_perm, fs_event_type_bit::open_exec },
        { fs_event_type_bit::close, fs_event_type_bit::close },
        { fs_event_type_bit::close_modified, fs_event_type_bit::close_modified },
        { fs_event_type_bit::access, fs_event_type_bit::access_perm },
        { fs_event_type_bit::access_perm, fs_event_type_bit::access },
        { fs_event_type_bit::modify, fs_event_type_bit::modify }};

    for (auto [orig_type_bit, replaced_type_bit] : ev_type_bits) {
        if (! ((1 << (int)orig_type_bit) & s.get_requested_event_types()))
            continue;

        auto& counters = mp.m_counters[(std::size_t)orig_type_bit];
        auto& repl_counters = mp.m_counters[(std::size_t)replaced_type_bit];

        if (do_bind) {
            if ((1 << (int)orig_type_bit) & (std::uint32_t)fs_event_type::perm_events) {
                if (counters.m_strong_counter++ == 0) {
                    swap(counters.m_weaks, repl_counters.m_weaks);
                    repl_counters.m_strong_counter = 0;
                }
            } else if (orig_type_bit != replaced_type_bit) {
                if (repl_counters.m_strong_counter)
                    repl_counters.m_weaks.push_back(&s);
                else {
                    ++counters.m_strong_counter;
                    counters.m_weaks.push_back(&s);
                    assert(counters.m_strong_counter == counters.m_weaks.size());
                }
            }
            else
                ++counters.m_strong_counter;
        } else {
            if ((1 << (int)orig_type_bit) & (std::uint32_t)fs_event_type::perm_events) {
                if (--counters.m_strong_counter == 0) {
                    swap(counters.m_weaks, repl_counters.m_weaks);
                    repl_counters.m_strong_counter = repl_counters.m_weaks.size();
                }
            } else if (orig_type_bit != replaced_type_bit) {
                if (repl_counters.m_strong_counter)
                    repl_counters.m_weaks.erase(
                        remove_if(repl_counters.m_weaks.begin(), repl_counters.m_weaks.end(),
                            [&s](auto v){ return v == &s; }),
                        repl_counters.m_weaks.end());
                else {
                    counters.m_weaks.erase(
                        remove_if(counters.m_weaks.begin(), counters.m_weaks.end(),
                            [&s](auto v){ return v == &s; }),
                        counters.m_weaks.end());
                    --counters.m_strong_counter;
                    assert(counters.m_strong_counter == counters.m_weaks.size());
                }
            } else
                --counters.m_strong_counter;
        }
    }
}

bool mu_interceptor_impl::mountpoint_state::recalc_event_types() {
    auto new_event_types = m_event_types;
    for (int i = 0; i < (int)fs_event_type_bit::total_count; ++i)
        if (m_counters[i].m_strong_counter)
            new_event_types |= 1 << i;
        else
            new_event_types &= ~(1 << i);

    std::swap(m_event_types, new_event_types);
    return m_event_types != new_event_types;
}

auto mu_interceptor_impl::thread_context::allocate_event(mu_interceptor_impl& interceptor)
    -> intrusive_ptr<fs_event_impl> {
    if (! m_free_events.empty()) {
        m_busy_events.splice(m_busy_events.begin(), m_free_events, m_free_events.begin());
        m_busy_events.begin()->add_ref();
        return intrusive_ptr{std::addressof(*m_busy_events.begin()), intrusive_add_ref{}};
    }

    fs_event_impl* res = nullptr;

    // TODO: is this algorithm really faster than just using one more mutex around
    // free/busy list (needed because finishing work with the event can happen in arbitrary
    // thread)?
    //
    // There is no special processing when an event is freed except its busy flag is reset.
    // Thus when there is no enough events in the free list, the next statement considers
    // 'free' events in the busy list. There could be spikes when many events are needed
    // by the system so every event is wanted small time after it's marked as freed. It's ok,
    // but when the spike goes away, memory pressure should be decreased. The statement
    // throws out too old events which weren't requested too long.
    const size_t max_free_events_throw_old = 10;
    const std::chrono::seconds too_old{10};
    for (auto it = m_busy_events.begin(); it != m_busy_events.end();) {
        if (! it->is_free()) {
            ++it;
            continue;
        }


        if (! res) {
            // Though we already know the m_is_busy flag contains [false], we need
            // to execute {acquire} operation to load latest dependent memory changes
            // into the CPU cache. This operation is needed for all elements in this cycle,
            // not just for the first one, but acquire semantic influences all reads
            // made after this load, so no need to repeat it more than once.
            (void)it->is_free(/*acquire*/ true);

            res = std::addressof(*it++);
        } else {
            if (m_free_events.size() < max_free_events_throw_old
                || it->get_last_used_time() + too_old >= std::chrono::steady_clock::now())
                m_free_events.splice(m_free_events.begin(), m_busy_events, it++);
            else
                it = m_busy_events.erase(it);
        }
    }

    if (! res)
        res = std::addressof(m_busy_events.emplace_back(*this, interceptor));

    // One more ref for making any finalization steps before the event object will be considered
    // as free
    res->add_ref();
    return intrusive_ptr{res, intrusive_add_ref{}};
}

namespace {

void fill_path_from_fd(std::vector<char>& buffer, int fd, std::uint64_t event_id, std::string& dest_path) {

    char proc_path[128] = "/proc/self/fd/";

    // This standard function still has some small bar on a flame graph :(
    //std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    utils::to_string(fd, proc_path + sizeof("/proc/self/fd/") - 1);

    if (buffer.size() < 256)
        buffer.resize(256);

    assert(fd >= 0);

    while (true) {
        ssize_t bytes;
        if(bytes = ::readlink(proc_path, buffer.data(), buffer.size() - 1); bytes < 0) {
            auto e = errno;
            throw std::system_error(e, std::generic_category(),
                "unable to get path for provided fd=" + std::to_string(fd) +
                " from event id=" + std::to_string(event_id));
        }

        if ((size_t)bytes < buffer.size() - 1) {
            dest_path.assign(buffer.data(), bytes);
            return;
        }

        buffer.resize(buffer.size() * 2);
    }
}

} // ns anonymous

// Regarding using noexcept it's important to remember that it's better to kill the app
// in case of any unexpected failure instead of silent swallowing an event without responding
// an answer on permit request from fanotify subsystem. Else it would block some external
// app infinitely.
void mu_interceptor_impl::on_fs_event(void* ctx, l1_fs_event&& event) noexcept {
    auto* const thread_ctx = static_cast<thread_context*>(ctx);

    assert(ctx);

    // Sequence of processing separate event types in case if fanotify subsystem
    // joined them together. First permission events come because it's desired to
    // handle them and send verdict back into the subsystem as fast as possible.
    const fs_event_type single_types[] = {
        fs_event_type::open_perm, fs_event_type::open_exec_perm, fs_event_type::access_perm,
        fs_event_type::open, fs_event_type::open_exec, fs_event_type::access,
        fs_event_type::modify, fs_event_type::close, fs_event_type::close_modified };

    static_assert(sizeof(single_types)/sizeof(single_types[0]) ==
        (std::size_t)fs_event_type_bit::total_count);

    struct ::stat current_fd_stat;
    const auto orig_event_types = event.m_event_types;
    bool verdict_will_be_posted = false;
    bool delay_close_fd = false;

    try {
        if (::fstat(event.m_fd.handle(), &current_fd_stat) < 0) {
            auto e = errno;
            throw std::system_error(e, std::generic_category(),
                "unable to get stat info for fd=" + std::to_string(event.m_fd.handle()));
        }

        fill_path_from_fd(thread_ctx->m_buffer, event.m_fd.handle(), event.m_event_id,
            thread_ctx->m_current_fd_path);

        unsigned mnt_ns_unique_id = 0, mnt_ns_unique_id_latest;
        {
            std::shared_lock l{m_mountpoint_mutex};
            if (auto it = m_mountpoints.find(event.m_mnt_ns_id); it != m_mountpoints.end())
                mnt_ns_unique_id = it->second.m_mount_ns_unique_id;
            mnt_ns_unique_id_latest = m_mount_ns_unique_id_gen.load(std::memory_order_relaxed);
        }

        unsigned dev_last_change_seq_num;
        {
            std::shared_lock l{m_disk_last_mp_change_mutex};
            dev_last_change_seq_num = m_disk_last_mp_changes[current_fd_stat.st_dev];
        }

        for (fs_event_type ev_type : single_types) {
            if (! (event.m_event_types & (std::uint32_t)ev_type))
                continue;

            event.m_event_types &= ~(std::uint32_t)ev_type;

            auto l2_event = thread_ctx->allocate_event(*this);
            l2_event->m_event_type = ev_type;
            std::memcpy(&l2_event->m_fd_stat, &current_fd_stat, sizeof(struct ::stat));
            l2_event->m_path.assign(thread_ctx->m_current_fd_path);
            l2_event->m_pid = event.m_pid;
            l2_event->m_mnt_ns_id = event.m_mnt_ns_id;
            // l2_event->m_mount_id = mnt_id;
            l2_event->m_mount_ns_unique_id = mnt_ns_unique_id;
            l2_event->m_mount_ns_id_ver = mnt_ns_unique_id_latest;
            l2_event->m_fd_for_permission_event = event.m_fd.handle();

            l2_event->init_verdict();

            fs_event_impl::receiver_unlocker rec_unlocker;

            {
                auto cache_entry = m_l2_cache.get_ce(
                    current_fd_stat.st_dev, current_fd_stat.st_ino,
                    dev_last_change_seq_num, current_fd_stat.st_ctime);

                std::shared_lock l{m_subscription_mutex};

                for (auto& s: m_subscriptions) {
                    if (! (s.get_mask_event_types() & (std::uint32_t)ev_type))
                        continue;
                    if (std::memcmp(l2_event->m_path.data(), s.get_prefix_path().data(),
                        s.get_prefix_path().size()) != 0)
                        continue;

                    std::optional<l2_cache::rce> cache_rec_entry;
                    if (s.is_cache_enabled())
                        cache_rec_entry.emplace(cache_entry.get_rce(s.id(), s.m_cache_rce_storage, ev_type));

                    const bool need_to_post_verdict =
                        (std::uint32_t)ev_type
                        & (std::uint32_t)fs_event_type::perm_events
                        & s.get_requested_event_types();

                    if (cache_rec_entry) {
                        verdict v;
                        if (need_to_post_verdict && cache_rec_entry->is_verdict_ready(v)) {
                            l2_event->join_verdict(v);
                            continue;
                        }

                        auto flags = cache_rec_entry->prepare_for_work();
                        if (flags & l2_cache::rce::action_flag::delay_close_fd)
                            delay_close_fd = true;
                        if (! (flags & l2_cache::rce::action_flag::cont))
                            continue;
                    }

                    l2_event->add_receiver(s, need_to_post_verdict, std::move(cache_rec_entry));
                }

                // An intrusive pointer is created for every receiver and the subscription's
                // usage count is incremented. Should be called under subscription's lock.
                rec_unlocker = l2_event->activate_receivers();
            }

            // Short-cut for the case when all verdicts have got from a cache so no receivers
            // created
            if (l2_event->get_receivers().empty()
                && ((std::uint32_t)ev_type & (std::uint32_t)fs_event_type::perm_events)) {
                verdict_will_be_posted = true;
                m_layer1->post_verdict(event.m_mnt_ns_id, event.m_fd.handle(), l2_event->get_verdict());
                continue;
            }

            // Need to duplicate the file descriptor holder if this not the last event type to
            // deliver (to process)...
/*
            if (event.m_event_types)
                l2_event->m_fd = event.m_fd;
            else {
                // last cycle of incoming event processing...
                if (delay_close_fd)
                    add_fd_to_delayed_close(event.m_fd);
                l2_event->m_fd = std::move(event.m_fd);
            }
*/

            l2_event->m_fd = event.m_fd;

            if (l2_event->will_verdict_be_posted())
                verdict_will_be_posted = true;

            for (auto& [receiver, ptr] : l2_event->get_receivers()) {
                ++s_executing_on_thread;
                bool need_to_finalize = false;

                try {
                    if (ptr) {
                        need_to_finalize = true;
                        receiver.call_client(std::move(ptr));
                    }
                } catch (const std::exception& e) {
                    TRACE_L2_ERROR() << "catched unexpected exception on calling subscriber '"
                        << receiver.client_name() << "' for event id=" << event.m_event_id
                        << ", type " << ev_type << ": " << utils::dump_exc_with_nested(e);
                } catch (...) {
                    TRACE_L2_ERROR() << "catched unexpected exception on calling subscriber '"
                        << receiver.client_name() << "' for event id=" << event.m_event_id
                        << ", type " << ev_type;
                }

                if (need_to_finalize)
                    receiver.finished_calling_client();
                --s_executing_on_thread;
            }

            // rec_unlocker will reset every not moved receiver here
        }

        if (delay_close_fd)
            add_fd_to_delayed_close(event.m_fd);

        thread_ctx->event_processed();
    } catch (const std::exception& e) {
        thread_ctx->event_failed();
        // This exception catcher is intended for internal errors like insufficient resources
        // or violation of invariants in this code. Any exceptions happened in subscription
        // clients are catched in the catcher above.
        TRACE_L2_ERROR() << "catched unexpected exception during handing an event id="
            << event.m_event_id << ": " << utils::dump_exc_with_nested(e);
    }

    if ((orig_event_types & (std::uint32_t)fs_event_type::perm_events)
        && ! verdict_will_be_posted
        && event.m_fd)
        m_layer1->post_verdict(event.m_mnt_ns_id, event.m_fd.handle(), verdict::allow);
}

void mu_interceptor_impl::add_fd_to_delayed_close(fd_holder fd) {
    auto now_tp = std::chrono::steady_clock::now();
    std::unique_lock l{m_fds_to_close_mutex};

    // Using an additional list of list_node<fd_holder> objects allows to get rid of one
    // more allocation when new item is needed to be added into m_fds_to_close list.
    if (! m_free_fds_to_close.empty())
        m_fds_to_close.splice(m_fds_to_close.end(), m_free_fds_to_close, m_free_fds_to_close.begin());
    else
        m_fds_to_close.push_back(decltype(m_fds_to_close)::value_type{});

    m_fds_to_close.back() = std::make_pair(now_tp, std::move(fd));

    if (! m_closing_task_id)
        m_closing_task_id = m_service_timer->post_single_shot_task(
            [this](){ close_fds(); }, now_tp + std::chrono::seconds(1));
}

void mu_interceptor_impl::close_fds() {
    auto limit_tp = std::chrono::steady_clock::now() + std::chrono::seconds(1);

    unsigned closed_count = 0;
    bool added_new_task = false;
    decltype(m_fds_to_close) tmp_list;

    {
        std::unique_lock l{m_fds_to_close_mutex};

        tmp_list.splice(
            tmp_list.end(),
            m_fds_to_close,
            m_fds_to_close.begin(),
            find_if(m_fds_to_close.begin(), m_fds_to_close.end(),
                [limit_tp](auto& v){ return v.first >= limit_tp; }));
    }

    // Execute potentially time consuming operation of closing file descriptors
    // out of the lock
    for (auto& v : tmp_list)
        v.second.close();

    closed_count = tmp_list.size();

    {
        std::unique_lock l{m_fds_to_close_mutex};

        m_free_fds_to_close.splice(m_free_fds_to_close.end(), tmp_list,
            tmp_list.begin(), tmp_list.end());

        if (! m_fds_to_close.empty()) {
            added_new_task = true;
            m_closing_task_id = m_service_timer->post_single_shot_task(
                [this](){ close_fds(); }, m_fds_to_close.front().first + std::chrono::seconds(1));
        }
        else
            m_closing_task_id = 0;
    }

    TRACE_L2_INFO() << "closed " << closed_count << " fds in a pending manner"
        << (added_new_task ? " and initiated one more pending task" : "");
}

void mu_interceptor_impl::failure(void* ctx, std::exception_ptr p) {
    try {
        std::rethrow_exception(p);
    } catch (const std::exception& e) {
        TRACE_L2_ERROR() << "faced with catastrophic failure in one of threads of layer 1: "
            << utils::dump_exc_with_nested(e);
    } catch (...) {
        TRACE_L2_ERROR() << "faced with catastrophic failure of unknown type in one "
            "of threads of layer 1";
    }
}

void mu_interceptor_impl::start() {
    if (m_params.m_print_stat)
        m_print_stat_task_id = m_service_timer->post_repeat_task(
            [this](){ dump_stat(); }, std::chrono::seconds(5));

    m_layer1->start();
}

void mu_interceptor_impl::stop() {
    m_layer1->stop();

    if (m_print_stat_task_id) {
        m_service_timer->cancel_task(m_print_stat_task_id);
        m_print_stat_task_id = 0;
    }

    int closing_task_id = 0;
    {
        std::unique_lock l{m_fds_to_close_mutex};
        closing_task_id = m_closing_task_id;
    }

    if (closing_task_id)
        m_service_timer->cancel_task(closing_task_id);

    {
        std::unique_lock l{m_fds_to_close_mutex};
        m_fds_to_close.clear();
        m_free_fds_to_close.clear();
    }
}

void mu_interceptor_impl::dump_stat() {
    unsigned long total_processed = 0;
    unsigned long total_failed = 0;
    bool have_threads;

    {
        std::lock_guard l{m_thread_context_mutex};

        have_threads = ! m_all_thread_contexts.empty();
        for (auto ctx : m_all_thread_contexts) {
            TRACE_L2_INFO() << "thread stat: "
                "events processed = " << ctx->get_processed_events_count() << ", "
                "events failed = " << ctx->get_failed_events_count();
            total_processed += ctx->get_processed_events_count();
            total_failed += ctx->get_failed_events_count();
        }
    }

    if (have_threads)
        TRACE_L2_INFO() << "---- " <<
            "total events processed = " << total_processed << ", "
            "total events failed = " << total_failed;
}

void mu_interceptor_impl::thread_started(void** ctx_ptr) {
    auto p = new thread_context;
    std::lock_guard l{m_thread_context_mutex};
    m_all_thread_contexts.push_back(p);
    *ctx_ptr = p;
}

void mu_interceptor_impl::thread_finishing(void* ctx) {
    auto thread_ctx = static_cast<thread_context*>(ctx);

    {
        std::lock_guard l{m_nursing_home_mutex};
        thread_ctx->grab_busy_events_info(m_events_nursing_home);
    }

    {
        std::lock_guard l{m_thread_context_mutex};
        if (auto it = find(m_all_thread_contexts.begin(), m_all_thread_contexts.end(), thread_ctx);
            it != m_all_thread_contexts.end())
            m_all_thread_contexts.erase(it);
    }

    delete thread_ctx;
}

} // ns fan_interceptor
