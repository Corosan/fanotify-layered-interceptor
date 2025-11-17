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

#include "l2_cache.h"

#include <algorithm>

namespace fan_interceptor {

auto l2_cache::cache_entry::get_entry_data() -> file_entry_data* {
    if (! m_entry_ptr && m_entries_ver != m_parent.m_entries_ver.load(std::memory_order_relaxed)) {
        std::shared_lock l{m_parent.m_entry_mutex};
        if (auto it = m_parent.m_entries.find(m_key); it != m_parent.m_entries.end()) {
            m_entry_ptr = &it->second;
            m_entry_ptr->m_del_lock_count.fetch_add(1, std::memory_order_relaxed);
        }
        m_entries_ver = m_parent.m_entries_ver.load(std::memory_order_relaxed);
    }
    return m_entry_ptr;
}

bool l2_cache::remove_cache_entry(key_t key, unsigned long& current_change_version) {
    bool res = false;
    std::lock_guard g{m_entry_mutex};

    current_change_version = m_entries_ver.load(std::memory_order_relaxed);

    if (auto it = m_entries.find(key); it != m_entries.end()) {
        // It doesn't matter whether the entry data is used by somebody or not, it's not
        // going to be deleted physically, just moved into the internal cache
        m_entry_internal_cache.push_back(m_entries.extract(it));
        res = true;
    }

    // Remove some entries from the internal cache if it's too big and the entries being removed are
    // not used anymore
    auto it_end = m_entry_internal_cache.end();
    for (auto it = m_entry_internal_cache.begin();
         it < it_end && it_end - m_entry_internal_cache.begin() > 128;) {
        if (it->mapped().m_del_lock_count.load(std::memory_order_acquire) == 0)
            swap(*it, *--it_end);
        else
            ++it;
    }

    m_entry_internal_cache.erase(it_end, m_entry_internal_cache.end());

    return res;
}

auto l2_cache::cache_entry::get_or_create_entry_data() -> file_entry_data* {
    if (auto res = get_entry_data())
        return res;

    std::unique_lock l{m_parent.m_entry_mutex};

    bool found_in_internal_cache = false;
    auto node_it = m_parent.m_entry_internal_cache.end();
    while (node_it != m_parent.m_entry_internal_cache.begin()) {
        if ((--node_it)->mapped().m_del_lock_count.load(std::memory_order_acquire) == 0) {
            found_in_internal_cache = true;
            break;
        }
    }

    bool inserted = false;
    entries_t::iterator it;

    if (found_in_internal_cache) {
        auto node = std::move(*node_it);
        m_parent.m_entry_internal_cache.erase(node_it);
        node.key() = m_key;
        auto r = m_parent.m_entries.insert(std::move(node));
        inserted = r.inserted;
        it = r.position;
    } else {
        tie(it, inserted) = m_parent.m_entries.emplace(std::piecewise_construct,
            std::forward_as_tuple(m_key), std::forward_as_tuple());
    }

    if (inserted)
        it->second.m_generation = 0;    // force the file_entry_data to be re_init later

    m_entries_ver = m_parent.m_entries_ver.fetch_add(inserted, std::memory_order_relaxed) + inserted;
    m_entry_ptr = &it->second;
    m_entry_ptr->m_del_lock_count.fetch_add(1, std::memory_order_relaxed);
    return m_entry_ptr;
}

void l2_cache::cache_entry::try_remove_binded_ce_data() {
    if (! m_entry_ptr && m_entries_ver == m_parent.m_entries_ver.load(std::memory_order_relaxed))
        return;

    // Here is the same sequence as if last cache_entry object in a chain has been removed (take a
    // look at cache_entry's dtor). So anybody (any thread strictly speaking) can remove the
    // file cache entry right after this.
    if (m_entry_ptr) {
        m_entry_ptr->m_del_lock_count.fetch_sub(1, std::memory_order_release);
        m_entry_ptr = nullptr;
    }

    m_parent.remove_cache_entry(m_key, m_entries_ver);
}

bool l2_cache::cache_entry::is_file_entry_valid(const file_entry_data& v) const {
    // In case of any change in mount point table for current disk device which current
    // event came from - assume that no previously cached verdict. Trivial case could be -
    // somebody unmounted removable drive, changed a file on it and mounted it back.
    if (v.m_dev_last_change_seq_num != m_dev_last_change_seq_num)
        return false;

    if (v.m_generation != m_parent.m_generation.load(std::memory_order_relaxed))
        return false;

    if (v.m_ctime != m_ctime)
        return false;

    return true;
}

void l2_cache::cache_entry::reinit_file_entry_if_need(file_entry_data& v) const {
    if (! is_file_entry_valid(v)) {
        v.m_dev_last_change_seq_num = m_dev_last_change_seq_num;
        v.m_generation = m_parent.m_generation.load(std::memory_order_relaxed);
        v.m_ctime = m_ctime;
        v.m_receiver_entries.clear();
    }
}

bool l2_cache::rce::is_verdict_ready(verdict& v) const {
    if (auto entry_ptr = m_parent_ce.get_entry_data()) {
        std::unique_lock l{entry_ptr->m_mutex};

        if (! m_parent_ce.is_file_entry_valid(*entry_ptr))
            return false;

        auto it = std::lower_bound(entry_ptr->m_receiver_entries.begin(), entry_ptr->m_receiver_entries.end(),
            m_subscr_id, [](auto& v, unsigned id){ return v.m_subscr_id < id; });

        if (it != entry_ptr->m_receiver_entries.end()
            && it->m_subscr_id == m_subscr_id
            && (it->m_have_verdicts & m_ev_type)) {
            switch (m_ev_type) {
            case fs_event_type::open_perm: v = it->m_open_verdict; break;
            case fs_event_type::open_exec_perm: v = it->m_open_exec_verdict; break;
            case fs_event_type::access_perm: v = it->m_access_verdict; break;
            default: v = verdict::allow; break;
            }
            return true;
        }
    }

    return false;
}

auto l2_cache::rce::prepare_for_work() -> action_flags_t {
    if ((std::uint32_t)m_ev_type
        & ((std::uint32_t)fs_event_type::modify | (std::uint32_t)fs_event_type::close_modified))
        m_parent_ce.try_remove_binded_ce_data();

    action_flags_t res_flags;

    if (m_parent.m_delay_fd_on_close) {
        if (((std::uint32_t)m_ev_type
             & ((std::uint32_t)fs_event_type::close | (std::uint32_t)fs_event_type::close_modified))
            && m_parent_ce.get_entry_data())
            res_flags |= action_flag::delay_close_fd;
    }

    if (! ((std::uint32_t)m_ev_type & m_rec_storage.m_orig_mask_event_types))
        // The event has not been requested by real subscriber but instead - by this cache code.
        // So... return false that the caller knows there is no need to continue work with this
        // subscriber / receiver.
        return res_flags;

    res_flags |= action_flag::cont;

    if ((std::uint32_t)m_ev_type & (std::uint32_t)fs_event_type::perm_events) {
        try {
            auto entry_ptr = m_parent_ce.get_or_create_entry_data();
            std::unique_lock l{entry_ptr->m_mutex};

            m_parent_ce.reinit_file_entry_if_need(*entry_ptr);

            auto it = std::lower_bound(entry_ptr->m_receiver_entries.begin(), entry_ptr->m_receiver_entries.end(),
                m_subscr_id, [](auto& v, unsigned id){ return v.m_subscr_id < id; });

            if (it == entry_ptr->m_receiver_entries.end() || it->m_subscr_id != m_subscr_id)
                it = entry_ptr->m_receiver_entries.insert(it, {m_subscr_id});
        } catch (const std::bad_alloc&) {
            // In case of insufficient memory just silently skip the unablility to create either
            // the file cache entry or the particular receiver/subscriber cache entry
        }
    }

    return res_flags;
}

void l2_cache::rce::set_verdict(verdict v) {
    std::shared_lock l{m_parent.m_entry_mutex};
    if (auto it = m_parent.m_entries.find(m_key); it != m_parent.m_entries.end()) {
        auto entry_ptr = &it->second;

        std::unique_lock l{entry_ptr->m_mutex};
        auto it2 = std::lower_bound(entry_ptr->m_receiver_entries.begin(), entry_ptr->m_receiver_entries.end(),
            m_subscr_id, [](auto& v, unsigned id){ return v.m_subscr_id < id; });

        if (it2 != entry_ptr->m_receiver_entries.end() && it2->m_subscr_id == m_subscr_id) {
            it2->m_have_verdicts |= m_ev_type;
            switch (m_ev_type) {
            case fs_event_type::open_perm: it2->m_open_verdict = v; break;
            case fs_event_type::open_exec_perm: it2->m_open_exec_verdict = v; break;
            case fs_event_type::access_perm: it2->m_access_verdict = v; break;
            default: break;
            }
        }
    }
}

} // ns fan_interceptor
