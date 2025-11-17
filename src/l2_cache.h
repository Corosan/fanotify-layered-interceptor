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
#include "utils.h"

#include <cstdint>
#include <utility>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <atomic>

#include <sys/types.h>
#include <sys/stat.h>

namespace fan_interceptor {

struct cache_rce_storage {
    std::uint32_t m_orig_requested_event_types;
    std::uint32_t m_orig_mask_event_types;
};

typedef utils::bit_flags<fs_event_type> fs_event_types;

class l2_cache {
    // The cache works with file entries denoted by {device_id, file_inode_id}. Perfectly enough if
    // forgot about possible inode reusing in case of very fast file delete-create operations on
    // filesystems with coarse file creation timestamps. The latter can be addressed by delaying of
    // inode reusage with temporary holding of file descriptors on files being deleted.
    typedef std::pair<dev_t, ino_t> key_t;

    struct key_hash {
        std::size_t operator()(const key_t& k) const {
            return std::hash<dev_t>{}(k.first) ^ std::hash<ino_t>{}(k.second);
        }
    };

    // A piece of data stored per file for each receiver (a subscriber in other words). Remember
    // that different receivers can have different opition on the same file, thus having different
    // verdicts on particular event.
    struct receiver_entry_data {
        unsigned m_subscr_id;
        verdict m_open_verdict;
        verdict m_open_exec_verdict;
        verdict m_access_verdict;
        fs_event_types m_have_verdicts;
    };

    struct file_entry_data {
        typedef utils::small_vector<receiver_entry_data, 4> receiver_entries_t;

        // This object can be destroyed only when this count is zero
        // TODO: spin-waiting or to use real mutex per each file entry?
        std::atomic<int> m_del_lock_count{0};

        unsigned m_dev_last_change_seq_num = 0;
        unsigned m_generation = 0;
        time_t m_ctime = 0;

        utils::spin_lock m_mutex;

        // Per-receiver states; sorted by rec_entry_data::m_subscr_id
        receiver_entries_t m_receiver_entries;
    };

    typedef std::unordered_map<key_t, file_entry_data, key_hash> entries_t;

public:
    l2_cache(bool delay_fd_on_close)
        : m_delay_fd_on_close(delay_fd_on_close) {
    }

    void on_subscribe(cache_rce_storage& s, std::uint32_t& requested_event_types,
            std::uint32_t (*calc_mask)(std::uint32_t)) {
        s.m_orig_requested_event_types = requested_event_types;
        s.m_orig_mask_event_types = calc_mask(requested_event_types);
        // If a subscriber requested to cache verdict result for permission-based file event, it's
        // assumed that it doesn't want to get more events until the file changes. So the cache
        // fixes up a {requested_types} bitset adding {modify} events into the resulting set.
        if (requested_event_types & (std::uint32_t)fs_event_type::perm_events) {
            requested_event_types |=
                (std::uint32_t)fs_event_type::modify
                | (std::uint32_t)fs_event_type::close_modified;
            if (m_delay_fd_on_close)
                requested_event_types |= (std::uint32_t)fs_event_type::close;
        }
    }

    class rce;
    class cache_entry;

    // Get file cache entry wrapper for a file object on a disk. Assume that each file object is
    // uniquely identified by device ID, i-node ID and the object creation time. Also assume that
    // the cache entry should be considered obsolete if a mount point picture of the device has been
    // changed (controversal statement - a file object could be changed through a mount point which
    // is not observed by the interceptor - the cache entry should become obsolete in this case
    // also). As long as particular i-nodes can be reused if one file object is deleted (unlinked)
    // and new one is created, creation time also helps to judge whether it's the original file
    // object.
    cache_entry get_cache_entry(dev_t dev, ino_t ino, unsigned dev_last_change_seq_num, std::time_t ctime);

    void invalidate() {
        m_generation.fetch_add(1, std::memory_order_relaxed);
    }

    static std::uint32_t get_orig_requested_event_types(cache_rce_storage& s) {
        return s.m_orig_requested_event_types;
    }

private:
    const bool m_delay_fd_on_close;

    // TODO: implement LRU cache with time-based priority queue.
    //       implement clearing the cache when mount point picture changes.
    entries_t m_entries;
    std::vector<entries_t::node_type> m_entry_internal_cache;
    std::shared_mutex m_entry_mutex;
    std::atomic<unsigned long> m_entries_ver{1};
    std::atomic<unsigned> m_generation{1};

    bool remove_cache_entry(key_t key, unsigned long& current_change_version);
};

// single-threaded wrapper around multi-threaded cache entry
class l2_cache::cache_entry {
public:
    cache_entry(cache_entry&& r) noexcept
        : m_parent(r.m_parent)
        , m_key(r.m_key)
        , m_dev_last_change_seq_num(r.m_dev_last_change_seq_num)
        , m_entry_ptr(r.m_entry_ptr)
        , m_entries_ver(r.m_entries_ver) {
        r.m_entry_ptr = nullptr;
    }

    ~cache_entry() {
        if (m_entry_ptr)
            m_entry_ptr->m_del_lock_count.fetch_sub(1, std::memory_order_release);
    }

    rce get_cache_entry_for_receiver(unsigned subscr_id, cache_rce_storage&, fs_event_type);

private:
    friend cache_entry l2_cache::get_cache_entry(dev_t, ino_t, unsigned, std::time_t);
    friend rce;

    l2_cache& m_parent;
    const key_t m_key;
    const unsigned m_dev_last_change_seq_num;
    file_entry_data* m_entry_ptr = nullptr;
    unsigned long m_entries_ver = 0;
    std::time_t m_ctime;

    cache_entry(l2_cache& parent, key_t k, unsigned dev_last_change_seq_num, std::time_t ctime)
        : m_parent(parent)
        , m_key(k)
        , m_dev_last_change_seq_num(dev_last_change_seq_num)
        , m_ctime(ctime) {
    }

    // Look up on a file entry data; if found, lock it until this object is removed
    file_entry_data* get_entry_data();

    // Look up on a file entry data, create if not found; lock it until this object is removed
    file_entry_data* get_or_create_entry_data();

    void try_remove_binded_ce_data();

    bool is_file_entry_valid(const file_entry_data& v) const;
    void reinit_file_entry_if_need(file_entry_data& v) const;
};

inline auto l2_cache::get_cache_entry(dev_t dev, ino_t ino, unsigned dev_last_change_seq_num, std::time_t ctime)
    -> cache_entry {
    return {*this, key_t(dev, ino), dev_last_change_seq_num, ctime};
}

class l2_cache::rce {
public:
    enum class action_flag : std::uint8_t {
        cont = 1, delay_close_fd = 2
    };

    typedef utils::bit_flags<action_flag> action_flags_t;

    bool is_verdict_ready(verdict&) const;
    action_flags_t prepare_for_work();

    void set_verdict(verdict v);

private:
    l2_cache& m_parent;
    l2_cache::cache_entry& m_parent_ce;
    cache_rce_storage& m_rec_storage;
    const unsigned m_subscr_id;
    const fs_event_type m_ev_type;
    const key_t m_key;

    rce(l2_cache::cache_entry& parent_ce, cache_rce_storage& s,
        unsigned subscr_id, fs_event_type ev_type)
        : m_parent(parent_ce.m_parent)
        , m_parent_ce(parent_ce)
        , m_rec_storage(s)
        , m_subscr_id(subscr_id)
        , m_ev_type(ev_type)
        , m_key(m_parent_ce.m_key) {
    }

    friend rce cache_entry::get_cache_entry_for_receiver(unsigned, cache_rce_storage&, fs_event_type);
};

inline auto l2_cache::cache_entry::get_cache_entry_for_receiver(
        unsigned subscr_id, cache_rce_storage& s, fs_event_type ev_type) -> rce {
    return {*this, s, subscr_id, ev_type};
}

} // ns fan_interceptor
