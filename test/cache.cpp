#include "utils.h"
#include "interceptor_types.h"
#include "interceptor_l2.h"
#include "l2_cache.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <cstdint>
#include <optional>

namespace {

using namespace ::fan_interceptor;
using namespace ::fan_interceptor::utils;

TEST(L2Cache, Basic) {
    l2_cache c{true};

    auto identity_mask = [](std::uint32_t v){ return v; };
    cache_rce_storage rce_storage;

    std::uint32_t req_ev_types = (std::uint32_t)fs_event_type::open_perm;
    c.on_subscribe(rce_storage, req_ev_types, identity_mask);

    EXPECT_EQ(
        (std::uint32_t)fs_event_type::open_perm
        | (std::uint32_t)fs_event_type::modify
        | (std::uint32_t)fs_event_type::close
        | (std::uint32_t)fs_event_type::close_modified,
        req_ev_types);

    std::optional<l2_cache::rce> rce1, rce2;

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce1.emplace(std::move(rce));
        }

        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 5, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce2.emplace(std::move(rce));
        }
    }

    // Next modification event coming. It must reset all cache state for this dev/inode
    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::modify);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_FALSE(rce.prepare_for_work());
        }
    }

    rce1->set_verdict(verdict::allow);
    rce2->set_verdict(verdict::allow);
    rce1.reset();
    rce2.reset();

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce1.emplace(std::move(rce));
        }

        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 5, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce2.emplace(std::move(rce));
        }
    }

    rce1->set_verdict(verdict::allow);
    rce2->set_verdict(verdict::deny);
    rce1.reset();
    rce2.reset();

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v = verdict::deny;
            EXPECT_EQ(true, rce.is_verdict_ready(v));
            EXPECT_EQ(verdict::allow, v);
        }

        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 5, rce_storage, fs_event_type::open_perm);

            verdict v = verdict::allow;
            EXPECT_EQ(true, rce.is_verdict_ready(v));
            EXPECT_EQ(verdict::deny, v);
        }
    }

    // Device mount state changed - the cache entry should be reset again
    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 13, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce1.emplace(std::move(rce));
        }
    }

    rce1->set_verdict(verdict::allow);
    rce1.reset();

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 13, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v = verdict::deny;
            EXPECT_EQ(true, rce.is_verdict_ready(v));
            EXPECT_EQ(verdict::allow, v);
        }
    }

    // ctime changed - reset the cache entry again
    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 13, /*ctime*/ 112);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());
        }
    }
}

TEST(L2Cache, Invalidate)
{
    l2_cache c{true};

    std::optional<l2_cache::rce> rce1, rce2, rce3;
    auto identity_mask = [](std::uint32_t v){ return v; };
    cache_rce_storage rce_storage;

    std::uint32_t req_ev_types = (std::uint32_t)fs_event_type::open_perm;
    c.on_subscribe(rce_storage, req_ev_types, identity_mask);

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce1.emplace(std::move(rce));
        }

        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 5, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce2.emplace(std::move(rce));
        }
    }

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 101, /*dev_change*/ 12, /*ctime*/ 112);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
            EXPECT_EQ(l2_cache::rce::action_flag::cont, rce.prepare_for_work());

            rce3.emplace(std::move(rce));
        }
    }

    rce1->set_verdict(verdict::allow);
    rce2->set_verdict(verdict::deny);
    rce3->set_verdict(verdict::allow);
    rce1.reset();
    rce2.reset();
    rce3.reset();

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v = verdict::deny;
            EXPECT_EQ(true, rce.is_verdict_ready(v));
            EXPECT_EQ(verdict::allow, v);
        }

        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 5, rce_storage, fs_event_type::open_perm);

            verdict v = verdict::allow;
            EXPECT_EQ(true, rce.is_verdict_ready(v));
            EXPECT_EQ(verdict::deny, v);
        }
    }

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 101, /*dev_change*/ 12, /*ctime*/ 112);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v = verdict::deny;
            EXPECT_EQ(true, rce.is_verdict_ready(v));
            EXPECT_EQ(verdict::allow, v);
        }
    }

    c.invalidate();

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 100, /*dev_change*/ 12, /*ctime*/ 111);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
        }

        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 5, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
        }
    }

    {
        auto ce = c.get_cache_entry(/*dev_id*/ 1, /*node_id*/ 101, /*dev_change*/ 12, /*ctime*/ 112);
        {
            auto rce = ce.get_cache_entry_for_receiver(/*subscr_id*/ 4, rce_storage, fs_event_type::open_perm);

            verdict v;
            EXPECT_EQ(false, rce.is_verdict_ready(v));
        }
    }

}

} // ns anonymous
