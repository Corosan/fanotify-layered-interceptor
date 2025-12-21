#include "utils.h"
#include "interceptor_types.h"
#include "interceptor_l1.h"

#include <chrono>
#include <thread>
#include <iterator>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace {

using namespace fan_interceptor;
using namespace fan_interceptor::utils;

using namespace std::chrono_literals;

TEST(Utils, IntrusivePtr) {
    struct base_test_obj {
        int ref = 0;
        void add_ref() noexcept { ++ref; }
        void release() noexcept { --ref; }
    };

    struct der_test_obj : base_test_obj {
    } der_obj1;

    {
        der_obj1.ref = 1;
        intrusive_ptr<der_test_obj> p1{&der_obj1};
        intrusive_ptr<base_test_obj> p2{p1};

        EXPECT_EQ(der_obj1.ref, 2);
    }

    EXPECT_EQ(der_obj1.ref, 0);

    {
        der_obj1.ref = 0;
        intrusive_ptr<der_test_obj> p1{&der_obj1, intrusive_add_ref{}};
        intrusive_ptr<base_test_obj> p2{p1};

        EXPECT_EQ(der_obj1.ref, 2);
    }

    EXPECT_EQ(der_obj1.ref, 0);

    {
        der_obj1.ref = 0;
        intrusive_ptr<der_test_obj> p1{&der_obj1, intrusive_add_ref{}};
        intrusive_ptr<base_test_obj> p2{std::move(p1)};

        EXPECT_EQ(der_obj1.ref, 1);
        EXPECT_EQ(static_cast<bool>(p1), false);
    }

    EXPECT_EQ(der_obj1.ref, 0);
}

TEST(Utils, ToNumber) {
    unsigned char c;
    EXPECT_EQ(to_number_ref("10", c), num_conv_result::ok);
    EXPECT_EQ(c, 10);
    EXPECT_EQ(to_number_ref(" 11 ", c), num_conv_result::ok);
    EXPECT_EQ(c, 11);
    EXPECT_EQ(to_number_ref("255", c), num_conv_result::ok);
    EXPECT_EQ(c, 255);
    EXPECT_EQ(to_number_ref("256", c), num_conv_result::overflow);
    EXPECT_EQ(to_number_ref("-12", c), num_conv_result::garbage);

    int n;
    EXPECT_EQ(to_number_ref("-1000", n), num_conv_result::ok);
    EXPECT_EQ(n, -1000);
    EXPECT_EQ(to_number<int>("0x12", 16), 18);
}

TEST(Utils, ToString) {
    char buf[128];
    EXPECT_EQ(utils::to_string(45u, buf), buf + 2);
    EXPECT_STREQ(buf, "45");
    EXPECT_EQ(utils::to_string(-128L, buf), buf + 4);
    EXPECT_STREQ(buf, "-128");
    EXPECT_EQ(utils::to_string((unsigned char)-1, buf), buf + 3);
    EXPECT_STREQ(buf, "255");
}

MATCHER_P(GenSequence, s, "equal sequences") {
    auto s_it = std::cbegin(arg);
    auto d_it = std::cbegin(s);
    std::size_t pos = 0;

    while (true) {
        if (s_it == std::end(arg) && d_it == std::end(s))
            return true;

        if (s_it != std::end(arg) && d_it == std::end(s)) {
            *result_listener << "source sequence is longer";
            return false;
        }

        if (s_it == std::end(arg) && d_it != std::end(s)) {
            *result_listener << "pattern sequence is longer";
            return false;
        }

        if (*s_it != *d_it) {
            *result_listener << '[' << *s_it << "] != [" << *d_it << "] at pos " << pos;
            return false;
        }

        ++s_it;
        ++d_it;
        ++pos;
    }
}

TEST(Utils, StringSplitter) {
    EXPECT_TRUE(string_splitter("", "").empty());
    EXPECT_TRUE(string_splitter("  ", " \t").empty());
    EXPECT_THAT(string_splitter("a,; b ", ",;"), GenSequence(std::vector{"a", " b "}));
    EXPECT_THAT(string_splitter(",a,; b ;", ",;"), GenSequence(std::vector{"a", " b "}));
}

TEST(DeferredDispatcher, BasicAssertions) {
    deferred_dispatcher disp;

    disp.dispatch(nullptr);

    int called = 0;

    disp.defer([&called](void*){ ++called; });
    disp.defer([&called](void*){ called += 5; });
    disp.dispatch(nullptr);
    EXPECT_EQ(called, 6);

    disp.dispatch(nullptr);
    EXPECT_EQ(called, 6);

    auto m1 = [&called](void*){ ++called; };
    auto cb = disp.defer(m1);
    disp.cancel(cb);
    disp.dispatch(nullptr);
    EXPECT_EQ(called, 6);

    disp.defer(m1);
    disp.dispatch(nullptr);
    EXPECT_EQ(called, 7);

    disp.dispatch(nullptr);
    EXPECT_EQ(called, 7);

    cb = disp.defer([&called, &cb, &disp](void*){ ++called; disp.cancel(cb); });
    disp.dispatch(nullptr);
    EXPECT_EQ(called, 8);

    disp.dispatch(nullptr);
    EXPECT_EQ(called, 8);
}

// TODO: don't like timed tests, need to use synthetic time. But let's do it this way so far...

TEST(DeferredDispatcher, WaitOnCancelling) {
    deferred_dispatcher disp;

    auto cb = disp.defer([](void*){ std::this_thread::sleep_for(1s); });
    std::thread t{[&disp]{ disp.dispatch(nullptr); }};

    std::this_thread::sleep_for(100ms);
    auto t1 = std::chrono::steady_clock::now();
    disp.cancel(cb);
    EXPECT_GE(std::chrono::steady_clock::now() - t1, 500ms);

    t.join();
}

TEST(Reactor, Deferred) {
    reactor r;

    std::atomic<int> cycles, called;
    atomic_init(&cycles, 0);
    atomic_init(&called, 0);

    std::thread t{[&cycles, &r]{ while (r.poll(nullptr)) cycles.fetch_add(1); }};

    std::this_thread::sleep_for(100ms);
    auto c1 = cycles.load();
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(c1, cycles.load());

    r.defer([&called](void*){ called++; });
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(c1 + 1, cycles.load());
    EXPECT_EQ(1, called.load());

    r.enable(false);
    t.join();
}


// TODO: I think it can be better from occupied size point of view
static_assert(sizeof(small_vector<int, 1>) <= sizeof(void*) * 3);
static_assert(sizeof(small_vector<int, 4>) <= sizeof(void*) * 3);

TEST(Vector, Basic) {
    small_vector<int, 4> v;

    EXPECT_EQ(v.empty(), true);
    EXPECT_EQ(v.size(), 0);
    EXPECT_EQ(v.capacity(), 4);

    v.push_back(3);
    EXPECT_EQ(v.empty(), false);
    EXPECT_EQ(v.size(), 1);
    EXPECT_EQ(v.capacity(), 4);
    EXPECT_EQ(v[0], 3);
    EXPECT_EQ(*v.begin(), 3);
    EXPECT_EQ(v.begin() + 1, v.end());

    v.push_back(4);
    v.push_back(5);
    EXPECT_EQ(v.size(), 3);
    EXPECT_EQ(v[2], 5);

    v.push_back(6);
    EXPECT_EQ(v.size(), 4);
    EXPECT_EQ(v.capacity(), 4);

    {
        auto v2 = v;
        EXPECT_EQ(v.size(), 4);
        EXPECT_EQ(v.capacity(), 4);
        EXPECT_EQ(v[3], 6);
    }

    v.push_back(7);
    EXPECT_EQ(v[0], 3);
    EXPECT_EQ(v[4], 7);
    EXPECT_EQ(v.size(), 5);
    EXPECT_EQ(v.capacity(), 8);

    v.push_back(8);
    EXPECT_EQ(v.size(), 6);
    EXPECT_EQ(v[5], 8);

    {
        auto v2 = v;
        EXPECT_EQ(v.size(), 6);
        EXPECT_EQ(v.capacity(), 8);
        EXPECT_EQ(v[5], 8);
    }
}

struct test_obj {
    static int objs_count;
    int id;
    test_obj(int i) : id(i) { ++objs_count; }
    test_obj(test_obj&& r) : id(r.id) { ++objs_count; }
    test_obj& operator=(test_obj&&) = delete;
    ~test_obj() { --objs_count; }
};

int test_obj::objs_count = 0;

TEST(Vector, Objects) {
    small_vector<test_obj, 4> v;

    v.push_back({2});
    v.push_back({3});
    v.push_back({4});
    v.push_back({5});
    v.push_back({6});
    v.insert(v.begin(), {1});
    EXPECT_EQ(v[0].id, 1);
    EXPECT_EQ(v[4].id, 5);
    EXPECT_EQ(v.capacity(), 8);

    {
        auto v2 = std::move(v);
        EXPECT_EQ(v2[0].id, 1);
        EXPECT_EQ(v2[4].id, 5);
        EXPECT_EQ(v2.capacity(), 8);
        EXPECT_EQ(v2.size(), 6);
        EXPECT_EQ(v2.back().id, 6);

        v2.pop_back();
        EXPECT_EQ(v2.size(), 5);
        EXPECT_EQ(v2.back().id, 5);

        EXPECT_EQ(v.size(), 0);
        EXPECT_EQ(v.capacity(), 4);
    }

    EXPECT_EQ(test_obj::objs_count, 0);
}

TEST(BitFields, Basic) {
    enum class test_flags {
        f1 = 0x01,
        f2 = 0x02
    };

    bit_flags<test_flags> bfs;

    EXPECT_EQ(false, static_cast<bool>(bfs));

    bfs |= test_flags::f1;
    EXPECT_EQ(1, static_cast<int>(bfs));

    auto bfs2 = bfs | test_flags::f2;
    EXPECT_EQ(3, static_cast<int>(bfs2));
    static_assert(std::is_same<decltype(bfs2), decltype(bfs)>::value);

    bfs2 &= ~bit_flags<test_flags>(test_flags::f1);
    EXPECT_EQ(2, static_cast<int>(bfs2));

    EXPECT_TRUE(bfs2 & test_flags::f2);
    EXPECT_TRUE(test_flags::f2 == bfs2);
    EXPECT_FALSE(bfs2 & test_flags::f1);
}

TEST(PollingTimer, Basic) {
    typedef polling_timer_executor::time_point_t tp_t;

    int replan_counter = 0;
    polling_timer_executor pt{[&replan_counter]{ ++replan_counter; }};

    // Expecting that next returned time point to re-check is {infinity} if there is no
    // any task yet in the timer object.
    EXPECT_EQ(tp_t::max(), pt.execute([]{ return tp_t{1s}; }));

    int task1_count = 0, task2_count = 0, task3_count = 0;
    /*task1_id = */ pt.post_single_shot_task([&task1_count, &pt]{
        ++task1_count;
        pt.post_single_shot_task([&task1_count]{ task1_count += 100; }, tp_t{0s});
    }, tp_t{4s});
    /*task2_id = */ pt.post_single_shot_task([&task2_count]{ ++task2_count; }, tp_t{2s});
    int task3_id = pt.post_single_shot_task([&task3_count]{ ++task3_count; }, tp_t{3s});

    EXPECT_EQ(tp_t{2s}, pt.execute([]{ return tp_t{1500ms}; }));
    EXPECT_EQ(0, task1_count);
    EXPECT_EQ(0, task2_count);

    pt.cancel_task(task3_id);

    EXPECT_EQ(tp_t{4s}, pt.execute([]{ return tp_t{2500ms}; }));
    EXPECT_EQ(0, task1_count);
    EXPECT_EQ(1, task2_count);

    EXPECT_EQ(tp_t::max(), pt.execute([]{ return tp_t{5s}; }));
    EXPECT_EQ(101, task1_count);
    EXPECT_EQ(1, task2_count);

    // Replan callback is called only when some task with the earliest execution time is added.
    // Here we've added {4 sec exec time} task which was first. Than we've added {2 sec exec time}
    // task.
    EXPECT_EQ(2, replan_counter);
    EXPECT_EQ(0, task3_count);  // the task actually was never executed cause it has been cancelled
}

TEST(PollingTimer, RepeatTask) {
    typedef polling_timer_executor::time_point_t tp_t;

    int replan_counter = 0;
    polling_timer_executor pt{[&replan_counter]{ ++replan_counter; }};

    int task1_count = 0, task2_count = 0;
    pt.post_single_shot_task([&task1_count]{ ++task1_count; }, tp_t{4500ms});

    EXPECT_EQ(1, replan_counter);

    EXPECT_EQ(tp_t{4500ms}, pt.execute([]{ return tp_t{1s}; }));

    int task2_id = pt.post_repeat_task([&task2_count]{ ++task2_count; }, 1s);

    EXPECT_EQ(2, replan_counter);

    EXPECT_EQ(tp_t{3s}, pt.execute([]{ return tp_t{2s}; }));
    EXPECT_EQ(tp_t{3s}, pt.execute([]{ return tp_t{2500ms}; }));

    EXPECT_EQ(0, task1_count);
    EXPECT_EQ(1, task2_count);

    EXPECT_EQ(tp_t{4s}, pt.execute([]{ return tp_t{3s}; }));

    EXPECT_EQ(0, task1_count);
    EXPECT_EQ(2, task2_count);

    pt.cancel_task(task2_id);

    EXPECT_EQ(2, replan_counter);

    EXPECT_EQ(tp_t{4500ms}, pt.execute([]{ return tp_t{4s}; }));

    EXPECT_EQ(0, task1_count);
    EXPECT_EQ(2, task2_count);

    EXPECT_EQ(tp_t::max(), pt.execute([]{ return tp_t{5s}; }));

    EXPECT_EQ(1, task1_count);
    EXPECT_EQ(2, task2_count);
    EXPECT_EQ(2, replan_counter);
}

TEST(ThreadTimer, Basic) {
    thread_timer_executor pt;

    pt.start();

    int task1_count = 0, task2_count = 0;
    pt.post_single_shot_task([&task1_count](){ ++task1_count; },
        std::chrono::steady_clock::now() + 1s);
    pt.post_single_shot_task([&task2_count](){ ++task2_count; },
        std::chrono::steady_clock::now() + 2s);

    std::this_thread::sleep_for(1500ms);

    auto t1 = std::chrono::steady_clock::now();
    pt.stop();

    EXPECT_GE(400ms, std::chrono::steady_clock::now() - t1);
    EXPECT_EQ(1, task1_count);
    EXPECT_EQ(0, task2_count);
}

} // ns anonymous
