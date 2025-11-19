#include "utils.h"
#include "interceptor_types.h"
#include "interceptor_l2.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <cstring>
#include <variant>
#include <deque>
#include <thread>
#include <chrono>
#include <initializer_list>
#include <algorithm>
#include <type_traits>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

namespace {

using namespace ::fan_interceptor;
using namespace ::fan_interceptor::utils;

class mt_barrier final {
public:
    void inc() {
        std::lock_guard l{m_mutex};
        ++m_check_point;
        m_cv.notify_all();
    }

    // Wait until the mt_barrier walks through a check point {min(cps) - 1} and increment state.
    // Thus the object can walk through cp N+1 only after passing cp N.
    bool check_point(std::initializer_list<int> cps,
            std::chrono::seconds timeout = std::chrono::seconds{10}) {
        std::unique_lock l{m_mutex};
        if (m_check_point >= min(cps))
            return false;
        if (m_cv.wait_for(l, timeout, [this, cps]{
                return std::any_of(cps.begin(), cps.end(), [this](int v){
                    return v == m_check_point + 1;
                });
            })) {
            ++m_check_point;
            m_cv.notify_all();
            return true;
        }
        return false;
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    int m_check_point = 0;
};

class l1_mock : public interceptor_l1 {
    l1_mock** m_me_ptr;

public:
    l1_mock(l1_mock** me_ptr = nullptr) : m_me_ptr(me_ptr) {
        if (m_me_ptr)
            *m_me_ptr = this;
    }

    ~l1_mock() {
        if (m_me_ptr)
            *m_me_ptr = nullptr;
    }

    MOCK_METHOD(void, set_client, (l1_client*), (override));
    MOCK_METHOD(void, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(void, request_update_masks_async, (::ino_t, void*), (override));
    MOCK_METHOD(void, request_update_masks, (std::optional<::ino_t>, void*), (override));
    MOCK_METHOD(void, post_verdict, (::ino_t, int, verdict), (override));
};

class subscriber_mock : public mu_subscriber {
public:
    explicit subscriber_mock(std::string name = "subscriber mock")
        : m_name{std::move(name)} {
    }

    MOCK_METHOD(void, on_fs_event, (fs_event_ptr), (override));
    std::string_view name() override { return m_name; }

private:
    std::string m_name;
};

class trivial_timer_mock : public trivial_timer {
    MOCK_METHOD(int, post_single_shot_task, (cb_t, time_point_t), (override));
    MOCK_METHOD(int, post_repeat_task, (cb_t, time_point_t::duration), (override));
    MOCK_METHOD(void, cancel_task, (int), (override));
    MOCK_METHOD(void, cancel_all, (), (override));
};

class thread_worker final {
public:
    void start(interceptor_l1::l1_client *l1_c) {
        this->l1_c = l1_c;
        runner = std::thread{[this]{ run(); }};
    }

    void stop() {
        put_cmd(cmd_quit{});
        runner.join();
    }

    void exec_async(std::function<void()> f) {
        put_cmd(cmd_func{std::move(f)});
    }

    void* get_thread_ctx() const {
        return thread_ctx;
    }

private:
    void* thread_ctx = nullptr;
    std::thread runner;
    interceptor_l1::l1_client* l1_c;

    struct cmd_quit {};
    struct cmd_func { std::function<void()> f; };
    typedef std::variant<cmd_quit, cmd_func> queue_item_t;

    std::deque<queue_item_t> cmd_queue;
    std::mutex cmd_mutex;
    std::condition_variable cmd_cv;

    queue_item_t get_cmd() {
        std::unique_lock l{cmd_mutex};
        queue_item_t res;
        cmd_cv.wait(l, [&res, this]{
            if (cmd_queue.empty())
                return false;
            res = std::move(cmd_queue.front());
            cmd_queue.pop_front();
            return true;
        });
        return res;
    }

    void put_cmd(queue_item_t c) {
        std::lock_guard l{cmd_mutex};
        cmd_queue.push_back(std::move(c));
        cmd_cv.notify_all();
    }

    void run() {
        l1_c->thread_started(&thread_ctx);

        while (true) {
            queue_item_t c = get_cmd();
            if (std::get_if<cmd_quit>(&c))
                break;
            if (auto pv = std::get_if<cmd_func>(&c))
                pv->f();
        }

        l1_c->thread_finishing(thread_ctx);
    }
};

const l2_params g_common_l2_params{{}, /*delay_fd*/ false, /*print stat*/ false};


TEST(Layer2, StartStopEmptyProcessEvents) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    EXPECT_NE(l1_m_ptr, nullptr);

    interceptor_l1::l1_client* l1_c = nullptr;
    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    {
        mu_interceptor_impl iceptor{
            g_common_l2_params,
            std::move(l1_m),
            std::make_unique<StrictMock<trivial_timer_mock>>()};

        void* thread_ctx = nullptr;
        EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
        iceptor.start();

        l1_c->on_fs_event(thread_ctx, l1_fs_event{(std::uint32_t)fs_event_type::open, fd_holder{}});
        EXPECT_EQ(iceptor.get_processed_events_count(thread_ctx), 0);
        EXPECT_EQ(iceptor.get_failed_events_count(thread_ctx), 1);
        EXPECT_EQ(iceptor.get_event_cache_size(thread_ctx), 0);
        EXPECT_EQ(iceptor.get_event_nursing_home_size(), 0);

        l1_c->on_fs_event(thread_ctx, l1_fs_event{
            (std::uint32_t)fs_event_type::open, fd_holder{::open("/proc/self/exe", O_RDONLY)}});
        EXPECT_EQ(iceptor.get_processed_events_count(thread_ctx), 1);
        EXPECT_EQ(iceptor.get_failed_events_count(thread_ctx), 1);
        EXPECT_EQ(iceptor.get_event_cache_size(thread_ctx), 1);
        EXPECT_EQ(iceptor.get_event_nursing_home_size(), 0);

        EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_finishing(thread_ctx); });
        iceptor.stop();

        // Previous event has completely handled so it's skeleton doesn't go to a nursing home
        EXPECT_EQ(iceptor.get_event_nursing_home_size(), 0);
        EXPECT_NE(l1_m_ptr, nullptr);
    }

    EXPECT_EQ(l1_m_ptr, nullptr);
}

TEST(Layer2, SubscribeUnsubscribe) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));
    EXPECT_CALL(*l1_m_ptr, request_update_masks).WillRepeatedly([&l1_c](auto, auto ctx){
            l1_c->update_masks_done(ctx);
        });

    // Try to subscribe while the interceptor is not started yet
    {
        mu_interceptor_impl iceptor{
            g_common_l2_params,
            std::move(l1_m),
            std::make_unique<StrictMock<trivial_timer_mock>>()};
        iceptor.subscribe(subscr, {});
        EXPECT_EQ(iceptor.unsubscribe(subscr), true);
    }

    l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));
    EXPECT_CALL(*l1_m_ptr, request_update_masks).WillRepeatedly([&l1_c](auto a1, auto ctx){
            l1_c->update_masks_done(ctx);
        });

    // Try to subscribe after the interceptor started
    {
        mu_interceptor_impl iceptor{
            g_common_l2_params,
            std::move(l1_m),
            std::make_unique<StrictMock<trivial_timer_mock>>()};

        void* thread_ctx = nullptr;
        EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
        iceptor.start();

        iceptor.subscribe(subscr, {});

        EXPECT_EQ(iceptor.unsubscribe(subscr), true);

        EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_finishing(thread_ctx); });
        iceptor.stop();
    }
}

MATCHER_P(IsSameFile, path, "") {
    struct ::stat st_path, st_in;
    if (::stat(path, &st_path) < 0) {
        *result_listener << "can't get stat for pattern path '" << path << '\'';
        return false;
    }

    if (::fstat(arg, &st_in) < 0) {
        *result_listener << "can't get stat for arg";
        return false;
    }

    if (st_path.st_dev != st_in.st_dev || st_path.st_ino != st_in.st_ino) {
        *result_listener << "arg not points to '" << path << '\'';
        return false;
    }
    return true;
}

TEST(Layer2, MultipleStartStopWithSubscriptions) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    EXPECT_CALL(*l1_m_ptr, request_update_masks).WillOnce([l1_c](auto opt_mnt_id, void* ctx){
            l1_c->update_masks_done(ctx);
        });
    iceptor.subscribe(subscr, {(std::uint32_t)fs_event_type::open});

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillRepeatedly([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(subscr, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
            // Pointer(Property("mnt_id", &fs_event::mnt_id, Eq(10)))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    EXPECT_CALL(mask_setter, Call(10, 0));
    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(thread_ctx);
    });
    iceptor.stop();

    // Start the interceptor again - the subscription is still alive
    EXPECT_CALL(*l1_m_ptr, start).WillRepeatedly([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(subscr, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        2,
        152,
        1000});

    // Instead of proper stopping the interceptor we just signal that one (and the only) thread
    // has been finished. It should be enough for clearing resources because all other needed
    // cleanup actions the interceptor must do itself.
    l1_c->thread_finishing(thread_ctx);
}

// Subscribe to one unblocking event type by one subscriber before starting
// the interceptor; 'find' a few mount points and issue a number of events
// of this type
TEST(Layer2, SubscribeUnblockingBeforeStart) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr, subscrNull;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    // Subscribe and start with getting some mount points after it
    EXPECT_CALL(*l1_m_ptr, request_update_masks)
        .Times(2)
        .WillRepeatedly([l1_c](auto opt_mnt_id, void* ctx){
            l1_c->update_masks_done(ctx);
        });
    iceptor.subscribe(subscr, {(std::uint32_t)fs_event_type::open});
    iceptor.subscribe(subscrNull, {(std::uint32_t)fs_event_type::access});

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 11, "/boot", mask_setter.AsStdFunction());

    // Actually too strict checking that at one step the first subscriber is handled and we
    // get partial event type bits set. The only thing we need to know is that open|access types
    // are selected eventually
    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(10,
        (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::access));
    EXPECT_CALL(mask_setter, Call(11,
        (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::access));
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    // Two sequential notify-only events - must reuse the same skeleton for event delivery
    EXPECT_CALL(subscr, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    EXPECT_CALL(subscr, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(153))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        2,
        153,
        1001});

    // Ignored because this event type is not interesting
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::close,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        22,
        153,
        1002});

    EXPECT_CALL(subscr, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(3))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(153))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile(".")))
        ))).WillOnce(Throw(std::exception{}));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open(".", O_RDONLY)},
        3,
        153,
        1003});

    // Though the last delivery ends up with throwing an exception from a subscriber, we still
    // believe that the event has been processed successfully, because "failed event" is a
    // layer 1 event which even wasn't delivered to any subscriber (an exception in the internal
    // code of a delivery cycle, not in a subscriber).
    EXPECT_EQ(iceptor.get_processed_events_count(thread_ctx), 4);
    EXPECT_EQ(iceptor.get_failed_events_count(thread_ctx), 0);
    EXPECT_EQ(iceptor.get_event_cache_size(thread_ctx), 1);

    // It's expected that on unsubscribing the layer 2 will request to update fanotify masks for
    // all namespaces. But this test scenario assumes registering for 152 mount namespace id
    // only.
    EXPECT_CALL(*l1_m_ptr, request_update_masks(Eq(std::nullopt), _))
        .WillOnce([l1_c, &mask_setter](auto opt_mnt_id, void* ctx){
            l1_c->update_masks(/*nsid*/ 152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });
    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::access));
    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::access));
    EXPECT_EQ(iceptor.unsubscribe(subscr), true);

    // This event will not be delivered to anybody.
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open(".", O_RDONLY)},
        4,
        153,
        1003});

    EXPECT_EQ(iceptor.get_processed_events_count(thread_ctx), 5);
    EXPECT_EQ(iceptor.get_event_cache_size(thread_ctx), 1);

    // When all mounts have gone, Layer2 must told explicitly that it's not interested in them
    EXPECT_CALL(mask_setter, Call(10, 0));
    EXPECT_CALL(mask_setter, Call(11, 0));

    // The whole mount namespace with all its mount points should disappear on stopping. It's
    // not expected to call a mask setter because no need to touch a fanotify subsystem on
    // unmounting
    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 11, "/boot", mask_setter.AsStdFunction());
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(thread_ctx);
    });
    iceptor.stop();

    EXPECT_CALL(*l1_m_ptr, request_update_masks(Eq(std::nullopt), _))
        .WillOnce([l1_c](auto opt_mnt_id, void* ctx){
            l1_c->update_masks_done(ctx);
        });
    EXPECT_EQ(iceptor.unsubscribe(subscrNull), true);
}

// Subscribe to a few unblocking events after starting the interceptor; 'find' a few mount points.
// Check that each subscriber receives only required event. Check also that only right mount points
// affect corresponding subscribers.
//
// Mount points: m-a) '/'; m-b) '/boot'
// Subscribers for paths: s-a) '/usr'; s-b) '/boot/vg1'; s-c) '/'
//
// [s-a] is interested in [m-a]
// [s-b] is interested in [m-b]
// [s-c] is interested in [m-a] and [m-b]
//
// Later another mount point [m-c] '/boot/vg1' comes:
// [s-b] leaves [m-b] and becomes to be interested in [m-c]
// [s-c] is additionally interested in [m-c]
//
// Later another mount point [m-d] '/boot/vg1/dev1' comes:
// [s-b] is additionally interested in [m-d]
// [s-c] is additionally interesed in [m-d]
//
// Later [m-d] disappears. [s-b] and [s-c] become not interesed in it
// Later [m-c] disappears. [s-c] leaves it. [s-b] leaves it also and also returns to
// observing [m-b].
TEST(Layer2, SubscribeUnblockingAfterStart) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscrForOpen_A, subscrForModify_B, subscrForModify_C;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    // Mount points: m-a) '/'; m-b) '/boot'
    // Subscribers for paths: s-a) '/usr'; s-b) '/boot/vg1'; s-c) '/'
    //
    // [s-a] is interested in [m-a]
    // [s-b] is interested in [m-b]
    // [s-c] is interested in [m-a] and [m-b]
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 11, "/boot", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(*l1_m_ptr, request_update_masks(Eq(std::nullopt), _))
        .WillRepeatedly([l1_c, &mask_setter](auto opt_mnt_id, void* ctx){
            l1_c->update_masks(152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::modify));
    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify));
    iceptor.subscribe(subscrForOpen_A, {(std::uint32_t)fs_event_type::open, "/usr"});
    iceptor.subscribe(subscrForModify_B, {(std::uint32_t)fs_event_type::modify, "/boot/vg1"});
    iceptor.subscribe(subscrForModify_C, {(std::uint32_t)fs_event_type::modify});

    EXPECT_CALL(subscrForOpen_A, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(4))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
            // Pointer(Property("mnt_id", &fs_event::mnt_id, Eq(10)))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/usr/bin", O_RDONLY)},
        4,
        152,
        1001});

    EXPECT_CALL(subscrForModify_C, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::modify,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    // Later another mount point [m-c] '/boot/vg1' comes:
    //
    // [s-b] leaves [m-b] and becomes to be interested in [m-c]
    // [s-c] is additionally interested in [m-c]
    EXPECT_CALL(mask_setter, Call(12, (std::uint32_t)fs_event_type::modify));
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 12, "/boot/vg1", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    // Let's remove 'modify' subscription for mp='/' for a while
    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(11, 0));
    EXPECT_EQ(iceptor.unsubscribe(subscrForModify_C), true);
    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify));
    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::modify));
    iceptor.subscribe(subscrForModify_C, {(std::uint32_t)fs_event_type::modify});

    // Later another mount point [m-d] '/boot/vg1/dev1' comes:
    //
    // [s-b] is additionally interested in [m-d]
    // [s-c] is additionally interesed in [m-d]
    EXPECT_CALL(mask_setter, Call(13, (std::uint32_t)fs_event_type::modify));
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 13, "/boot/vg1/dev1", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(subscrForOpen_A, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        )));
    EXPECT_CALL(subscrForModify_C, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        )));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify,
        fd_holder{::open("/usr/bin", O_RDONLY)},
        2,
        152,
        1000});

    // Later [m-d] disappears. [s-b] and [s-c] become not interesed in it
    // Later [m-c] disappears. [s-c] leaves it. [s-b] leaves it also and also returns to
    // observing [m-b].
    EXPECT_CALL(mask_setter, Call(13, 0));
    EXPECT_CALL(mask_setter, Call(12, 0));
    l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 13, "/boot/vg1/dev1", mask_setter.AsStdFunction());
    l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 12, "/boot/vg1", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx, &mask_setter]{
            l1_c->on_umount(152, /*dev_id*/ 1, /*mount_id*/ 11, "/boot", mask_setter.AsStdFunction());
            l1_c->on_umount(152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(thread_ctx);
        });
    EXPECT_CALL(mask_setter, Call(_, _));
    EXPECT_CALL(mask_setter, Call(10, 0));
    EXPECT_CALL(mask_setter, Call(11, 0));
    iceptor.stop();
}

TEST(Layer2, BlockingUnblocking) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscrForOpen_A, subscrForOpen_B, subscrForOpenPerm_C,
        subscrForModify_D;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 11, "/usr", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(*l1_m_ptr, request_update_masks(Eq(std::nullopt), _))
        .WillRepeatedly([l1_c, &mask_setter](auto opt_mnt_id, void* ctx){
            l1_c->update_masks(152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify));
    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify));
    iceptor.subscribe(subscrForOpen_A, {(std::uint32_t)fs_event_type::open, {}, false});
    iceptor.subscribe(subscrForOpen_B, {(std::uint32_t)fs_event_type::open, "/usr", false});
    iceptor.subscribe(subscrForModify_D, {(std::uint32_t)fs_event_type::modify, {}, false});

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open_perm | (std::uint32_t)fs_event_type::modify));
    iceptor.subscribe(subscrForOpenPerm_C, {(std::uint32_t)fs_event_type::open_perm, "/dev", false});

    EXPECT_CALL(subscrForOpen_A, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe"))),
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open)))
        )));

    fd_holder fdh1{::open("/proc/self/exe", O_RDONLY)};
    int fd1_orig = fdh1.handle();

    // Going to post perm event though no perm events have been requested for / mount point
    EXPECT_CALL(*l1_m_ptr, post_verdict(152, fd1_orig, verdict::allow));

    // 1 event
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        std::move(fdh1),
        1,
        152,
        1000});

    EXPECT_EQ(iceptor.get_processed_events_count(thread_ctx), 1);
    EXPECT_EQ(iceptor.get_failed_events_count(thread_ctx), 0);
    EXPECT_EQ(iceptor.get_event_cache_size(thread_ctx), 1);

    fdh1.reset(::open("/dev/dri", O_RDONLY));
    fd1_orig = fdh1.handle();

    EXPECT_CALL(subscrForModify_D, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
            Pointer(Property("fd", &fs_event::fd, Eq(fd1_orig))),
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::modify)))
        )));
    if (std::is_same<fd_holder, fan_interceptor::details::fd_dup_holder>::value) {
        EXPECT_CALL(subscrForOpen_A, on_fs_event(AllOf(
                Pointer(Property("pid", &fs_event::pid, Eq(1))),
                Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
                Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
                // See a description for the next EXPECT_CALL
                Pointer(Property("fd", &fs_event::fd, Ne(fd1_orig))),
                Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open)))
            )));
        EXPECT_CALL(subscrForOpenPerm_C, on_fs_event(AllOf(
                Pointer(Property("pid", &fs_event::pid, Eq(1))),
                Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
                Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
                // It's defined by design that permission event delivery is made before non-permission
                // one. An fd should be duplicated for all but the last event. Thus it must not be
                // equal to the original fd value. Moreover this statement assumes 'other'
                // non-permission events, not one derived from this one. Bear in mind that for instance
                // 'open' and 'open_perm' subscribers receive the only 'open_perm' fanotify original
                // event.
                Pointer(Property("fd", &fs_event::fd, Ne(fd1_orig))),
                Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm)))
            )));
    } else {
        EXPECT_CALL(subscrForOpen_A, on_fs_event(AllOf(
                Pointer(Property("pid", &fs_event::pid, Eq(1))),
                Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
                Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
                Pointer(Property("fd", &fs_event::fd, Eq(fd1_orig))),
                Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open)))
            )));
        EXPECT_CALL(subscrForOpenPerm_C, on_fs_event(AllOf(
                Pointer(Property("pid", &fs_event::pid, Eq(1))),
                Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
                Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
                Pointer(Property("fd", &fs_event::fd, Eq(fd1_orig))),
                Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm)))
            )));
    }

    EXPECT_CALL(*l1_m_ptr, post_verdict(152, fd1_orig, verdict::allow));

    std::cout << "fd_orig = " << fd1_orig << std::endl;

    // 2 event which is a merge of 2 events
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm | (std::uint32_t)fs_event_type::modify,
        std::move(fdh1),
        1,
        152,
        1000});

    EXPECT_EQ(iceptor.unsubscribe(subscrForOpen_A), true);

    fs_event_ptr fs_evt;
    EXPECT_CALL(subscrForOpenPerm_C, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm)))
        ))).WillOnce(Invoke([&fs_evt](auto e){ fs_evt = std::move(e); }));

    // 3 event
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        fd_holder{::open("/dev/dri", O_RDONLY)},
        2,
        152,
        1000});

    EXPECT_EQ(iceptor.get_processed_events_count(thread_ctx), 3);
    EXPECT_EQ(iceptor.get_failed_events_count(thread_ctx), 0);
    EXPECT_EQ(iceptor.get_event_cache_size(thread_ctx), 1);

    EXPECT_CALL(*l1_m_ptr, post_verdict(152, _, verdict::deny));
    fs_evt->post_verdict(verdict::deny);
    fs_evt.reset();

    EXPECT_CALL(subscrForOpenPerm_C, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(3))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/dev/dri"))),
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm)))
        ))).WillOnce(Invoke([&fs_evt](auto e){ fs_evt = std::move(e); }));
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        fd_holder{::open("/dev/dri", O_RDONLY)},
        3,
        152,
        1000});

    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 11, "/usr", mask_setter.AsStdFunction());
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(thread_ctx);
        });
    EXPECT_CALL(mask_setter, Call(_, _)).Times(2);
    EXPECT_CALL(mask_setter, Call(10, 0));
    EXPECT_CALL(mask_setter, Call(11, 0));
    iceptor.stop();

    EXPECT_EQ(iceptor.get_event_nursing_home_size(), 1);
}

// Strictly speaking, I can't check via public interface, which subscriber was bound to which
// mountpoint... directly. There is no public info available. But if different subscribers would
// have different event types requested, I can check, which event type is requested for which
// mountpoint.
TEST(Layer2, RightSelectionOfMountpoints) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr1, subscr2, subscr3, subscr4;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 11, "/dir1", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 12, "/dir1/sdir1", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 13, "/dir1/sdir2", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 14, "/dir1/sdir2/ssdir", mask_setter.AsStdFunction());
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 15, "/dir2", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(*l1_m_ptr, request_update_masks(Eq(std::nullopt), _))
        .WillRepeatedly([l1_c, &mask_setter](auto opt_mnt_id, void* ctx){
            l1_c->update_masks(152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });

    EXPECT_CALL(mask_setter, Call(11, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(12, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(13, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(14, (std::uint32_t)fs_event_type::open));
    EXPECT_CALL(mask_setter, Call(13, (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify));
    EXPECT_CALL(mask_setter, Call(14, (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify));
    EXPECT_CALL(mask_setter, Call(13,
        (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify | (std::uint32_t)fs_event_type::close));
    EXPECT_CALL(mask_setter, Call(14,
        (std::uint32_t)fs_event_type::open | (std::uint32_t)fs_event_type::modify | (std::uint32_t)fs_event_type::access));
    iceptor.subscribe(subscr1, {(std::uint32_t)fs_event_type::open, "/dir1"});
    iceptor.subscribe(subscr2, {(std::uint32_t)fs_event_type::modify, "/dir1/sdir2"});
    iceptor.subscribe(subscr3, {(std::uint32_t)fs_event_type::close, "/dir1/sdir2/ggg"});
    iceptor.subscribe(subscr4, {(std::uint32_t)fs_event_type::access, "/dir1/sdir2/ssdir"});

    // Instead of proper stopping the interceptor we just signal that one (and the only) thread
    // has been finished. It should be enough for clearing resources because all other needed
    // cleanup actions the interceptor must do itself.
    l1_c->thread_finishing(thread_ctx);
}

TEST(Layer2, UnsubscribeFromCallback) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr1, subscr2, subscr3;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    thread_worker other_worker;
    void *this_thread_ctx = nullptr;

    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &this_thread_ctx, &other_worker]{
        l1_c->thread_started(&this_thread_ctx);
        other_worker.start(l1_c);
    });
    iceptor.start();

    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(*l1_m_ptr, request_update_masks(Eq(std::nullopt), _))
        .WillRepeatedly([l1_c, &mask_setter](auto opt_mnt_id, void* ctx){
            l1_c->update_masks(152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    iceptor.subscribe(subscr1, {(std::uint32_t)fs_event_type::open});
    iceptor.subscribe(subscr2, {(std::uint32_t)fs_event_type::open});

    mt_barrier barrier;
    std::atomic<int> order{0};

    // These events will be delivered in another thread
    EXPECT_CALL(subscr1, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(5))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        ))).WillOnce([&barrier, &order](auto){
            barrier.inc();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            order.fetch_add(1);
        });
    EXPECT_CALL(subscr2, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(5))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        )));

    // These events are delivered in this thread
    EXPECT_CALL(subscr1, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        ))).WillOnce([&iceptor, &subscr1, &subscr3, &order](fs_event_ptr){
            // This callback must start only after the same subscriber get called from another
            // thread (take a look at the latch operation).
            iceptor.unsubscribe(subscr1);
            int v = 1;
            // The next line must be called after another thread's callback finished
            order.compare_exchange_strong(v, 2);
            iceptor.subscribe(subscr3, {(std::uint32_t)fs_event_type::open});
        });
    EXPECT_CALL(subscr2, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        )));

    other_worker.exec_async([l1_c, &other_worker]{
        l1_c->on_fs_event(other_worker.get_thread_ctx(), l1_fs_event{
            (std::uint32_t)fs_event_type::open,
            fd_holder{::open("/usr/bin", O_RDONLY)},
            5,
            152,
            1000});
    });

    EXPECT_TRUE(barrier.check_point({2}));
    l1_c->on_fs_event(this_thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/usr/bin", O_RDONLY)},
        2,
        152,
        1000});

    EXPECT_EQ(order.load(), 2);

    EXPECT_CALL(subscr3, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(3))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        )));
    EXPECT_CALL(subscr2, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(3))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/usr/bin")))
        )));
    l1_c->on_fs_event(this_thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/usr/bin", O_RDONLY)},
        3,
        152,
        1001});

    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &this_thread_ctx, &other_worker, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(this_thread_ctx);
            other_worker.stop();
        });
    EXPECT_CALL(mask_setter, Call(10, 0));
    iceptor.stop();
}

TEST(Layer2, StopThreadWhileProcessingEvent) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    void *thread1_ctx, *thread2_ctx;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread1_ctx, &thread2_ctx]{
        l1_c->thread_started(&thread1_ctx);
        l1_c->thread_started(&thread2_ctx);
    });
    iceptor.start();

    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);


    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open_perm));

    EXPECT_CALL(*l1_m_ptr, request_update_masks)
        .WillRepeatedly([l1_c, &mask_setter](auto opt_mnt_id, void* ctx){
            l1_c->update_masks(/*nsid*/ 152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });
    iceptor.subscribe(subscr, {(std::uint32_t)fs_event_type::open_perm, "/", false});

    fs_event_ptr ev;

    EXPECT_CALL(subscr, on_fs_event(AllOf(
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )))
        .WillOnce([&ev](auto e){ ev = e; });

    l1_c->on_fs_event(thread1_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    l1_c->thread_finishing(thread1_ctx);

    EXPECT_EQ(1, iceptor.get_event_nursing_home_size());

    EXPECT_CALL(*l1_m_ptr, post_verdict(_, _, verdict::allow));
    ev->post_verdict(verdict::allow);

    ev.reset();

    EXPECT_EQ(0, iceptor.get_event_nursing_home_size());

    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, thread2_ctx, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(thread2_ctx);
        });
    EXPECT_CALL(mask_setter, Call(10, 0));
    iceptor.stop();
}

TEST(Layer2, Cache) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr1, subscr2;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    EXPECT_CALL(*l1_m_ptr, request_update_masks)
        .Times(2)
        .WillRepeatedly([l1_c](auto opt_mnt_id, void* ctx){
            l1_c->update_masks_done(ctx);
        });
    iceptor.subscribe(subscr1, {(std::uint32_t)fs_event_type::open_perm});
    iceptor.subscribe(subscr2, {(std::uint32_t)fs_event_type::open_perm});

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    EXPECT_CALL(mask_setter, Call(10,
        (std::uint32_t)fs_event_type::open_perm
        | (std::uint32_t)fs_event_type::modify
        | (std::uint32_t)fs_event_type::close_modified));
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(subscr1, on_fs_event(AllOf(
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm))),
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )))
        .WillOnce([](auto ev){ ev->post_verdict(verdict::allow, /*cache_it*/ true); });

    EXPECT_CALL(subscr2, on_fs_event(AllOf(
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm))),
            Pointer(Property("pid", &fs_event::pid, Eq(1))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )))
        .WillOnce([](auto ev){ ev->post_verdict(verdict::allow, /*cache_it*/ true); });

    EXPECT_CALL(*l1_m_ptr, post_verdict(152, _, verdict::allow)).Times(2);

    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    // Second time cached verdict must be used
    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::close_modified,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    EXPECT_CALL(subscr1, on_fs_event(AllOf(
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm))),
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )))
        .WillOnce([](auto ev){ ev->post_verdict(verdict::deny, /*cache_it*/ true); });

    EXPECT_CALL(subscr2, on_fs_event(AllOf(
            Pointer(Property("type", &fs_event::type, Eq(fs_event_type::open_perm))),
            Pointer(Property("pid", &fs_event::pid, Eq(2))),
            Pointer(Property("mnt_ns_id", &fs_event::mnt_ns_id, Eq(152))),
            Pointer(Property("fd", &fs_event::fd, IsSameFile("/proc/self/exe")))
        )))
        .WillOnce([](auto ev){ ev->post_verdict(verdict::allow, /*cache_it*/ true); });

    EXPECT_CALL(*l1_m_ptr, post_verdict(152, _, verdict::deny));

    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open_perm,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        2,
        152,
        1000});

    EXPECT_CALL(mask_setter, Call(10, 0));
    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(thread_ctx);
    });
    iceptor.stop();
}

// A subscription being deleted can be used concurently:
// 1. 'unsubscribe' is called
// 2. a specified subscription is marked with PENDING_DELETED flag. There is one outstanding
//    pointer P1 to an event referencing this subscription.
// 3. a lock around a subscriptions list is released
// 4. while the 'unsubscribe' sequence modifies fanotify masks via request_update_masks call
//    to L1, somebody releases P1. It yields to zero usage counter in a subscription object
//    and removing the latter consequently.
//
// This test has been added to check this scenario after the usage counter has been also used
// to lock the subscription object from deleting.
TEST(Layer2, UnsubscribeAndReleaseEventConcurrently) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr;
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    EXPECT_CALL(*l1_m_ptr, request_update_masks)
        .WillOnce([l1_c](auto, auto ctx){
            l1_c->update_masks_done(ctx);
        });

    iceptor.subscribe(subscr, {(std::uint32_t)fs_event_type::open});

    void* thread_ctx = nullptr;
    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &thread_ctx]{ l1_c->thread_started(&thread_ctx); });
    iceptor.start();

    EXPECT_CALL(mask_setter, Call(10, (std::uint32_t)fs_event_type::open));
    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    fs_event_ptr ev_ptr;
    EXPECT_CALL(subscr, on_fs_event(_)).WillOnce([&ev_ptr](auto p){ ev_ptr = p; });

    l1_c->on_fs_event(thread_ctx, l1_fs_event{
        (std::uint32_t)fs_event_type::open,
        fd_holder{::open("/proc/self/exe", O_RDONLY)},
        1,
        152,
        1000});

    EXPECT_CALL(mask_setter, Call(10, 0));
    EXPECT_CALL(*l1_m_ptr, request_update_masks)
        .WillOnce([l1_c, &ev_ptr, &mask_setter](auto, auto ctx){
            ev_ptr = {};
            l1_c->update_masks(/*nsid*/ 152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });

    iceptor.unsubscribe(subscr);

    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &thread_ctx, &mask_setter]{
        l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
        l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), true);
        l1_c->thread_finishing(thread_ctx);
    });
    iceptor.stop();
}

TEST(Layer2, DependentThreadsTracking) {
    using namespace ::testing;

    l1_mock* l1_m_ptr = nullptr;
    interceptor_l1::l1_client* l1_c = nullptr;
    auto l1_m = std::make_unique<StrictMock<l1_mock>>(&l1_m_ptr);

    StrictMock<subscriber_mock> subscr1{"subscr1"}, subscr2{"subscr2"};
    StrictMock<MockFunction<interceptor_l1::l1_client::mask_setter_t>> mask_setter;

    EXPECT_CALL(*l1_m_ptr, set_client).WillOnce(SaveArg<0>(&l1_c));

    mu_interceptor_impl iceptor{
        g_common_l2_params,
        std::move(l1_m),
        std::make_unique<StrictMock<trivial_timer_mock>>()};

    thread_worker w1, w2;
    void* this_thread_ctx = nullptr;

    EXPECT_CALL(*l1_m_ptr, start).WillOnce([&l1_c, &this_thread_ctx, &w1, &w2]{
        l1_c->thread_started(&this_thread_ctx);
        w1.start(l1_c);
        w2.start(l1_c);
    });
    iceptor.start();

    l1_c->on_mount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
    l1_c->mount_changes_done(/*nsid*/ 152, mask_setter.AsStdFunction(), false);

    EXPECT_CALL(*l1_m_ptr, request_update_masks)
        .WillRepeatedly([l1_c, &mask_setter](auto, auto ctx){
            l1_c->update_masks(152, ctx, mask_setter.AsStdFunction());
            l1_c->update_masks_done(ctx);
        });

    EXPECT_CALL(mask_setter, Call(10, _)).Times(2);
    iceptor.subscribe(subscr1, {(std::uint32_t)fs_event_type::open_exec});
    iceptor.subscribe(subscr2, {(std::uint32_t)fs_event_type::open});

    mt_barrier barrier;
    std::atomic<int> order{0};

    EXPECT_CALL(subscr1, on_fs_event).WillOnce([&barrier, &order](auto){
        EXPECT_TRUE(barrier.check_point({1}));
        std::this_thread::sleep_for(std::chrono::seconds(1));
        int v = 0;
        order.compare_exchange_strong(v, 1);
    });

    EXPECT_CALL(subscr2, on_fs_event).WillOnce([&iceptor, &subscr1, &barrier, &order](auto){
        EXPECT_TRUE(barrier.check_point({2}));
        iceptor.unsubscribe(subscr1);   // this call must block until an event handler
                                        // expressed in a statement above is not finished
        int v = 1;
        order.compare_exchange_strong(v, 2);
    });

    EXPECT_CALL(mask_setter, Call(10, _));
    EXPECT_CALL(mask_setter, Call(10, 0));

    w2.exec_async([l1_c, &w2]{
        l1_c->on_fs_event(w2.get_thread_ctx(), l1_fs_event{
            (std::uint32_t)fs_event_type::open,
            fd_holder{::open("/usr/bin", O_RDONLY)},
            5,
            152,
            1000});
    });

    w1.exec_async([l1_c, &w1]{
        l1_c->on_fs_event(w1.get_thread_ctx(), l1_fs_event{
            (std::uint32_t)fs_event_type::open_exec,
            fd_holder{::open("/usr/bin", O_RDONLY)},
            5,
            152,
            1000});
    });

    EXPECT_TRUE(barrier.check_point({3}));
    iceptor.unsubscribe(subscr2);
    EXPECT_EQ(order.load(), 2);

    EXPECT_CALL(*l1_m_ptr, stop).WillOnce([&l1_c, &this_thread_ctx, &w1, &w2, &mask_setter]{
            l1_c->on_umount(/*nsid*/ 152, /*dev_id*/ 1, /*mount_id*/ 10, "/", mask_setter.AsStdFunction());
            l1_c->mount_changes_done(152, mask_setter.AsStdFunction(), true);
            l1_c->thread_finishing(this_thread_ctx);
            w1.stop();
            w2.stop();
        });
    iceptor.stop();
}

} // ns anonymous
