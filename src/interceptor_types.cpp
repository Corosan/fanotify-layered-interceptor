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

#include "interceptor_types.h"
#include "interceptor_l1.h"
#include "interceptor_l2.h"

#include <system_error>
#include <atomic>

#include <unistd.h>
#include <fcntl.h>

namespace fan_interceptor::details {

fd_dup_holder::fd_dup_holder(const fd_dup_holder& r) {
    if (r.m_fd >= 0) {
        m_fd = ::fcntl(r.m_fd, F_DUPFD_CLOEXEC, r.m_fd);
        if (m_fd < 0) {
            auto e = errno;
            throw std::system_error(e, std::generic_category(),
                "unable to duplicate fd=" + std::to_string(r.m_fd));
        }
    }
}

void fd_dup_holder::close() noexcept {
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = -1;
}

struct fd_shared_holder::cb {
    int m_fd;
    std::atomic<int> m_ref;
};

fd_shared_holder::fd_shared_holder(int fd) {
    if (fd >= 0)
        m_cb = new cb{fd, 1};
}

fd_shared_holder::fd_shared_holder(const fd_shared_holder& r) noexcept
    : m_cb(r.m_cb) {
    if (m_cb)
        m_cb->m_ref.fetch_add(1, std::memory_order_relaxed);
}

int fd_shared_holder::release() noexcept {
    int t = m_cb ? m_cb->m_fd : -1;
    m_cb = nullptr;
    return t;
}

void fd_shared_holder::close() noexcept {
    if (m_cb) {
        if (m_cb->m_ref.fetch_sub(1, std::memory_order_relaxed) == 1) {
            ::close(m_cb->m_fd);
            delete m_cb;
        }
        m_cb = nullptr;
    }
}

int fd_shared_holder::handle() const noexcept {
    return m_cb ? m_cb->m_fd : -1;
}

} // ns fan_interceptor::details

namespace fan_interceptor {

std::unique_ptr<interceptor_l1> create_interceptor(const l1_params& params, mnt_namespace_detector_ptr p) {
    return std::make_unique<interceptor_l1_impl>(params, std::move(p));
}

std::unique_ptr<mu_interceptor> create_mu_interceptor(
        const l2_params& params, std::unique_ptr<interceptor_l1> p) {
    if (! p)
        p = create_interceptor(params.m_l1_params);

    auto timer = std::make_shared<utils::thread_timer_executor>();
    timer->start();

    return std::make_unique<mu_interceptor_impl>(params, std::move(p), std::move(timer));
}

} // ns fan_interceptor
