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

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

class test_namespace_detector final : public fan_interceptor::mnt_namespace_detector {
public:
    void subscribe(subscription& client) override {
        struct ::stat st{};
        if (::stat("/proc/self/ns/mnt", &st) < 0)
            throw std::system_error(errno, std::generic_category(),
                "unable to determine self mount namespace id");

        fan_interceptor::fd_holder root_fd{::open("/", O_CLOEXEC | O_RDONLY)};
        if (! root_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open root dir in self mount namespace");

        fan_interceptor::fd_holder base_proc_dir_fd{::open("/proc/self", O_CLOEXEC | O_RDONLY)};
        if (! base_proc_dir_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open base process directory in self mount namespace");

        client.namespace_found(st.st_ino, std::move(root_fd), std::move(base_proc_dir_fd));

        m_self_mnt_ns_id = st.st_ino;
        m_client = &client;
    }

    void unsubscribe(subscription&) override {
        if (m_client) {
            for (auto id : m_other_ns_ids)
                m_client->namespace_have_gone(id);
            m_client->namespace_have_gone(m_self_mnt_ns_id);
            m_client = nullptr;
        }
    }

    bool add_namespace_by_pid(::pid_t proc) {
        struct ::stat st{};
        char buf[128];

        if (! m_client)
            throw std::logic_error("namespace detector has no subscriptions");

        std::snprintf(buf, sizeof(buf), "/proc/%d/ns/mnt", proc);
        if (::stat(buf, &st) < 0)
            throw std::system_error(errno, std::generic_category(),
                "unable to determine mount namespace id for provided pid");

        if (st.st_ino == m_self_mnt_ns_id)
            return false;

        std::snprintf(buf, sizeof(buf), "/proc/%d/root", proc);
        fan_interceptor::fd_holder root_fd{::open(buf, O_CLOEXEC | O_RDONLY)};
        if (! root_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open root dir in provided proc's mount namespace");

        std::snprintf(buf, sizeof(buf), "/proc/%d", proc);
        fan_interceptor::fd_holder base_proc_dir_fd{::open(buf, O_CLOEXEC | O_RDONLY)};
        if (! base_proc_dir_fd)
            throw std::system_error(errno, std::generic_category(),
                "unable to open base process directory for provided process");

        m_client->namespace_found(st.st_ino, std::move(root_fd), std::move(base_proc_dir_fd));

        m_other_ns_ids.push_back(st.st_ino);
        return true;
    }

private:
    subscription* m_client = nullptr;
    ::ino_t m_self_mnt_ns_id;
    std::vector<::ino_t> m_other_ns_ids;
};

struct intercept_dir_params {
    const char* m_dir;
    bool m_cache_on;
    bool m_delay_fd_on_close;
    unsigned m_working_thread_count;
    bool m_is_verbose;
    bool m_print_stat;
};

int intercept_dir(const intercept_dir_params& params) {
    struct subs : fan_interceptor::mu_subscriber {
        bool is_verbose;

        subs(bool b) : is_verbose(b) {}

        void on_fs_event(fan_interceptor::fs_event_ptr p) override {
            if (is_verbose)
                std::cout << "pid " << p->pid() << " access to: " << p->path() << std::endl;

            // small pause to see that internal caching works
            for (int i = 0; i < 10000; ++i)
                __builtin_ia32_pause();

            p->post_verdict(fan_interceptor::verdict::allow, true);
        }
        std::string_view name() override {
            return "[intercept-dir]";
        }
    } s{params.m_is_verbose};

    std::cout << "starting interceptor with " << params.m_working_thread_count
        << " threads, cache " << (params.m_cache_on ? "on" : "off")
        << (params.m_delay_fd_on_close ? ", delayed fds" : ", no delayed fds")
        << (params.m_print_stat ? ", print stat" : ", no print stat") << std::endl;

    auto iceptor = fan_interceptor::create_mu_interceptor(
        {
            { params.m_working_thread_count },
            params.m_delay_fd_on_close,
            params.m_print_stat
        });

    iceptor->subscribe(s,
        {
            (std::uint32_t)fan_interceptor::fs_event_type::open_perm,
            params.m_dir,
            params.m_cache_on
        });

    iceptor->start();

    std::cout << "command cycle started ... Enter 'stop' for quiting" << std::endl;

    std::string cmd_line;
    while (getline(std::cin, cmd_line)) {
        std::istringstream iss{cmd_line};

        std::string cmd;
        iss >> cmd;

        if (cmd == "stop")
            break;

        std::cerr << "unknown command: " << cmd << std::endl;
    }

    return 0;
}

void usage(const char* this_binary) {
    if (auto p = strrchr(this_binary, '/'))
        this_binary = p + 1;

    std::cout <<
        "This '" << this_binary << "' is an utility for testing a fan-interceptor library.\n"
        "\n"
        "Usage: " << this_binary << " [OPTIONS] [ARGS]\n"
        "\n"
        "Options:\n"
        "  -h, --help - this help message\n"
        "  -m N       - mode of operation. Currently supported only (1) - intercept specified in ARGS dir\n"
        "  -v         - be more verbose - print each access request\n"
        "  -t N       - number of interceptor working threads (default: 10)\n"
        "  --no-cache          - turning interceptor verdict cache off\n"
        "  --no-delay-fd-close - no storing intercepted fds for delayed closing\n"
        "  --print-stat        - print event statistics every 5 seconds"
        << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        const struct option long_opts[] = {
            {"help", 0, nullptr, 'h'},
            {"no-cache", 0, nullptr, 1},
            {"no-delay-fd-close", 0, nullptr, 2},
            {"print-stat", 0, nullptr, 3},
            {}};

        bool is_verbose = false;
        bool cache_on = true;
        bool delay_fd_on_close = true;
        bool print_stat = false;
        int interceptor_working_threads = 10;
        int opt;
        int mode = 1;

        while ((opt = ::getopt_long(argc, argv, "hm:vt:", long_opts, nullptr)) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0]); return 0;
            case 'v':
                is_verbose = true; break;
            case 1:
                cache_on = false; break;
            case 2:
                delay_fd_on_close = false; break;
            case 3:
                print_stat = true; break;
            case 't':
                interceptor_working_threads = std::strtol(optarg, nullptr, 10); break;
            case 'm':
                mode = std::strtol(optarg, nullptr, 10); break;
            default:
                return 1;
            }
        }

        if (mode == 1) {
            if (optind >= argc)
                throw std::runtime_error("a directory for interception must be provided");
            if (interceptor_working_threads < 1 || interceptor_working_threads > 100)
                throw std::runtime_error("insane number of working threads for interceptor specified");

            return intercept_dir(
                {
                    argv[optind],
                    cache_on,
                    delay_fd_on_close,
                    (unsigned)interceptor_working_threads,
                    is_verbose,
                    print_stat
                });
        } else {
            throw std::runtime_error("mode " + std::to_string(mode) + " is not supported");
        }
    } catch (const std::exception& ex) {
        std::cerr << "unexpected error: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
