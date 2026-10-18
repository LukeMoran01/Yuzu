/**
 * test_vuln_config_checks.cpp -- Pure Linux config-check decisions (#4961).
 *
 * A read that failed must surface as UNREADABLE (the check could not run), never
 * as the empty/unexpected-value finding. Covers the pure checks in
 * config_checks.hpp and the portable stream readers' fault detection. Portable:
 * no process access; the one file access is an open of a path that does not
 * exist (ENOENT plumbing), on Linux/macOS only.
 */

#include "config_checks.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <sstream>
#include <string>
#include <vector>

using namespace yuzu::vuln;

namespace {

const ReadResult kEacces = std::unexpected(EACCES);

LinesResult lines(std::vector<std::string> v) {
    return v;
}

} // namespace

TEST_CASE("errno_name: known table and fallback", "[vuln][config]") {
    CHECK(errno_name(EACCES) == "eacces");
    CHECK(errno_name(EPERM) == "eperm");
    CHECK(errno_name(ENOENT) == "enoent");
    CHECK(errno_name(EIO) == "eio");
    CHECK(errno_name(ENOTDIR) == "enotdir");
    CHECK(errno_name(EISDIR) == "eisdir");
    CHECK(errno_name(12345) == "errno_12345");
}

// ── ASLR ────────────────────────────────────────────────────────────────────

TEST_CASE("aslr_check: unreadable is UNREADABLE with path and cause", "[vuln][config]") {
    auto r = aslr_check(kEacces);
    CHECK(r.severity == "UNREADABLE");
    CHECK(r.title == "ASLR (Address Space Layout Randomization)");
    CHECK(r.detail == "/proc/sys/kernel/randomize_va_space: eacces");
    CHECK_FALSE(r.passed);
}

TEST_CASE("aslr_check: read values keep today's rows", "[vuln][config]") {
    auto ok = aslr_check(ReadResult{"2"});
    CHECK(ok.severity == "INFO");
    CHECK(ok.detail == "Full randomization enabled (value=2)");
    CHECK(ok.passed);

    auto bad = aslr_check(ReadResult{"1"});
    CHECK(bad.severity == "HIGH");
    CHECK(bad.title == "ASLR (Address Space Layout Randomization)");
    CHECK(bad.detail == "Not fully enabled (value=1) - should be 2");
    CHECK_FALSE(bad.passed);

    auto empty = aslr_check(ReadResult{""});
    CHECK(empty.severity == "UNREADABLE");
    CHECK(empty.detail == "/proc/sys/kernel/randomize_va_space: eio");
    CHECK_FALSE(empty.passed);
}

// ── /tmp noexec ─────────────────────────────────────────────────────────────

TEST_CASE("tmp_noexec_check: unreadable, no /tmp mount, noexec and exec", "[vuln][config]") {
    auto unreadable = tmp_noexec_check(LinesResult(std::unexpected(EACCES)));
    REQUIRE(unreadable.has_value());
    CHECK(unreadable->severity == "UNREADABLE");
    CHECK(unreadable->title == "/tmp noexec");
    CHECK(unreadable->detail == "/proc/self/mountinfo: eacces");
    CHECK_FALSE(unreadable->passed);

    CHECK_FALSE(
        tmp_noexec_check(lines({"22 1 0:21 / /proc rw,nosuid,nodev,noexec - proc proc rw",
                                "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw"}))
            .has_value());
    CHECK_FALSE(tmp_noexec_check(lines({"30 1 0:30 / /var/tmp rw,noexec - tmpfs tmpfs rw",
                                        "31 1 0:31 / /tmp/x rw,noexec - tmpfs tmpfs rw"}))
                    .has_value()); // the mount point must be exactly /tmp

    auto noexec = tmp_noexec_check(
        lines({"1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw",
               "40 1 0:40 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw"}));
    REQUIRE(noexec.has_value());
    CHECK(noexec->severity == "INFO");
    CHECK(noexec->title == "/tmp noexec");
    CHECK(noexec->detail == "/tmp is mounted with noexec");
    CHECK(noexec->passed);

    auto exec = tmp_noexec_check(lines({"40 1 0:40 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw"}));
    REQUIRE(exec.has_value());
    CHECK(exec->severity == "MEDIUM");
    CHECK(exec->title == "/tmp noexec");
    CHECK(exec->detail == "/tmp is not mounted with noexec - executables can run from /tmp");
    CHECK_FALSE(exec->passed);
}

TEST_CASE("tmp_noexec_check: the top /tmp mount wins, by parent ID (#5517)", "[vuln][config]") {
    // An exec mount created first, then moved over a noexec /tmp: the top is
    // listed first (captured from a kernel 6.12 mount namespace).
    auto moved_exec = tmp_noexec_check(
        lines({"1971 1972 0:214 / /tmp rw,relatime - tmpfs tmpA rw,uid=999,gid=1000",
               "1972 1910 0:215 / /tmp rw,noexec,relatime - tmpfs tmpB rw,uid=999,gid=1000"}));
    REQUIRE(moved_exec.has_value());
    CHECK(moved_exec->severity == "MEDIUM");
    CHECK_FALSE(moved_exec->passed);

    auto moved_noexec = tmp_noexec_check(
        lines({"1971 1972 0:214 / /tmp rw,noexec,relatime - tmpfs tmpA rw",
               "1972 1910 0:215 / /tmp rw,relatime - tmpfs tmpB rw"}));
    REQUIRE(moved_noexec.has_value());
    CHECK(moved_noexec->severity == "INFO");
    CHECK(moved_noexec->passed);

    // Ordinary stacking: the later mount is on top and listed last.
    auto stacked_exec =
        tmp_noexec_check(lines({"40 1 0:40 / /tmp rw,noexec - tmpfs tmpfs rw",
                                "41 40 0:41 / /tmp rw,nosuid - tmpfs tmpfs rw"}));
    REQUIRE(stacked_exec.has_value());
    CHECK(stacked_exec->severity == "MEDIUM");
    CHECK_FALSE(stacked_exec->passed);
}

TEST_CASE("tmp_noexec_check: noexec only as an exact per-mount option", "[vuln][config]") {
    // In the source or the superblock options, noexec is not a mount option.
    auto source = tmp_noexec_check(lines({"40 1 8:2 / /tmp rw - ext4 /dev/noexec0 rw,noexec"}));
    REQUIRE(source.has_value());
    CHECK(source->severity == "MEDIUM");
    CHECK_FALSE(source->passed);

    auto substring = tmp_noexec_check(lines({"40 1 0:40 / /tmp rw,xnoexec,noexecx - tmpfs t rw"}));
    REQUIRE(substring.has_value());
    CHECK(substring->severity == "MEDIUM");
    CHECK_FALSE(substring->passed);

    // A /tmp entry too short to carry mount options fails closed: not noexec.
    auto short_line = tmp_noexec_check(lines({"40 1 0:40 / /tmp"}));
    REQUIRE(short_line.has_value());
    CHECK(short_line->severity == "MEDIUM");
    CHECK_FALSE(short_line->passed);

    // A /tmp line too short to name a mount point is not a /tmp mount.
    CHECK_FALSE(tmp_noexec_check(lines({"40 1 0:40 /tmp"})).has_value());
}

TEST_CASE("tmp_noexec_check: several or no tops (#5517)", "[vuln][config]") {
    // An overmounted ancestor (mount --rbind / /) leaves two unrelated /tmp
    // tops (captured from a kernel 6.12 mount namespace). Both noexec: pass.
    auto two_noexec = tmp_noexec_check(lines({"1970 1910 0:172 / /tmp rw,noexec - tmpfs a rw",
                                              "1996 1971 0:172 / /tmp rw,noexec - tmpfs a rw"}));
    REQUIRE(two_noexec.has_value());
    CHECK(two_noexec->severity == "INFO");
    CHECK(two_noexec->passed);

    // Tops that disagree fail closed.
    auto mixed = tmp_noexec_check(lines({"40 1 0:40 / /tmp rw,noexec - tmpfs a rw",
                                         "41 2 0:41 / /tmp rw - tmpfs b rw"}));
    REQUIRE(mixed.has_value());
    CHECK(mixed->severity == "MEDIUM");
    CHECK_FALSE(mixed->passed);

    // A parent-ID cycle has no top: fail closed.
    auto cycle = tmp_noexec_check(lines({"40 41 0:40 / /tmp rw,noexec - tmpfs a rw",
                                         "41 40 0:41 / /tmp rw,noexec - tmpfs b rw"}));
    REQUIRE(cycle.has_value());
    CHECK(cycle->severity == "MEDIUM");
    CHECK_FALSE(cycle->passed);
}

// ── suid_dumpable ───────────────────────────────────────────────────────────

TEST_CASE("suid_dumpable_check: unreadable is UNREADABLE with path and cause", "[vuln][config]") {
    auto r = suid_dumpable_check(kEacces);
    CHECK(r.severity == "UNREADABLE");
    CHECK(r.title == "SUID Core Dumps");
    CHECK(r.detail == "/proc/sys/fs/suid_dumpable: eacces");
    CHECK_FALSE(r.passed);
}

TEST_CASE("suid_dumpable_check: read values keep today's rows", "[vuln][config]") {
    auto ok = suid_dumpable_check(ReadResult{"0"});
    CHECK(ok.severity == "INFO");
    CHECK(ok.detail == "Restricted (suid_dumpable=0)");
    CHECK(ok.passed);

    auto bad = suid_dumpable_check(ReadResult{"2"});
    CHECK(bad.severity == "MEDIUM");
    CHECK(bad.title == "SUID Core Dumps");
    CHECK(bad.detail == "Not restricted (suid_dumpable=2) - SUID programs may dump core");
    CHECK_FALSE(bad.passed);

    auto empty = suid_dumpable_check(ReadResult{""});
    CHECK(empty.severity == "UNREADABLE");
    CHECK(empty.detail == "/proc/sys/fs/suid_dumpable: eio");
    CHECK_FALSE(empty.passed);
}

// ── SSH root login ──────────────────────────────────────────────────────────

TEST_CASE("ssh_root_login_check: directives", "[vuln][config]") {
    auto yes = ssh_root_login_check(lines({"Port 22", "PermitRootLogin yes"}));
    CHECK(yes.severity == "HIGH");
    CHECK(yes.title == "SSH Root Login");
    CHECK(yes.detail == "PermitRootLogin is set to yes - direct root access via SSH is enabled");
    CHECK_FALSE(yes.passed);

    auto no = ssh_root_login_check(lines({"PermitRootLogin no"}));
    CHECK(no.severity == "INFO");
    CHECK(no.detail == "PermitRootLogin is set to no");
    CHECK(no.passed);

    auto neither = ssh_root_login_check(lines({}));
    CHECK(neither.severity == "MEDIUM");
    CHECK(neither.detail ==
          "PermitRootLogin not explicitly set - may default to prohibit-password");
    CHECK_FALSE(neither.passed);
}

TEST_CASE("ssh_root_login_check: commented-out line is ignored", "[vuln][config]") {
    auto r = ssh_root_login_check(lines({"# PermitRootLogin yes", "  \t#PermitRootLogin yes"}));
    CHECK(r.severity == "MEDIUM");
}

TEST_CASE("ssh_root_login_check: absent config is not applicable, other errors UNREADABLE",
          "[vuln][config]") {
    auto absent = ssh_root_login_check(LinesResult{std::unexpected(ENOENT)});
    CHECK(absent.severity == "INFO");
    CHECK(absent.detail == "/etc/ssh/sshd_config not present; check not applicable");
    CHECK(absent.passed);

    auto eio = ssh_root_login_check(LinesResult{std::unexpected(EIO)});
    CHECK(eio.severity == "UNREADABLE");
    CHECK(eio.detail == "/etc/ssh/sshd_config: eio");
    CHECK_FALSE(eio.passed);

    auto denied = ssh_root_login_check(LinesResult{std::unexpected(EACCES)});
    CHECK(denied.severity == "UNREADABLE");
    CHECK(denied.detail == "/etc/ssh/sshd_config: eacces");
}

// ── SSH password authentication ─────────────────────────────────────────────

TEST_CASE("ssh_password_auth_check: neither directive emits no row", "[vuln][config]") {
    CHECK_FALSE(ssh_password_auth_check(lines({"Port 22", "# PasswordAuthentication yes"}))
                    .has_value());
    CHECK_FALSE(ssh_password_auth_check(lines({})).has_value());
}

TEST_CASE("ssh_password_auth_check: directives", "[vuln][config]") {
    auto yes = ssh_password_auth_check(lines({"PasswordAuthentication yes"}));
    REQUIRE(yes.has_value());
    CHECK(yes->severity == "MEDIUM");
    CHECK(yes->title == "SSH Password Authentication");
    CHECK(yes->detail == "Enabled - consider using key-based authentication only");
    CHECK_FALSE(yes->passed);

    auto no = ssh_password_auth_check(lines({"PasswordAuthentication no"}));
    REQUIRE(no.has_value());
    CHECK(no->severity == "INFO");
    CHECK(no->detail == "Disabled - key-based auth only");
    CHECK(no->passed);
}

TEST_CASE("ssh_password_auth_check: absent config is not applicable, other errors UNREADABLE",
          "[vuln][config]") {
    auto absent = ssh_password_auth_check(LinesResult{std::unexpected(ENOENT)});
    REQUIRE(absent.has_value());
    CHECK(absent->severity == "INFO");
    CHECK(absent->detail == "/etc/ssh/sshd_config not present; check not applicable");
    CHECK(absent->passed);

    auto eio = ssh_password_auth_check(LinesResult{std::unexpected(EIO)});
    REQUIRE(eio.has_value());
    CHECK(eio->severity == "UNREADABLE");
    CHECK(eio->detail == "/etc/ssh/sshd_config: eio");
    CHECK_FALSE(eio->passed);
}

// ── Stream readers: fault detection ─────────────────────────────────────────

TEST_CASE("read_value_from: clean, empty and faulted streams", "[vuln][config]") {
    std::istringstream clean("2\n");
    auto v = read_value_from(clean);
    REQUIRE(v.has_value());
    CHECK(*v == "2");

    std::istringstream empty("");
    auto e = read_value_from(empty);
    REQUIRE(e.has_value()); // failbit+eofbit on an empty file is a value, not a fault
    CHECK(e->empty());
    CHECK(aslr_check(e).severity == "UNREADABLE"); // the check, not the reader, refuses an empty /proc/sys value

    std::istringstream faulted("2\n");
    faulted.setstate(std::ios::badbit);
    auto f = read_value_from(faulted);
    REQUIRE_FALSE(f.has_value());
    CHECK(f.error() == EIO);
    CHECK(aslr_check(f).severity == "UNREADABLE");
    CHECK(suid_dumpable_check(f).severity == "UNREADABLE");
}

TEST_CASE("read_lines_from: clean, empty and faulted streams", "[vuln][config]") {
    std::istringstream clean("a\nb\n");
    auto v = read_lines_from(clean);
    REQUIRE(v.has_value());
    CHECK(*v == std::vector<std::string>{"a", "b"});

    std::istringstream empty("");
    auto e = read_lines_from(empty);
    REQUIRE(e.has_value());
    CHECK(e->empty());

    std::istringstream faulted("PermitRootLogin no\n");
    faulted.setstate(std::ios::badbit);
    auto f = read_lines_from(faulted);
    REQUIRE_FALSE(f.has_value());
    CHECK(f.error() == EIO);
    CHECK(ssh_root_login_check(f).severity == "UNREADABLE");
    auto pw = ssh_password_auth_check(f);
    REQUIRE(pw.has_value());
    CHECK(pw->severity == "UNREADABLE");
}

TEST_CASE("summary_rows: UNREADABLE counted separately and excluded from issues",
          "[vuln][config]") {
    const auto rows = summary_rows({"INFO", "INFO", "HIGH", "UNREADABLE", "UNREADABLE", "UNREADABLE"});
    const std::vector<std::string> expected{
        "summary|TOTAL|6 findings (1 issues)", "summary|CRITICAL|0", "summary|HIGH|1",
        "summary|MEDIUM|0",                    "summary|LOW|0",      "summary|INFO|2",
        "summary|UNREADABLE|3"};
    CHECK(rows == expected);
}

#if defined(__linux__) || defined(__APPLE__)
TEST_CASE("read_proc_value / read_lines: a missing path reports ENOENT", "[vuln][config]") {
    const char* missing = "/nonexistent/yuzu_test_vuln_config_checks/absent";
    auto v = detail::read_proc_value(missing);
    REQUIRE_FALSE(v.has_value());
    CHECK(v.error() == ENOENT);
    auto l = detail::read_lines(missing);
    REQUIRE_FALSE(l.has_value());
    CHECK(l.error() == ENOENT);
    CHECK(ssh_root_login_check(l).severity == "INFO");
}
#endif
