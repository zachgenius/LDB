// Tests for bpftrace program-text generation from probe.create params.
// Pure string transformation — given an `UprobeBpfSpec`, the engine
// emits a single-line bpftrace program.

#include <catch_amalgamated.hpp>

#include "probes/bpftrace_engine.h"

#include <string>
#include <vector>

using ldb::probes::UprobeBpfSpec;
using ldb::probes::generate_bpftrace_program;

TEST_CASE("bpftrace program: uprobe form", "[probes][bpftrace][program]") {
  UprobeBpfSpec s;
  s.where_kind   = UprobeBpfSpec::Kind::kUprobe;
  s.where_target = "/lib/x86_64-linux-gnu/libc.so.6:bind";
  s.captured_args = {"arg0", "arg1", "arg2"};
  std::string p = generate_bpftrace_program(s);
  // Probe attachment site
  REQUIRE(p.find("uprobe:/lib/x86_64-linux-gnu/libc.so.6:bind") !=
          std::string::npos);
  // No filter (no /pid==N/) when filter_pid not set
  REQUIRE(p.find("/pid ==") == std::string::npos);
  // Body emits ts_ns / tid / pid + arg list
  REQUIRE(p.find("ts_ns") != std::string::npos);
  REQUIRE(p.find("nsecs")  != std::string::npos);
  // Note: the program is bpftrace shellout text. The JSON keys appear
  // backslash-escaped inside printf("..."), so we search for the
  // escaped form.
  REQUIRE(p.find("\\\"args\\\"") != std::string::npos);
  REQUIRE(p.find("arg0") != std::string::npos);
  REQUIRE(p.find("arg1") != std::string::npos);
  REQUIRE(p.find("arg2") != std::string::npos);
}

TEST_CASE("bpftrace program: tracepoint form", "[probes][bpftrace][program]") {
  UprobeBpfSpec s;
  s.where_kind   = UprobeBpfSpec::Kind::kTracepoint;
  s.where_target = "syscalls:sys_enter_bind";
  std::string p = generate_bpftrace_program(s);
  REQUIRE(p.find("tracepoint:syscalls:sys_enter_bind") != std::string::npos);
}

TEST_CASE("bpftrace program: kprobe form", "[probes][bpftrace][program]") {
  UprobeBpfSpec s;
  s.where_kind   = UprobeBpfSpec::Kind::kKprobe;
  s.where_target = "tcp_v4_connect";
  std::string p = generate_bpftrace_program(s);
  REQUIRE(p.find("kprobe:tcp_v4_connect") != std::string::npos);
}

TEST_CASE("bpftrace program: filter_pid attaches predicate",
          "[probes][bpftrace][program]") {
  UprobeBpfSpec s;
  s.where_kind   = UprobeBpfSpec::Kind::kUprobe;
  s.where_target = "/lib/x86_64-linux-gnu/libc.so.6:bind";
  s.filter_pid   = 12345;
  std::string p = generate_bpftrace_program(s);
  REQUIRE(p.find("/pid == 12345/") != std::string::npos);
}

TEST_CASE("bpftrace program: zero captured args emits empty array",
          "[probes][bpftrace][program]") {
  UprobeBpfSpec s;
  s.where_kind   = UprobeBpfSpec::Kind::kKprobe;
  s.where_target = "do_nanosleep";
  std::string p = generate_bpftrace_program(s);
  // Escaped JSON inside the printf format string.
  REQUIRE(p.find("\\\"args\\\":[]") != std::string::npos);
}

TEST_CASE("bpftrace program: rejects unsupported arg names",
          "[probes][bpftrace][program][error]") {
  UprobeBpfSpec s;
  s.where_kind     = UprobeBpfSpec::Kind::kUprobe;
  s.where_target   = "/lib/x86_64-linux-gnu/libc.so.6:bind";
  s.captured_args  = {"arg0", "; rm -rf /"};
  REQUIRE_THROWS_AS(generate_bpftrace_program(s), std::invalid_argument);
}
