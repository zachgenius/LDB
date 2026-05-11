// SPDX-License-Identifier: Apache-2.0
// Unit tests for the GDB/MI3 protocol parser (post-V1 plan #8).
//
// The parser is the bottom of the GdbMiBackend stack — every MI
// command the backend issues lands here as a stream of stdout lines
// from `gdb --interpreter=mi3`. The reader thread feeds lines in;
// the parser turns them into structured records the backend can
// pattern-match on.
//
// MI3 record kinds (see docs/18-gdbmi-backend.md):
//   ^token-result-record-payload    e.g. ^done,bkpt={...}
//   *exec-async-record              e.g. *stopped,reason="..."
//   +status-async-record            e.g. +download,{...}
//   =notify-async-record            e.g. =thread-group-added,id="i1"
//   ~"console-stream"               informational text
//   &"log-stream"                   gdb warnings
//   @"target-stream"                inferior stdout
//   (gdb)                           prompt; batch terminator
//
// Value grammar inside records:
//   string : "..." with C-style escapes
//   tuple  : { name=value, name=value, ... }
//   list   : [ value, value, ... ] OR [ name=value, name=value, ... ]
//
// Everything is exercised against canned text fixtures — no live
// gdb required. The fixtures cover the records and edge cases the
// dispatcher mapping table in docs/18 actually needs.

#include <catch_amalgamated.hpp>

#include "backend/gdbmi/parser.h"

using ldb::backend::gdbmi::MiRecord;
using ldb::backend::gdbmi::MiRecordKind;
using ldb::backend::gdbmi::MiValue;
using ldb::backend::gdbmi::parse_line;
using ldb::backend::gdbmi::parse_value;

// ── Result records ─────────────────────────────────────────────────────

TEST_CASE("mi_parser: bare ^done", "[mi][parser]") {
  auto r = parse_line("^done");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kResult);
  CHECK(r->klass == "done");
  CHECK_FALSE(r->token.has_value());
  CHECK(r->payload.is_tuple());
  CHECK(r->payload.as_tuple().empty());
}

TEST_CASE("mi_parser: tokenized result record", "[mi][parser]") {
  auto r = parse_line("42^done,bkpt={number=\"3\",addr=\"0x401234\"}");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kResult);
  CHECK(r->klass == "done");
  REQUIRE(r->token.has_value());
  CHECK(*r->token == 42);
  REQUIRE(r->payload.is_tuple());
  const auto& t = r->payload.as_tuple();
  REQUIRE(t.count("bkpt") == 1);
  const auto& bkpt = t.at("bkpt");
  REQUIRE(bkpt.is_tuple());
  CHECK(bkpt.as_tuple().at("number").as_string() == "3");
  CHECK(bkpt.as_tuple().at("addr").as_string() == "0x401234");
}

TEST_CASE("mi_parser: ^error records carry msg", "[mi][parser]") {
  auto r = parse_line("^error,msg=\"No symbol \\\"missing\\\" in current "
                      "context.\"");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kResult);
  CHECK(r->klass == "error");
  REQUIRE(r->payload.is_tuple());
  CHECK(r->payload.as_tuple().at("msg").as_string()
        == "No symbol \"missing\" in current context.");
}

TEST_CASE("mi_parser: ^running record (no payload)", "[mi][parser]") {
  auto r = parse_line("^running");
  REQUIRE(r.has_value());
  CHECK(r->klass == "running");
  CHECK(r->payload.as_tuple().empty());
}

// ── Async records ──────────────────────────────────────────────────────

TEST_CASE("mi_parser: *stopped with nested frame tuple", "[mi][parser]") {
  auto r = parse_line(
      "*stopped,reason=\"breakpoint-hit\",disp=\"keep\",bkptno=\"1\","
      "frame={addr=\"0x401234\",func=\"main\",args=[],"
      "file=\"main.c\",line=\"12\"},thread-id=\"1\",stopped-threads=\"all\"");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kExecAsync);
  CHECK(r->klass == "stopped");
  const auto& t = r->payload.as_tuple();
  CHECK(t.at("reason").as_string() == "breakpoint-hit");
  CHECK(t.at("thread-id").as_string() == "1");
  REQUIRE(t.at("frame").is_tuple());
  CHECK(t.at("frame").as_tuple().at("func").as_string() == "main");
  CHECK(t.at("frame").as_tuple().at("file").as_string() == "main.c");
}

TEST_CASE("mi_parser: =thread-group-added", "[mi][parser]") {
  auto r = parse_line("=thread-group-added,id=\"i1\"");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kNotifyAsync);
  CHECK(r->klass == "thread-group-added");
  CHECK(r->payload.as_tuple().at("id").as_string() == "i1");
}

TEST_CASE("mi_parser: +download status-async record", "[mi][parser]") {
  auto r = parse_line("+download,{section=\".text\",section-size=\"4096\"}");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kStatusAsync);
  CHECK(r->klass == "download");
}

// ── Stream records ─────────────────────────────────────────────────────

TEST_CASE("mi_parser: console stream record", "[mi][parser]") {
  auto r = parse_line("~\"Breakpoint 1 at 0x401234: file main.c, line 12.\\n\"");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kConsoleStream);
  CHECK(r->stream_text
        == "Breakpoint 1 at 0x401234: file main.c, line 12.\n");
}

TEST_CASE("mi_parser: log stream record", "[mi][parser]") {
  auto r = parse_line("&\"some warning text\\n\"");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kLogStream);
  CHECK(r->stream_text == "some warning text\n");
}

TEST_CASE("mi_parser: target stream record", "[mi][parser]") {
  auto r = parse_line("@\"inferior stdout text\\n\"");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kTargetStream);
  CHECK(r->stream_text == "inferior stdout text\n");
}

// ── Prompt and blanks ──────────────────────────────────────────────────

TEST_CASE("mi_parser: prompt line", "[mi][parser]") {
  auto r = parse_line("(gdb)");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kPrompt);
}

TEST_CASE("mi_parser: prompt with trailing space tolerated", "[mi][parser]") {
  auto r = parse_line("(gdb) ");
  REQUIRE(r.has_value());
  CHECK(r->kind == MiRecordKind::kPrompt);
}

TEST_CASE("mi_parser: blank line returns nullopt", "[mi][parser]") {
  CHECK_FALSE(parse_line("").has_value());
  CHECK_FALSE(parse_line("   ").has_value());
}

// ── Value parser edge cases ────────────────────────────────────────────

TEST_CASE("mi_parser: string with escaped quote + backslash + nl",
          "[mi][parser][value]") {
  auto v = parse_value("\"foo \\\"bar\\\" \\\\ \\n end\"");
  REQUIRE(v.has_value());
  CHECK(v->as_string() == "foo \"bar\" \\ \n end");
}

TEST_CASE("mi_parser: list of strings", "[mi][parser][value]") {
  auto v = parse_value("[\"a\",\"b\",\"c\"]");
  REQUIRE(v.has_value());
  REQUIRE(v->is_list());
  const auto& l = v->as_list();
  REQUIRE(l.size() == 3);
  CHECK(l[0].as_string() == "a");
  CHECK(l[1].as_string() == "b");
  CHECK(l[2].as_string() == "c");
}

TEST_CASE("mi_parser: list of tuples (frames)", "[mi][parser][value]") {
  auto v = parse_value("[frame={level=\"0\",addr=\"0x401234\"},"
                       "frame={level=\"1\",addr=\"0x500\"}]");
  REQUIRE(v.has_value());
  REQUIRE(v->is_list());
  // Named-element lists (frame=... frame=...) flatten to a plain
  // list where each entry is the value (the tuple). The "frame"
  // name itself is implicit from context.
  REQUIRE(v->as_list().size() == 2);
  REQUIRE(v->as_list()[0].is_tuple());
  CHECK(v->as_list()[0].as_tuple().at("level").as_string() == "0");
  CHECK(v->as_list()[1].as_tuple().at("level").as_string() == "1");
}

TEST_CASE("mi_parser: empty list / empty tuple", "[mi][parser][value]") {
  auto e_list = parse_value("[]");
  REQUIRE(e_list.has_value());
  REQUIRE(e_list->is_list());
  CHECK(e_list->as_list().empty());

  auto e_tuple = parse_value("{}");
  REQUIRE(e_tuple.has_value());
  REQUIRE(e_tuple->is_tuple());
  CHECK(e_tuple->as_tuple().empty());
}

TEST_CASE("mi_parser: nested tuple inside list inside tuple",
          "[mi][parser][value]") {
  auto v = parse_value(
      "{threads=[{id=\"1\",frame={addr=\"0x401234\",func=\"main\"}}]}");
  REQUIRE(v.has_value());
  const auto& threads = v->as_tuple().at("threads");
  REQUIRE(threads.is_list());
  REQUIRE(threads.as_list().size() == 1);
  const auto& t0 = threads.as_list()[0];
  CHECK(t0.as_tuple().at("id").as_string() == "1");
  CHECK(t0.as_tuple().at("frame").as_tuple().at("func").as_string()
        == "main");
}

// ── Error handling ─────────────────────────────────────────────────────

TEST_CASE("mi_parser: malformed record returns nullopt rather than throw",
          "[mi][parser][error]") {
  // We never want a single bad line from gdb to crash the daemon —
  // log it and move on.
  CHECK_FALSE(parse_line("^").has_value());           // truncated
  CHECK_FALSE(parse_line("^done,bkpt={").has_value()); // unclosed tuple
  CHECK_FALSE(parse_line("~not-a-quoted-string").has_value());
}
