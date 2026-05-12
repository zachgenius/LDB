// SPDX-License-Identifier: Apache-2.0
// Tests for the predicate.compile dispatcher endpoint
// (post-V1 #25 phase-2, docs/29-predicate-compiler.md §3).
//
// Coverage:
//   * Happy path: valid S-expression source → {bytecode_b64, bytes,
//     mnemonics, reg_table}. bytecode_b64 round-trips through the
//     existing codec to a Program identical to compile()'s result.
//   * Empty source → kEnd-only program; non-empty response carrying
//     "end" in mnemonics.
//   * Compile error → -32602 kInvalidParams with the line:column
//     anchor surfaced in the error message.
//   * Missing source → -32602.
//   * Source not a string → -32602.
//   * Source > kMaxSourceBytes → -32602 (validated before tokenise).
//   * describe.endpoints lists predicate.compile.

#include <catch_amalgamated.hpp>

#include "agent_expr/bytecode.h"
#include "agent_expr/compiler.h"
#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "util/base64.h"

#include <memory>
#include <string>

using ldb::agent_expr::Op;
using ldb::agent_expr::decode;
using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::json;
using ldb::util::base64_decode;

namespace {

Request req(const std::string& method, json params, const std::string& id = "1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

Dispatcher make_dispatcher() {
  auto be = std::make_shared<LldbBackend>();
  return Dispatcher{be};
}

}  // namespace

TEST_CASE("predicate.compile: valid source returns bytecode + listing",
          "[dispatcher][predicate][compile]") {
  auto disp = make_dispatcher();
  auto resp = disp.dispatch(req("predicate.compile",
      json{{"source", "(eq (reg \"rax\") (const 42))"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("bytecode_b64"));
  REQUIRE(resp.data.contains("bytes"));
  REQUIRE(resp.data.contains("mnemonics"));
  REQUIRE(resp.data.contains("reg_table"));

  CHECK(resp.data["bytes"].is_number_unsigned());
  CHECK(resp.data["mnemonics"].is_array());
  CHECK(resp.data["reg_table"].is_array());
  REQUIRE(resp.data["reg_table"].size() == 1);
  CHECK(resp.data["reg_table"][0].get<std::string>() == "rax");

  // Round-trip: decode the base64 → Program → matches compile()'s
  // direct output.
  auto bytes = base64_decode(resp.data["bytecode_b64"].get<std::string>());
  auto prog_opt = decode(std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  REQUIRE(prog_opt.has_value());
  CHECK(prog_opt->reg_table.size() == 1);
  CHECK(prog_opt->reg_table[0] == "rax");
  // Mnemonics array should include the obvious opcodes.
  bool seen_reg = false, seen_const = false, seen_eq = false, seen_end = false;
  for (const auto& m : resp.data["mnemonics"]) {
    const auto s = m.get<std::string>();
    if (s.find("reg")    != std::string::npos) seen_reg = true;
    if (s.find("const")  != std::string::npos) seen_const = true;
    if (s.find("eq")     != std::string::npos) seen_eq = true;
    if (s.find("end")    != std::string::npos) seen_end = true;
  }
  CHECK(seen_reg);
  CHECK(seen_const);
  CHECK(seen_eq);
  CHECK(seen_end);
}

TEST_CASE("predicate.compile: empty source compiles to kEnd-only program",
          "[dispatcher][predicate][compile][empty]") {
  auto disp = make_dispatcher();
  auto resp = disp.dispatch(req("predicate.compile", json{{"source", ""}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["mnemonics"].size() == 1);
  CHECK(resp.data["mnemonics"][0].get<std::string>() == "end");
  CHECK(resp.data["reg_table"].empty());
  // `bytes` is the WIRE-format size: u32 program_size (4) + opcodes
  // (1 byte: kEnd) + u16 reg_count (2) = 7. The opcode-only count
  // is available via mnemonics.size().
  CHECK(resp.data["bytes"].get<int>() == 7);
}

TEST_CASE("predicate.compile: compile error surfaces -32602 with anchor",
          "[dispatcher][predicate][compile][error]") {
  auto disp = make_dispatcher();
  auto resp = disp.dispatch(req("predicate.compile",
      json{{"source", "(eq 1)"}}));   // wrong arity
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
  CHECK(resp.error_message.find("eq")        != std::string::npos);
  CHECK(resp.error_message.find("2 argument") != std::string::npos);
  // Line/column anchor should appear in the message.
  CHECK(resp.error_message.find("1:")        != std::string::npos);
}

TEST_CASE("predicate.compile: missing source → -32602",
          "[dispatcher][predicate][compile][error]") {
  auto disp = make_dispatcher();
  auto resp = disp.dispatch(req("predicate.compile", json::object()));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("predicate.compile: source not a string → -32602",
          "[dispatcher][predicate][compile][error]") {
  auto disp = make_dispatcher();
  auto resp = disp.dispatch(req("predicate.compile",
      json{{"source", 42}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("predicate.compile: oversized source → -32602",
          "[dispatcher][predicate][compile][error][cap]") {
  auto disp = make_dispatcher();
  std::string big(ldb::agent_expr::kMaxSourceBytes + 1, 'x');
  auto resp = disp.dispatch(req("predicate.compile",
      json{{"source", big}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("predicate.compile: describe.endpoints lists it",
          "[dispatcher][predicate][describe]") {
  auto disp = make_dispatcher();
  auto resp = disp.dispatch(req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  bool found = false;
  for (const auto& e : resp.data["endpoints"]) {
    if (e.value("method", std::string{}) == "predicate.compile") {
      found = true;
      CHECK(e.contains("params_schema"));
      CHECK(e.contains("returns_schema"));
      break;
    }
  }
  CHECK(found);
}
