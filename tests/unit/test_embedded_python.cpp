// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::python::Interpreter / ldb::python::Callable
// (post-V1 plan #9, docs/20-embedded-python.md).
//
// These exercise the JSON<->Python round-trip, exception capture and
// stdout capture contracts. The whole file is conditionally compiled
// against LDB_ENABLE_PYTHON; on OFF builds it reduces to an empty TU
// so CTest's unit_tests target stays green on machines without
// python3-embed.

#if defined(LDB_ENABLE_PYTHON) && LDB_ENABLE_PYTHON

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"   // backend::Error
#include "python/embed.h"

#include <nlohmann/json.hpp>

#include <string>

using ldb::python::Callable;
using ldb::python::Interpreter;
using nlohmann::json;

namespace {

// A Callable that takes ctx and returns it verbatim (echo). The
// canonical round-trip test: every supported JSON shape goes in, the
// same shape comes back unchanged.
const char* kEchoBody =
    "def run(ctx):\n"
    "    return ctx\n";

}  // namespace

TEST_CASE("embedded_python: interpreter init is idempotent",
          "[python][embed]") {
  auto& a = Interpreter::instance();
  auto& b = Interpreter::instance();
  REQUIRE(&a == &b);
}

TEST_CASE("embedded_python: scalar round-trip",
          "[python][embed][roundtrip]") {
  Callable c(kEchoBody, "<test>");
  REQUIRE(c.invoke(json(42)) == json(42));
  REQUIRE(c.invoke(json(-3)) == json(-3));
  REQUIRE(c.invoke(json("hello")) == json("hello"));
  REQUIRE(c.invoke(json(true)) == json(true));
  REQUIRE(c.invoke(json(false)) == json(false));
  REQUIRE(c.invoke(json(nullptr)) == json(nullptr));
  // Float survives the round-trip even though JSON has no distinct
  // float/int type — nlohmann::json keeps the runtime distinction.
  json f = 3.5;
  REQUIRE(c.invoke(f) == f);
}

TEST_CASE("embedded_python: list round-trip",
          "[python][embed][roundtrip]") {
  Callable c(kEchoBody, "<test>");
  json arr = json::array({1, "two", 3.0, true, nullptr});
  REQUIRE(c.invoke(arr) == arr);
}

TEST_CASE("embedded_python: dict round-trip",
          "[python][embed][roundtrip]") {
  Callable c(kEchoBody, "<test>");
  json obj = {
      {"target_id", 1},
      {"name", "btp_state"},
      {"flags", json::array({"a", "b"})},
      {"nested", {{"k", "v"}, {"n", 7}}},
  };
  REQUIRE(c.invoke(obj) == obj);
}

TEST_CASE("embedded_python: callable returning structured result",
          "[python][embed]") {
  const char* body =
      "def run(ctx):\n"
      "    return {'echoed': ctx.get('target_id'), 'count': 3}\n";
  Callable c(body, "<test>");
  auto result = c.invoke(json{{"target_id", 42}});
  REQUIRE(result.is_object());
  REQUIRE(result["echoed"] == 42);
  REQUIRE(result["count"] == 3);
}

TEST_CASE("embedded_python: runtime exception becomes backend::Error",
          "[python][embed][errors]") {
  const char* body =
      "def run(ctx):\n"
      "    raise ValueError('oops')\n";
  Callable c(body, "<test>");
  try {
    (void)c.invoke(json::object());
    FAIL("expected backend::Error");
  } catch (const ldb::backend::Error& e) {
    std::string what = e.what();
    REQUIRE(what.find("ValueError") != std::string::npos);
    REQUIRE(what.find("oops") != std::string::npos);
    REQUIRE(c.last_exception_type() == "ValueError");
    REQUIRE(c.last_exception_message() == "oops");
    REQUIRE_FALSE(c.last_traceback().empty());
  }
}

TEST_CASE("embedded_python: syntax error at compile time",
          "[python][embed][errors]") {
  // Trailing ':' with no body would be a syntax error, but Python
  // parses many almost-valid forms; use an unambiguous nonsense.
  const char* body =
      "def run(ctx):\n"
      "    retrn ctx_lol_typo)\n";
  try {
    Callable c(body, "<test>");
    FAIL("expected backend::Error on construction");
  } catch (const ldb::backend::Error& e) {
    std::string what = e.what();
    REQUIRE(what.find("SyntaxError") != std::string::npos);
  }
}

TEST_CASE("embedded_python: missing run() callable rejects at construction",
          "[python][embed][errors]") {
  const char* body = "x = 1\n";   // No `run` defined.
  try {
    Callable c(body, "<test>");
    FAIL("expected backend::Error on construction");
  } catch (const ldb::backend::Error& e) {
    std::string what = e.what();
    REQUIRE(what.find("run") != std::string::npos);
  }
}

TEST_CASE("embedded_python: stdout is captured, never leaks",
          "[python][embed][stdout]") {
  const char* body =
      "def run(ctx):\n"
      "    print('hi from python')\n"
      "    return ctx\n";
  Callable c(body, "<test>");
  // We can't actually intercept fd 1 from inside Catch — but we can
  // assert the captured-stdout snapshot from the Callable was set.
  // If the embed layer fails to capture, fd 1 contains "hi from
  // python" which corrupts the JSON-RPC channel in production.
  (void)c.invoke(json::object());
  REQUIRE(c.last_stdout().find("hi from python") != std::string::npos);
}

TEST_CASE("embedded_python: stdout buffer resets between invocations",
          "[python][embed][stdout]") {
  const char* body =
      "def run(ctx):\n"
      "    print('call', ctx.get('n', 0))\n"
      "    return ctx\n";
  Callable c(body, "<test>");
  (void)c.invoke(json{{"n", 1}});
  REQUIRE(c.last_stdout().find("call 1") != std::string::npos);
  (void)c.invoke(json{{"n", 2}});
  REQUIRE(c.last_stdout().find("call 2") != std::string::npos);
  // The "call 1" print from the prior invocation must NOT bleed into
  // the second invocation's captured buffer.
  REQUIRE(c.last_stdout().find("call 1") == std::string::npos);
}

TEST_CASE("embedded_python: integer slot returns int, not float",
          "[python][embed][types]") {
  const char* body =
      "def run(ctx):\n"
      "    return ctx['n'] * 2\n";
  Callable c(body, "<test>");
  auto result = c.invoke(json{{"n", 5}});
  REQUIRE(result.is_number_integer());
  REQUIRE(result.get<int>() == 10);
}

TEST_CASE("embedded_python: tuple return coerces to JSON array",
          "[python][embed][types]") {
  const char* body =
      "def run(ctx):\n"
      "    return (1, 2, 3)\n";
  Callable c(body, "<test>");
  auto result = c.invoke(json::object());
  REQUIRE(result.is_array());
  REQUIRE(result.size() == 3);
  REQUIRE(result[0] == 1);
}

TEST_CASE("embedded_python: bytes return is an explicit error",
          "[python][embed][types]") {
  const char* body =
      "def run(ctx):\n"
      "    return b'opaque'\n";
  Callable c(body, "<test>");
  try {
    (void)c.invoke(json::object());
    FAIL("expected backend::Error for bytes return");
  } catch (const ldb::backend::Error& e) {
    std::string what = e.what();
    REQUIRE(what.find("bytes") != std::string::npos);
  }
}

#endif  // LDB_ENABLE_PYTHON
