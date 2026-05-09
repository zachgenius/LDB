// SPDX-License-Identifier: Apache-2.0
// M5 part 2 — describe.endpoints emits JSON Schema (draft 2020-12) for
// every endpoint, plus per-endpoint `requires_stopped` and `cost_hint`
// metadata that an agent can read once at session-start to plan its
// calls.
//
// These tests are structural — we don't pull in a JSON Schema validator
// (no nlohmann/json-schema in tree, and the marginal value of a full
// validator over a sane structural check is small). Instead we assert
// shape: top-level type=object, properties is an object, every name in
// `required` is also a property, etc.
//
// Coverage report (the worklog has the full list):
//   * Every entry has method/summary/params_schema/returns_schema/
//     requires_target/requires_stopped/cost_hint.
//   * Spot-checks on target.open, mem.read, probe.create, observer.exec
//     pin down a few key shape invariants per the §4.8 contract.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <memory>
#include <set>
#include <string>

namespace {

ldb::protocol::Request make_req(const std::string& method,
                                const nlohmann::json& params = nlohmann::json::object(),
                                const std::string& id = "1") {
  ldb::protocol::Request r;
  r.id = id;
  r.method = method;
  r.params = params;
  return r;
}

// Returns by value (copy) — callers always bind to a `const auto`. We
// previously returned by reference, but that triggered GCC 13's
// -Wdangling-reference when callers chained a temporary like
// `find_endpoint(resp.data["endpoints"], "x")` because the `endpoints`
// subscript yielded a reference into a temporary chain. Copying is
// fine — the catalog is small and tests don't run hot.
nlohmann::json find_endpoint(const nlohmann::json& eps,
                             const std::string& method) {
  for (const auto& e : eps) {
    if (e.value("method", "") == method) return e;
  }
  FAIL("endpoint not found in catalog: " << method);
  return {};  // unreachable
}

// Recursive structural check: object schemas have a `properties` object
// (when present), `required` is an array of strings each appearing in
// `properties`, `items` (if present) is an object schema. `$ref`
// schemas are leaves — they refer into the surrounding `$defs` and
// don't carry their own `type`.
void check_schema_shape(const nlohmann::json& schema,
                        const std::string& where) {
  INFO("schema location: " << where);
  REQUIRE(schema.is_object());
  if (schema.contains("$ref")) {
    REQUIRE(schema["$ref"].is_string());
    return;  // leaf reference, target is in $defs and gets walked there
  }
  // type is optional in JSON Schema generally, but every concrete
  // (non-ref) schema we emit must carry one.
  REQUIRE(schema.contains("type"));
  const auto& type = schema["type"];
  REQUIRE(type.is_string());

  if (type == "object") {
    if (schema.contains("properties")) {
      REQUIRE(schema["properties"].is_object());
      for (auto it = schema["properties"].begin();
           it != schema["properties"].end(); ++it) {
        check_schema_shape(it.value(), where + "/properties/" + it.key());
      }
    }
    if (schema.contains("required")) {
      REQUIRE(schema["required"].is_array());
      // Every required name MUST be listed in properties.
      const auto& props = schema.value("properties", nlohmann::json::object());
      for (const auto& name : schema["required"]) {
        REQUIRE(name.is_string());
        REQUIRE(props.contains(name.get<std::string>()));
      }
    }
  } else if (type == "array") {
    if (schema.contains("items")) {
      // items can be a schema (object) or an array of schemas; we use the
      // schema form throughout.
      check_schema_shape(schema["items"], where + "/items");
    }
  }

  if (schema.contains("$defs")) {
    REQUIRE(schema["$defs"].is_object());
    for (auto it = schema["$defs"].begin(); it != schema["$defs"].end(); ++it) {
      check_schema_shape(it.value(), where + "/$defs/" + it.key());
    }
  }
}

}  // namespace

TEST_CASE("describe.endpoints returns the catalog with new schema shape",
          "[describe][schema]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("endpoints"));
  const auto& eps = resp.data["endpoints"];
  REQUIRE(eps.is_array());
  REQUIRE(eps.size() >= 50);

  static const std::set<std::string> kCostHintValues = {
      "low", "medium", "high", "unbounded"};

  for (const auto& e : eps) {
    INFO("endpoint: " << e.value("method", "<missing>"));
    REQUIRE(e.contains("method"));
    REQUIRE(e["method"].is_string());
    REQUIRE(e.contains("summary"));
    REQUIRE(e["summary"].is_string());
    REQUIRE(e.contains("params_schema"));
    REQUIRE(e.contains("returns_schema"));
    REQUIRE(e.contains("requires_target"));
    REQUIRE(e["requires_target"].is_boolean());
    REQUIRE(e.contains("requires_stopped"));
    REQUIRE(e["requires_stopped"].is_boolean());
    REQUIRE(e.contains("cost_hint"));
    REQUIRE(e["cost_hint"].is_string());
    REQUIRE(kCostHintValues.count(e["cost_hint"].get<std::string>()) == 1);

    check_schema_shape(e["params_schema"],
                       e["method"].get<std::string>() + ":params_schema");
    check_schema_shape(e["returns_schema"],
                       e["method"].get<std::string>() + ":returns_schema");
  }
}

TEST_CASE("describe.endpoints schema for hello documents handshake",
          "[describe][schema][hello]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  const auto e = find_endpoint(resp.data["endpoints"], "hello");

  // params_schema: optional `protocol_min` string of form major.minor.
  const auto& ps = e["params_schema"];
  REQUIRE(ps["type"] == "object");
  REQUIRE(ps["properties"].contains("protocol_min"));
  const auto& pm = ps["properties"]["protocol_min"];
  REQUIRE(pm["type"] == "string");
  REQUIRE(pm.contains("pattern"));
  REQUIRE(pm["pattern"].get<std::string>() == "^[0-9]+\\.[0-9]+$");
  // protocol_min is optional: must NOT appear in required.
  if (ps.contains("required")) {
    for (const auto& k : ps["required"]) {
      REQUIRE(k.get<std::string>() != "protocol_min");
    }
  }

  // returns_schema: protocol object with version/major/minor/min_supported.
  const auto& rs = e["returns_schema"];
  REQUIRE(rs["type"] == "object");
  REQUIRE(rs["properties"].contains("protocol"));
  const auto& proto = rs["properties"]["protocol"];
  REQUIRE(proto["type"] == "object");
  REQUIRE(proto["properties"].contains("version"));
  REQUIRE(proto["properties"].contains("major"));
  REQUIRE(proto["properties"].contains("minor"));
  REQUIRE(proto["properties"].contains("min_supported"));
  REQUIRE(proto["properties"]["version"]["type"] == "string");
  REQUIRE(proto["properties"]["major"]["type"] == "integer");
  REQUIRE(proto["properties"]["minor"]["type"] == "integer");
  REQUIRE(proto["properties"]["min_supported"]["type"] == "string");
}

TEST_CASE("describe.endpoints schema for target.open names path as required",
          "[describe][schema][target]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  const auto e = find_endpoint(resp.data["endpoints"], "target.open");
  const auto& ps = e["params_schema"];
  REQUIRE(ps["type"] == "object");
  REQUIRE(ps["properties"].contains("path"));
  REQUIRE(ps["properties"]["path"]["type"] == "string");
  // path is required
  bool path_required = false;
  for (const auto& r : ps["required"]) {
    if (r == "path") { path_required = true; break; }
  }
  REQUIRE(path_required);
  REQUIRE(e["returns_schema"]["properties"].contains("target_id"));
  REQUIRE(e["returns_schema"]["properties"]["target_id"]["type"] == "integer");
}

TEST_CASE("describe.endpoints schema for mem.read declares address+size required",
          "[describe][schema][mem]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  const auto e = find_endpoint(resp.data["endpoints"], "mem.read");
  const auto& ps = e["params_schema"];
  std::set<std::string> required;
  for (const auto& r : ps["required"]) required.insert(r.get<std::string>());
  REQUIRE(required.count("target_id") == 1);
  REQUIRE(required.count("address") == 1);
  REQUIRE(required.count("size") == 1);
  // returns: address (integer) + bytes (string, hex)
  const auto& rs = e["returns_schema"];
  REQUIRE(rs["properties"]["address"]["type"] == "integer");
  REQUIRE(rs["properties"]["bytes"]["type"] == "string");
  // mem.read needs the inferior live (we need to read its address space).
  REQUIRE(e["requires_stopped"].get<bool>() == false);  // running OR stopped both ok; doc-wise we treat as not strictly stopped
  // mem.read with size up to 1 MiB → high cost bucket.
  REQUIRE(e["cost_hint"] == "high");
}

TEST_CASE("describe.endpoints schema for probe.create lists kind+where required",
          "[describe][schema][probe]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  const auto e = find_endpoint(resp.data["endpoints"], "probe.create");
  const auto& ps = e["params_schema"];
  std::set<std::string> required;
  for (const auto& r : ps["required"]) required.insert(r.get<std::string>());
  REQUIRE(required.count("kind") == 1);
  REQUIRE(required.count("where") == 1);
  REQUIRE(ps["properties"]["kind"]["type"] == "string");
  REQUIRE(ps["properties"]["where"]["type"] == "object");
}

TEST_CASE("describe.endpoints schema for observer.exec has argv array",
          "[describe][schema][observers][exec]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  const auto e = find_endpoint(resp.data["endpoints"], "observer.exec");
  const auto& ps = e["params_schema"];
  REQUIRE(ps["properties"]["argv"]["type"] == "array");
  REQUIRE(ps["properties"]["argv"]["items"]["type"] == "string");
  // observer.exec is host-side, no target.
  REQUIRE(e["requires_target"].get<bool>() == false);
}

TEST_CASE("describe.endpoints flags requires_stopped on frame.* endpoints",
          "[describe][schema][frame]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  for (const auto& m : {"frame.locals", "frame.args", "frame.registers",
                        "value.eval", "value.read"}) {
    const auto e = find_endpoint(resp.data["endpoints"], m);
    INFO("endpoint: " << m);
    REQUIRE(e["requires_stopped"].get<bool>() == true);
  }
}

TEST_CASE("describe.endpoints does not flag requires_stopped on static endpoints",
          "[describe][schema][static]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  for (const auto& m : {"hello", "describe.endpoints",
                        "type.layout", "module.list",
                        "string.list", "disasm.range",
                        "symbol.find"}) {
    const auto e = find_endpoint(resp.data["endpoints"], m);
    INFO("endpoint: " << m);
    REQUIRE(e["requires_stopped"].get<bool>() == false);
  }
}

TEST_CASE("describe.endpoints draft is JSON Schema 2020-12",
          "[describe][schema]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  // We don't require every nested schema to repeat $schema, but at
  // least one top-level schema MUST advertise it so consumers know
  // the dialect.
  bool saw_schema = false;
  for (const auto& e : resp.data["endpoints"]) {
    const std::string draft = "https://json-schema.org/draft/2020-12/schema";
    if (e["params_schema"].value("$schema", "") == draft ||
        e["returns_schema"].value("$schema", "") == draft) {
      saw_schema = true;
      break;
    }
  }
  REQUIRE(saw_schema);
}
