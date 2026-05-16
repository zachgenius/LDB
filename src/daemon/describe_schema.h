// SPDX-License-Identifier: Apache-2.0
// describe_schema.h — JSON Schema (draft 2020-12) helpers used by
// `describe.endpoints` (M5, plan §4.8).
//
// `describe.endpoints` returns the full method catalog as proper JSON
// Schema — not the prose-y `params: {key:"type-name"}` shape that
// shipped through M4. Agents that read this catalog at session start
// can generate typed bindings or validate their own requests without
// parsing the docstring.
//
// The helpers here are tiny intentionally: each returns an
// `nlohmann::json` so the call site in `dispatcher.cpp` reads almost
// like prose — `obj({{"target_id", target_id_param()}}, {"target_id"})`.
//
// Style decision: free functions in `ldb::daemon::schema` rather than a
// class. There is no state to carry, and the call sites are dense
// enough that an `s::` qualifier just clutters them.

#pragma once

#include <nlohmann/json.hpp>

#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldb::daemon::schema {

using nlohmann::json;

inline constexpr const char* kDraft = "https://json-schema.org/draft/2020-12/schema";

// ---------- primitive type builders ----------

inline json str(std::string_view desc = "") {
  json j;
  j["type"] = "string";
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json str_pattern(std::string pattern, std::string_view desc = "") {
  json j;
  j["type"] = "string";
  j["pattern"] = std::move(pattern);
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

// JSON Schema integer (any integer ≥ 0 by default; pass min/max overrides).
inline json uint_(std::string_view desc = "") {
  json j;
  j["type"] = "integer";
  j["minimum"] = 0;
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json uint_min(std::int64_t minimum, std::string_view desc = "") {
  json j;
  j["type"] = "integer";
  j["minimum"] = minimum;
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json uint_range(std::int64_t minimum, std::int64_t maximum,
                       std::string_view desc = "") {
  json j;
  j["type"] = "integer";
  j["minimum"] = minimum;
  j["maximum"] = maximum;
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json int_(std::string_view desc = "") {
  json j;
  j["type"] = "integer";
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json bool_(std::string_view desc = "") {
  json j;
  j["type"] = "boolean";
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json hex_string(std::string_view desc = "") {
  json j;
  j["type"] = "string";
  j["pattern"] = "^[0-9a-fA-F]*$";
  std::string d = "lower-case packed hex";
  if (!desc.empty()) {
    d.append(" — ").append(desc);
  }
  j["description"] = std::move(d);
  return j;
}

inline json enum_str(std::initializer_list<std::string_view> values,
                     std::string_view desc = "") {
  json j;
  j["type"] = "string";
  json arr = json::array();
  for (auto v : values) arr.push_back(std::string(v));
  j["enum"] = std::move(arr);
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

// ---------- composite builders ----------

// Object schema with explicit property table and required list.
//
// Pattern: `obj({{"name", str()}, {"size", uint_()}}, {"name", "size"})`.
// Properties not listed in `required` are implicitly optional (the
// project convention so far).
inline json obj(std::initializer_list<std::pair<std::string_view, json>> props,
                std::initializer_list<std::string_view> required = {}) {
  json j;
  j["type"] = "object";
  json p = json::object();
  for (const auto& [k, v] : props) p[std::string(k)] = v;
  j["properties"] = std::move(p);
  if (required.size()) {
    json r = json::array();
    for (auto k : required) r.push_back(std::string(k));
    j["required"] = std::move(r);
  }
  return j;
}

// "Open" object — no fixed property list; arbitrary keys allowed.
inline json obj_open(std::string_view desc = "") {
  json j;
  j["type"] = "object";
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

inline json arr_of(json items, std::string_view desc = "") {
  json j;
  j["type"] = "array";
  j["items"] = std::move(items);
  if (!desc.empty()) j["description"] = std::string(desc);
  return j;
}

// Reference into the surrounding schema's $defs.
inline json ref(std::string_view name) {
  json j;
  j["$ref"] = std::string("#/$defs/") + std::string(name);
  return j;
}

// Convenience: tag a top-level schema with the draft id.
inline json with_draft(json j) {
  j["$schema"] = kDraft;
  return j;
}

// Attach a `$defs` block to a schema and return by value. Pattern-matches
// the `merge_patch` shape we used in the first pass but with the right
// return type — `merge_patch` itself is void.
inline json with_defs(json schema,
                      std::initializer_list<std::pair<std::string_view, json>> defs) {
  json d = json::object();
  for (const auto& [k, v] : defs) d[std::string(k)] = v;
  schema["$defs"] = std::move(d);
  return schema;
}

// ---------- common parameter fragments ----------
//
// These show up on dozens of endpoints. Defining them once keeps the
// catalog readable and means a description tweak hits everywhere.

inline json target_id_param() {
  return uint_min(1, "Opaque integer handle returned by target.open / "
                     "target.create_empty.");
}

inline json optional_target_id_param() {
  return uint_min(1, "Optional target binding for probes that attach to "
                     "a specific target. Omit for host-side probes.");
}

inline json pid_param() {
  return uint_min(1, "Operating-system process id.");
}

inline json tid_param() {
  return uint_min(1, "Thread id (LLDB SBThread::GetThreadID() — typically "
                     "the kernel TID on Linux, the Mach port on Darwin).");
}

inline json frame_index_param() {
  return uint_("Stack frame index, innermost first. Default 0.");
}

inline json address_param() {
  return uint_("Runtime virtual address (uint64).");
}

inline json size_param() {
  return uint_("Byte count.");
}

inline json host_param() {
  return str("Optional `[user@]host` for ssh dispatch. When absent the "
             "daemon's own host is queried via local exec.");
}

inline json view_param() {
  return obj({
      {"limit",   uint_("Cap returned items.")},
      {"offset",  uint_("Skip leading items.")},
      {"fields",  arr_of(str(), "Project to a subset of keys.")},
      {"summary", bool_("Return only counts/aggregates, no items.")},
  });
}

// ---------- common returned shapes ----------

inline json module_def() {
  return obj({
      {"name",          str()},
      {"path",          str()},
      {"build_id",      str()},
      {"uuid",          str()},
      {"file_addr",     uint_()},
      {"load_addr",     uint_()},
      {"section_count", uint_("Total top-level + nested sections. Always "
                              "populated, even when the `sections` array is "
                              "absent (cheap target.open shape).")},
      {"sections",      arr_of(obj({
          {"name", str()},
          {"file_addr", uint_()},
          {"load_addr", uint_()},
          {"size",      uint_()},
          {"perm",      str()},
          {"type",      str()},
      }), "Inline only when the endpoint walked the section table "
          "(module.list / load_core, or target.open with "
          "view.include_sections=true). Absent on default target.open "
          "responses — call module.list to enumerate.")},
  });
}

inline json field_def() {
  return obj({
      {"name", str()},
      {"type", str()},
      {"off",  uint_("Byte offset from struct start.")},
      {"sz",   uint_("Byte size.")},
  });
}

inline json value_info_def() {
  return obj({
      {"name",    str()},
      {"type",    str()},
      {"address", uint_()},
      {"bytes",   hex_string()},
      {"summary", str()},
      {"kind",    enum_str({"scalar", "pointer", "struct", "array", "other"})},
  });
}

inline json thread_info_def() {
  return obj({
      {"tid",         uint_()},
      {"index",       uint_()},
      {"state",       str()},
      {"pc",          uint_()},
      {"sp",          uint_()},
      {"name",        str()},
      {"stop_reason", str()},
  });
}

inline json frame_info_def() {
  return obj({
      {"index",    uint_()},
      {"pc",       uint_()},
      {"fp",       uint_()},
      {"sp",       uint_()},
      {"function", str()},
      {"module",   str()},
      {"file",     str()},
      {"line",     uint_()},
      {"inlined",  bool_()},
  });
}

inline json memory_region_def() {
  return obj({
      {"base", uint_()},
      {"size", uint_()},
      {"r",    bool_()},
      {"w",    bool_()},
      {"x",    bool_()},
      {"name", str()},
  });
}

inline json disasm_insn_def() {
  return obj({
      {"addr",     uint_("Instruction address. Alias of `address` "
                         "(both are always emitted; either may be used "
                         "in --view fields=...).")},
      {"address",  uint_("Instruction address. Alias of `addr`, "
                         "matching the field name used at the "
                         "disasm.function / disasm.range top level "
                         "and by mem.read.")},
      {"sz",       uint_()},
      {"bytes",    hex_string()},
      {"mnemonic", str()},
      {"operands", str()},
      {"comment",  str()},
  });
}

inline json symbol_match_def() {
  return obj({
      {"name",    str()},
      {"kind",    str()},
      {"addr",    uint_()},
      {"sz",      uint_()},
      {"module",  str()},
      {"mangled", str()},
  });
}

inline json global_var_match_def() {
  return obj({
      {"name",      str()},
      {"type",      str("DWARF type name as SBValue::GetTypeName() "
                        "reports it (verbatim).")},
      {"addr",      uint_("File (unrelocated) address.")},
      {"load_addr", uint_("Runtime address. Present only when the "
                          "target has an attached process.")},
      {"sz",        uint_()},
      {"module",    str("Basename of the owning module.")},
      {"file",      str("Declaration source file basename, when DWARF "
                        "carries it.")},
      {"line",      uint_("Declaration line, when DWARF carries it.")},
  });
}

inline json string_entry_def() {
  return obj({
      {"text",    str()},
      {"addr",    uint_()},
      {"section", str()},
      {"module",  str()},
  });
}

inline json xref_match_def() {
  return obj({
      {"addr",     uint_()},
      {"sz",       uint_()},
      {"mnemonic", str()},
      {"operands", str()},
      {"function", str()},
      {"comment",  str()},
  });
}

inline json process_state_def() {
  return obj({
      {"state", str()},
      {"pid",   int_()},
  });
}

}  // namespace ldb::daemon::schema
