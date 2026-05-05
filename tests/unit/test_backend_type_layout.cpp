// Tests for DebuggerBackend::find_type_layout.
//
// These exercise the LldbBackend impl directly against the structs fixture
// binary. The fixture path is injected at build time via the
// LDB_FIXTURE_STRUCTS_PATH compile define.
//
// Layouts we expect:
//
//   struct point2          : 8 B, align 4, [x@0 sz4, y@4 sz4]
//   struct stride_pad      : 8 B, align 4, [tag@0 sz1 hole=3, value@4 sz4]
//   struct nested          : 16 B, align 8, [origin@0 sz8, scale@8 sz8]
//   struct dxp_login_frame : 16 B, align 8, [magic@0 sz4 hole=4, sid@8 sz8]

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>
#include <string>

using ldb::backend::Field;
using ldb::backend::LldbBackend;
using ldb::backend::TargetId;
using ldb::backend::TypeLayout;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct OpenedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
};

OpenedFixture open_fixture() {
  auto be = std::make_unique<LldbBackend>();
  auto res = be->open_executable(kFixturePath);
  REQUIRE(res.target_id != 0);
  return {std::move(be), res.target_id};
}

const Field* field_named(const TypeLayout& t, const std::string& name) {
  for (const auto& f : t.fields) {
    if (f.name == name) return &f;
  }
  return nullptr;
}

}  // namespace

TEST_CASE("type.layout: simple POD with no padding (struct point2)",
          "[backend][type_layout]") {
  auto fx = open_fixture();
  auto layout = fx.backend->find_type_layout(fx.target_id, "point2");

  REQUIRE(layout.has_value());
  CHECK(layout->name      == "point2");
  CHECK(layout->byte_size == 8);
  CHECK(layout->alignment == 4);
  CHECK(layout->holes_total == 0);

  REQUIRE(layout->fields.size() == 2);

  const auto* x = field_named(*layout, "x");
  REQUIRE(x);
  CHECK(x->offset      == 0);
  CHECK(x->byte_size   == 4);
  CHECK(x->holes_after == 0);

  const auto* y = field_named(*layout, "y");
  REQUIRE(y);
  CHECK(y->offset      == 4);
  CHECK(y->byte_size   == 4);
  CHECK(y->holes_after == 0);
}

TEST_CASE("type.layout: internal hole from char→int alignment (struct stride_pad)",
          "[backend][type_layout]") {
  auto fx = open_fixture();
  auto layout = fx.backend->find_type_layout(fx.target_id, "stride_pad");

  REQUIRE(layout.has_value());
  CHECK(layout->byte_size  == 8);
  CHECK(layout->alignment  == 4);
  CHECK(layout->holes_total == 3);

  REQUIRE(layout->fields.size() == 2);

  const auto* tag = field_named(*layout, "tag");
  REQUIRE(tag);
  CHECK(tag->offset      == 0);
  CHECK(tag->byte_size   == 1);
  CHECK(tag->holes_after == 3);  // alignment hole before next int

  const auto* value = field_named(*layout, "value");
  REQUIRE(value);
  CHECK(value->offset      == 4);
  CHECK(value->byte_size   == 4);
  CHECK(value->holes_after == 0);
}

TEST_CASE("type.layout: nested struct with naturally-aligned double "
          "(struct nested)",
          "[backend][type_layout]") {
  auto fx = open_fixture();
  auto layout = fx.backend->find_type_layout(fx.target_id, "nested");

  REQUIRE(layout.has_value());
  CHECK(layout->byte_size  == 16);
  CHECK(layout->alignment  == 8);
  CHECK(layout->holes_total == 0);

  REQUIRE(layout->fields.size() == 2);

  const auto* origin = field_named(*layout, "origin");
  REQUIRE(origin);
  CHECK(origin->offset      == 0);
  CHECK(origin->byte_size   == 8);   // = sizeof(struct point2)
  CHECK(origin->holes_after == 0);

  const auto* scale = field_named(*layout, "scale");
  REQUIRE(scale);
  CHECK(scale->offset      == 8);
  CHECK(scale->byte_size   == 8);
  CHECK(scale->holes_after == 0);
}

TEST_CASE("type.layout: 4-byte hole from uint32→uint64 (struct dxp_login_frame)",
          "[backend][type_layout]") {
  auto fx = open_fixture();
  auto layout = fx.backend->find_type_layout(fx.target_id, "dxp_login_frame");

  REQUIRE(layout.has_value());
  CHECK(layout->byte_size   == 16);
  CHECK(layout->alignment   == 8);
  CHECK(layout->holes_total == 4);

  REQUIRE(layout->fields.size() == 2);

  const auto* magic = field_named(*layout, "magic");
  REQUIRE(magic);
  CHECK(magic->offset      == 0);
  CHECK(magic->byte_size   == 4);
  CHECK(magic->holes_after == 4);

  const auto* sid = field_named(*layout, "sid");
  REQUIRE(sid);
  CHECK(sid->offset      == 8);
  CHECK(sid->byte_size   == 8);
  CHECK(sid->holes_after == 0);
}

TEST_CASE("type.layout: type names are reported (best-effort)",
          "[backend][type_layout]") {
  auto fx = open_fixture();
  auto layout = fx.backend->find_type_layout(fx.target_id, "dxp_login_frame");
  REQUIRE(layout.has_value());

  const auto* magic = field_named(*layout, "magic");
  REQUIRE(magic);
  // Some compilers report the typedef chain; we accept either the typedef
  // or the canonical name.
  CHECK((magic->type_name == "uint32_t" || magic->type_name == "unsigned int"));

  const auto* sid = field_named(*layout, "sid");
  REQUIRE(sid);
  CHECK((sid->type_name == "uint64_t" || sid->type_name == "unsigned long" ||
         sid->type_name == "unsigned long long"));
}

TEST_CASE("type.layout: unknown type returns nullopt",
          "[backend][type_layout][error]") {
  auto fx = open_fixture();
  auto layout = fx.backend->find_type_layout(
      fx.target_id, "this_type_definitely_does_not_exist_42");
  CHECK_FALSE(layout.has_value());
}

TEST_CASE("type.layout: invalid target_id throws backend::Error",
          "[backend][type_layout][error]") {
  auto fx = open_fixture();
  CHECK_THROWS_AS(
      fx.backend->find_type_layout(/*tid=*/9999, "point2"),
      ldb::backend::Error);
}
