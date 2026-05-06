#include "protocol/provenance.h"

#include <string_view>

namespace ldb::protocol::provenance {

namespace {

constexpr std::string_view kCorePrefix = "core:";

}  // namespace

bool is_deterministic(const std::string& snapshot) {
  if (snapshot.size() <= kCorePrefix.size()) return false;
  return std::string_view(snapshot).substr(0, kCorePrefix.size()) == kCorePrefix;
}

json compute(const std::string& snapshot) {
  json out;
  out["snapshot"] = snapshot;
  out["deterministic"] = is_deterministic(snapshot);
  return out;
}

}  // namespace ldb::protocol::provenance
