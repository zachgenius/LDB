#include "protocol/view.h"

#include <stdexcept>
#include <unordered_set>

namespace ldb::protocol::view {

using nlohmann::json;

Spec parse_from_params(const json& params) {
  Spec out;
  if (!params.is_object()) return out;

  auto vit = params.find("view");
  if (vit == params.end() || vit->is_null()) return out;

  if (!vit->is_object()) {
    throw std::invalid_argument("'view' must be an object");
  }

  if (auto fit = vit->find("fields"); fit != vit->end() && !fit->is_null()) {
    if (!fit->is_array()) {
      throw std::invalid_argument("'view.fields' must be an array of strings");
    }
    for (const auto& f : *fit) {
      if (!f.is_string()) {
        throw std::invalid_argument("'view.fields' entries must be strings");
      }
      out.fields.push_back(f.get<std::string>());
    }
  }

  if (auto lit = vit->find("limit"); lit != vit->end() && !lit->is_null()) {
    if (lit->is_number_unsigned()) {
      out.limit = lit->get<std::uint64_t>();
    } else if (lit->is_number_integer()) {
      auto v = lit->get<std::int64_t>();
      if (v < 0) {
        throw std::invalid_argument("'view.limit' must be non-negative");
      }
      out.limit = static_cast<std::uint64_t>(v);
    } else {
      throw std::invalid_argument(
          "'view.limit' must be a non-negative integer");
    }
  }

  if (auto oit = vit->find("offset"); oit != vit->end() && !oit->is_null()) {
    if (oit->is_number_unsigned()) {
      out.offset = oit->get<std::uint64_t>();
    } else if (oit->is_number_integer()) {
      auto v = oit->get<std::int64_t>();
      if (v < 0) {
        throw std::invalid_argument("'view.offset' must be non-negative");
      }
      out.offset = static_cast<std::uint64_t>(v);
    } else {
      throw std::invalid_argument(
          "'view.offset' must be a non-negative integer");
    }
  }

  if (auto sit = vit->find("summary"); sit != vit->end() && !sit->is_null()) {
    if (!sit->is_boolean()) {
      throw std::invalid_argument("'view.summary' must be a boolean");
    }
    out.summary = sit->get<bool>();
  }

  return out;
}

namespace {

void project_fields(json& item, const std::vector<std::string>& fields) {
  if (fields.empty() || !item.is_object()) return;

  std::unordered_set<std::string> keep(fields.begin(), fields.end());
  for (auto it = item.begin(); it != item.end(); /* */) {
    if (keep.find(it.key()) == keep.end()) {
      it = item.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace

json apply_to_array(json items, const Spec& spec, std::string_view items_key) {
  json out = json::object();

  std::uint64_t total = items.is_array() ? items.size() : 0;
  out["total"] = total;

  if (!items.is_array()) {
    out[std::string(items_key)] = json::array();
    return out;
  }

  if (spec.summary) {
    json sample = json::array();
    std::size_t take = std::min<std::size_t>(items.size(), kSummarySampleSize);
    for (std::size_t i = 0; i < take; ++i) {
      json item = std::move(items[i]);
      project_fields(item, spec.fields);
      sample.push_back(std::move(item));
    }
    out["summary"] = true;
    out[std::string(items_key)] = std::move(sample);
    return out;
  }

  std::uint64_t start = spec.offset;
  if (start > items.size()) start = items.size();
  std::uint64_t end = items.size();
  if (spec.limit.has_value()) {
    std::uint64_t cap = start + *spec.limit;
    if (cap < end) end = cap;
  }

  json sliced = json::array();
  for (std::uint64_t i = start; i < end; ++i) {
    json item = std::move(items[i]);
    project_fields(item, spec.fields);
    sliced.push_back(std::move(item));
  }

  if (end < total) {
    out["next_offset"] = end;
  }

  out[std::string(items_key)] = std::move(sliced);
  return out;
}

}  // namespace ldb::protocol::view
