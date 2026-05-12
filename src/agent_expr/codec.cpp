// SPDX-License-Identifier: Apache-2.0
#include "agent_expr/bytecode.h"

#include <cstring>

namespace ldb::agent_expr {

namespace {

void put_u16(std::vector<std::uint8_t>* out, std::uint16_t v) {
  out->push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
  out->push_back(static_cast<std::uint8_t>( v       & 0xff));
}

void put_u32(std::vector<std::uint8_t>* out, std::uint32_t v) {
  out->push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
  out->push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
  out->push_back(static_cast<std::uint8_t>((v >>  8) & 0xff));
  out->push_back(static_cast<std::uint8_t>( v        & 0xff));
}

bool read_u16(const std::uint8_t* p, std::size_t avail, std::uint16_t* out) {
  if (avail < 2) return false;
  *out = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
  return true;
}

bool read_u32(const std::uint8_t* p, std::size_t avail, std::uint32_t* out) {
  if (avail < 4) return false;
  *out = (static_cast<std::uint32_t>(p[0]) << 24)
       | (static_cast<std::uint32_t>(p[1]) << 16)
       | (static_cast<std::uint32_t>(p[2]) <<  8)
       |  static_cast<std::uint32_t>(p[3]);
  return true;
}

}  // namespace

std::vector<std::uint8_t> encode(const Program& prog) {
  std::vector<std::uint8_t> out;
  out.reserve(4 + prog.code.size() + 2 +
              prog.reg_table.size() * 16);
  put_u32(&out, static_cast<std::uint32_t>(prog.code.size()));
  out.insert(out.end(), prog.code.begin(), prog.code.end());
  put_u16(&out, static_cast<std::uint16_t>(prog.reg_table.size()));
  for (const auto& name : prog.reg_table) {
    put_u16(&out, static_cast<std::uint16_t>(name.size()));
    out.insert(out.end(), name.begin(), name.end());
  }
  return out;
}

std::optional<Program> decode(std::string_view bytes) {
  const auto* p   = reinterpret_cast<const std::uint8_t*>(bytes.data());
  std::size_t left = bytes.size();
  std::uint32_t code_size = 0;
  if (!read_u32(p, left, &code_size)) return std::nullopt;
  p += 4; left -= 4;
  // Anti-DoS — refuse before allocating.
  if (code_size > kMaxProgramBytes) return std::nullopt;
  if (left < code_size) return std::nullopt;

  Program prog;
  prog.code.assign(p, p + code_size);
  p += code_size; left -= code_size;

  std::uint16_t reg_count = 0;
  if (!read_u16(p, left, &reg_count)) return std::nullopt;
  p += 2; left -= 2;
  prog.reg_table.reserve(reg_count);
  for (std::uint16_t i = 0; i < reg_count; ++i) {
    std::uint16_t name_len = 0;
    if (!read_u16(p, left, &name_len)) return std::nullopt;
    p += 2; left -= 2;
    if (left < name_len) return std::nullopt;
    prog.reg_table.emplace_back(reinterpret_cast<const char*>(p), name_len);
    p += name_len; left -= name_len;
  }
  return prog;
}

std::string_view mnemonic(Op op) {
  switch (op) {
    case Op::kEnd:        return "end";
    case Op::kConst8:     return "const8";
    case Op::kConst16:    return "const16";
    case Op::kConst32:    return "const32";
    case Op::kConst64:    return "const64";
    case Op::kReg:        return "reg";
    case Op::kRef8:       return "ref8";
    case Op::kRef16:      return "ref16";
    case Op::kRef32:      return "ref32";
    case Op::kRef64:      return "ref64";
    case Op::kAdd:        return "add";
    case Op::kSub:        return "sub";
    case Op::kMul:        return "mul";
    case Op::kDivSigned:  return "div_signed";
    case Op::kEq:         return "eq";
    case Op::kNe:         return "ne";
    case Op::kLtSigned:   return "lt_signed";
    case Op::kLeSigned:   return "le_signed";
    case Op::kGtSigned:   return "gt_signed";
    case Op::kGeSigned:   return "ge_signed";
    case Op::kBitAnd:     return "bit_and";
    case Op::kBitOr:      return "bit_or";
    case Op::kBitXor:     return "bit_xor";
    case Op::kBitNot:     return "bit_not";
    case Op::kLogAnd:     return "log_and";
    case Op::kLogOr:      return "log_or";
    case Op::kLogNot:     return "log_not";
    case Op::kDup:        return "dup";
    case Op::kDrop:       return "drop";
    case Op::kSwap:       return "swap";
    case Op::kIfGoto:     return "if_goto";
    case Op::kGoto:       return "goto";
  }
  return "";
}

}  // namespace ldb::agent_expr
