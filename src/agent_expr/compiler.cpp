// SPDX-License-Identifier: Apache-2.0
#include "agent_expr/compiler.h"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ldb::agent_expr {

namespace {

// --- Tokens -----------------------------------------------------------

enum class Tok {
  kLparen,
  kRparen,
  kInt,
  kSymbol,
  kString,
  kEof,
};

struct Token {
  Tok          kind = Tok::kEof;
  std::string  text;      // raw for symbols / string contents (unescaped)
  std::int64_t int_value = 0;
  std::size_t  line   = 1;
  std::size_t  column = 1;
};

// Tokeniser tracks 1-based line/column. Skips whitespace and
// `;` line comments.
struct Lexer {
  std::string_view  src;
  std::size_t       pos    = 0;
  std::size_t       line   = 1;
  std::size_t       column = 1;

  bool at_end() const { return pos >= src.size(); }

  char peek() const { return at_end() ? '\0' : src[pos]; }

  void advance() {
    if (at_end()) return;
    if (src[pos] == '\n') { ++line; column = 1; }
    else                  { ++column; }
    ++pos;
  }

  void skip_ws_and_comments() {
    while (!at_end()) {
      char c = src[pos];
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        advance();
      } else if (c == ';') {
        // line comment to end-of-line
        while (!at_end() && src[pos] != '\n') advance();
      } else {
        break;
      }
    }
  }

  Token next(std::string* err) {
    skip_ws_and_comments();
    Token t;
    t.line = line;
    t.column = column;
    if (at_end()) { t.kind = Tok::kEof; return t; }
    char c = src[pos];
    if (c == '(') { advance(); t.kind = Tok::kLparen; return t; }
    if (c == ')') { advance(); t.kind = Tok::kRparen; return t; }
    if (c == '"') {
      advance();   // consume "
      std::string s;
      while (!at_end() && src[pos] != '"') {
        if (src[pos] == '\\' && pos + 1 < src.size()) {
          char n = src[pos + 1];
          advance(); advance();
          switch (n) {
            case '"': s.push_back('"'); break;
            case '\\': s.push_back('\\'); break;
            case 'n': s.push_back('\n'); break;
            case 't': s.push_back('\t'); break;
            default:  s.push_back(n);    break;
          }
        } else {
          s.push_back(src[pos]);
          advance();
        }
      }
      if (at_end()) { *err = "unterminated string literal"; t.kind = Tok::kEof; return t; }
      advance();  // consume closing "
      t.kind = Tok::kString;
      t.text = std::move(s);
      return t;
    }
    // Integer (possibly negative) or symbol. Integers: optional -,
    // then digits, optionally 0x-hex.
    auto is_sym_char = [](char ch) {
      return std::isalnum(static_cast<unsigned char>(ch))
          || ch == '_' || ch == '-' || ch == '+'
          || ch == '?' || ch == '!' || ch == '/' || ch == '.';
    };
    if (c == '-' || c == '+' || (c >= '0' && c <= '9')) {
      // Could be integer. Try to parse.
      std::size_t start = pos;
      std::size_t scol  = column;
      std::size_t sline = line;
      // Consume one sign char if leading.
      if (c == '-' || c == '+') advance();
      bool any_digit = false;
      bool is_hex = false;
      if (!at_end() && src[pos] == '0' && pos + 1 < src.size()
          && (src[pos+1] == 'x' || src[pos+1] == 'X')) {
        advance(); advance();
        is_hex = true;
      }
      while (!at_end()) {
        char ch = src[pos];
        bool ok = is_hex
            ? (std::isxdigit(static_cast<unsigned char>(ch)) != 0)
            : (std::isdigit(static_cast<unsigned char>(ch)) != 0);
        if (!ok) break;
        any_digit = true;
        advance();
      }
      if (any_digit && (at_end() || !is_sym_char(src[pos]))) {
        std::string lit(src.substr(start, pos - start));
        // strtoll handles 0x via base=0. It doesn't throw; overflow
        // sets errno to ERANGE and saturates to LLONG_MIN/MAX, and a
        // partial parse leaves `endp` short of the end. Both cases
        // must surface as compile errors — silently truncating
        // `(const 99999999999999999999)` to LLONG_MAX produces a
        // predicate that behaves nothing like what the agent wrote.
        errno = 0;
        char* endp = nullptr;
        std::int64_t v = std::strtoll(lit.c_str(), &endp, 0);
        if (errno == ERANGE ||
            endp == nullptr ||
            endp != lit.c_str() + lit.size()) {
          *err = "invalid integer literal '" + lit + "'";
          t.kind = Tok::kEof;
          t.line = sline; t.column = scol;
          return t;
        }
        t.kind = Tok::kInt;
        t.int_value = v;
        t.line = sline; t.column = scol;
        return t;
      }
      // Not a valid int — fall through to symbol parsing from `start`.
      pos = start; line = sline; column = scol;
    }
    // Symbol: any run of sym chars.
    if (is_sym_char(c)) {
      std::size_t scol = column;
      std::size_t sline = line;
      std::size_t start = pos;
      while (!at_end() && is_sym_char(src[pos])) advance();
      t.kind = Tok::kSymbol;
      t.text = std::string(src.substr(start, pos - start));
      t.line = sline; t.column = scol;
      return t;
    }
    *err = std::string("unexpected character '") + c + "'";
    t.kind = Tok::kEof;
    return t;
  }
};

// --- Opcode dispatch ---------------------------------------------------

// Maps DSL op-name → opcode + expected arity.
struct OpInfo {
  Op           opcode;
  int          arity;     // # of operands (always emitted before opcode)
  // -1 in `arity` means "use the *_n form" (none today; placeholder).
};

const std::unordered_map<std::string, OpInfo>& op_table() {
  static const std::unordered_map<std::string, OpInfo> kT = {
      // Memory deref.
      {"ref8",  {Op::kRef8,  1}},
      {"ref16", {Op::kRef16, 1}},
      {"ref32", {Op::kRef32, 1}},
      {"ref64", {Op::kRef64, 1}},
      // Arithmetic.
      {"add",   {Op::kAdd,        2}},
      {"sub",   {Op::kSub,        2}},
      {"mul",   {Op::kMul,        2}},
      {"div",   {Op::kDivSigned,  2}},
      // Comparison.
      {"eq", {Op::kEq,        2}},
      {"ne", {Op::kNe,        2}},
      {"lt", {Op::kLtSigned,  2}},
      {"le", {Op::kLeSigned,  2}},
      {"gt", {Op::kGtSigned,  2}},
      {"ge", {Op::kGeSigned,  2}},
      // Bitwise — "and"/"or"/"xor"/"not" are the bitwise forms;
      // "land"/"lor"/"lnot" are logical (gdb spec spelling).
      {"and",  {Op::kBitAnd, 2}},
      {"or",   {Op::kBitOr,  2}},
      {"xor",  {Op::kBitXor, 2}},
      {"not",  {Op::kBitNot, 1}},
      {"land", {Op::kLogAnd, 2}},
      {"lor",  {Op::kLogOr,  2}},
      {"lnot", {Op::kLogNot, 1}},
  };
  return kT;
}

// --- Compiler state ----------------------------------------------------

struct State {
  Program  prog;
  std::unordered_map<std::string, std::uint16_t> reg_idx;

  std::uint16_t intern_reg(const std::string& name) {
    auto [it, inserted] = reg_idx.emplace(name,
        static_cast<std::uint16_t>(prog.reg_table.size()));
    if (inserted) prog.reg_table.push_back(name);
    return it->second;
  }

  void emit_const(std::int64_t v) {
    if (v >= -128 && v <= 127) {
      prog.code.push_back(static_cast<std::uint8_t>(Op::kConst8));
      prog.code.push_back(static_cast<std::uint8_t>(v & 0xff));
      return;
    }
    if (v >= -32768 && v <= 32767) {
      prog.code.push_back(static_cast<std::uint8_t>(Op::kConst16));
      prog.code.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
      prog.code.push_back(static_cast<std::uint8_t>( v       & 0xff));
      return;
    }
    if (v >= -2147483648LL && v <= 2147483647LL) {
      prog.code.push_back(static_cast<std::uint8_t>(Op::kConst32));
      prog.code.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
      prog.code.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
      prog.code.push_back(static_cast<std::uint8_t>((v >>  8) & 0xff));
      prog.code.push_back(static_cast<std::uint8_t>( v        & 0xff));
      return;
    }
    prog.code.push_back(static_cast<std::uint8_t>(Op::kConst64));
    for (int i = 7; i >= 0; --i) {
      prog.code.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xff));
    }
  }

  void emit_reg(std::uint16_t idx) {
    prog.code.push_back(static_cast<std::uint8_t>(Op::kReg));
    prog.code.push_back(static_cast<std::uint8_t>((idx >> 8) & 0xff));
    prog.code.push_back(static_cast<std::uint8_t>( idx       & 0xff));
  }

  void emit_op(Op op) {
    prog.code.push_back(static_cast<std::uint8_t>(op));
  }
};

// --- Parser + codegen --------------------------------------------------
//
// Reports errors via thrown CompileError. The compile() entry point
// catches and returns a CompileResult.

struct ParseFail {
  CompileError err;
};

[[noreturn]] void fail(std::size_t line, std::size_t col,
                       std::string msg) {
  ParseFail f;
  f.err.line    = line;
  f.err.column  = col;
  f.err.message = std::move(msg);
  throw f;
}

struct Parser {
  Lexer  lex;
  Token  cur;
  State* st;

  void prime() {
    std::string err;
    cur = lex.next(&err);
    if (!err.empty()) fail(cur.line, cur.column, err);
  }

  void advance() {
    std::string err;
    cur = lex.next(&err);
    if (!err.empty()) fail(cur.line, cur.column, err);
  }

  // Compile one expression at `cur`, advancing past it. Emits bytecode
  // that pushes its result.
  void compile_expr() {
    switch (cur.kind) {
      case Tok::kInt:
        st->emit_const(cur.int_value);
        advance();
        return;
      case Tok::kSymbol:
        fail(cur.line, cur.column,
             std::string("unexpected identifier '") + cur.text +
             "' — wrap registers in (reg \"" + cur.text + "\")");
      case Tok::kString:
        fail(cur.line, cur.column,
             "string literal at top level (only valid inside (reg \"...\"))");
      case Tok::kLparen:
        compile_list();
        return;
      default:
        fail(cur.line, cur.column,
             "expected expression, got end of input");
    }
  }

  void compile_list() {
    auto open_line = cur.line, open_col = cur.column;
    advance();  // consume '('
    if (cur.kind != Tok::kSymbol) {
      fail(cur.line, cur.column, "expected operator after '('");
    }
    std::string op = cur.text;
    auto op_line = cur.line, op_col = cur.column;
    advance();

    // Special forms first.
    if (op == "reg") {
      if (cur.kind != Tok::kString) {
        fail(cur.line, cur.column,
             "reg expects a string register name");
      }
      if (cur.text.empty()) {
        fail(cur.line, cur.column,
             "reg name must be non-empty");
      }
      std::uint16_t idx = st->intern_reg(cur.text);
      st->emit_reg(idx);
      advance();
      if (cur.kind != Tok::kRparen) {
        fail(cur.line, cur.column,
             "reg expects exactly 1 argument");
      }
      advance();
      return;
    }
    if (op == "const") {
      if (cur.kind != Tok::kInt) {
        fail(cur.line, cur.column,
             "const expects an integer literal");
      }
      st->emit_const(cur.int_value);
      advance();
      if (cur.kind != Tok::kRparen) {
        fail(cur.line, cur.column,
             "const expects exactly 1 argument");
      }
      advance();
      return;
    }
    if (op == "begin") {
      // Compile each form; after every form except the last, emit kDrop
      // so only the final result remains on the stack.
      bool first = true;
      bool any = false;
      while (cur.kind != Tok::kRparen && cur.kind != Tok::kEof) {
        if (!first) {
          st->emit_op(Op::kDrop);
        }
        compile_expr();
        first = false;
        any = true;
      }
      if (cur.kind != Tok::kRparen) {
        fail(open_line, open_col, "expected ')' to close 'begin'");
      }
      if (!any) {
        // (begin) with no forms — push 0 so the program still has a
        // value at end.
        st->emit_const(0);
      }
      advance();
      return;
    }

    // Generic op dispatch via op_table.
    auto& tbl = op_table();
    auto it = tbl.find(op);
    if (it == tbl.end()) {
      fail(op_line, op_col,
           std::string("unknown opcode '") + op + "'");
    }
    int arity = it->second.arity;
    int got = 0;
    while (cur.kind != Tok::kRparen && cur.kind != Tok::kEof) {
      compile_expr();
      ++got;
    }
    if (cur.kind != Tok::kRparen) {
      fail(open_line, open_col,
           std::string("expected ')' to close '") + op + "'");
    }
    if (got != arity) {
      fail(op_line, op_col,
           op + " expects " + std::to_string(arity) +
           " arguments, got " + std::to_string(got));
    }
    st->emit_op(it->second.opcode);
    advance();
  }
};

}  // namespace

CompileResult compile(std::string_view source) {
  CompileResult out;

  if (source.size() > kMaxSourceBytes) {
    CompileError e;
    e.line = 1; e.column = 1;
    e.message = "source exceeds kMaxSourceBytes (" +
                std::to_string(kMaxSourceBytes) + ")";
    out.error = std::move(e);
    return out;
  }

  State st;
  Parser p;
  p.lex.src = source;
  p.st = &st;

  try {
    p.prime();
    if (p.cur.kind == Tok::kEof) {
      // Empty source — emit just kEnd. Eval returns 0 (always-false
      // predicate); useful for "no predicate installed yet" callers.
      st.emit_op(Op::kEnd);
      out.program = std::move(st.prog);
      return out;
    }
    p.compile_expr();
    // Allow trailing whitespace / comments but reject trailing tokens.
    if (p.cur.kind != Tok::kEof) {
      fail(p.cur.line, p.cur.column,
           "unexpected trailing token after expression");
    }
    st.emit_op(Op::kEnd);
    out.program = std::move(st.prog);
    return out;
  } catch (const ParseFail& f) {
    out.error = f.err;
    return out;
  }
}

}  // namespace ldb::agent_expr
