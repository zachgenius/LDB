// SPDX-License-Identifier: Apache-2.0
//
// Minimal C++ fixture for symbol.find demangled-name lookup tests
// (papercut #3 from the cffex_server RE pass).
//
// Provides a class with a non-trivial method, declared in a namespace
// so the demangled name is `ldb_fix::Widget::poke(int)`. The intent is
// only to exercise the symbol-search code path; the program does just
// enough work to keep DCE from dropping the symbols.

#include <cstdint>

namespace ldb_fix {

class Widget {
 public:
  Widget() = default;
  // Out-of-line so the linker emits a discrete symbol.
  std::int64_t poke(std::int64_t x);
};

std::int64_t Widget::poke(std::int64_t x) {
  // Trivial body — keep the symbol non-empty.
  std::int64_t y = x;
  for (int i = 0; i < 3; ++i) y = (y * 31) + 7;
  return y;
}

}  // namespace ldb_fix

int main(int argc, char** /*argv*/) {
  ldb_fix::Widget w;
  return static_cast<int>(w.poke(static_cast<std::int64_t>(argc)) & 0xFF);
}
