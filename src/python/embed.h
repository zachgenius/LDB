// SPDX-License-Identifier: Apache-2.0
#pragma once

// Embedded CPython wrapper — post-V1 plan #9, see docs/20-embedded-python.md.
//
// Surfaces:
//   • Interpreter (singleton, lazy Py_Initialize, GIL acquire-on-invoke).
//   • Callable    (a compiled Python module + its `run` callable, ref-counted).
//
// The whole header is compiled to a no-op when LDB_ENABLE_PYTHON is OFF —
// callers that include this still get the type declarations so the
// recipe-store / dispatcher don't have to be #ifdef'd at every use site;
// the methods just throw backend::Error("python: disabled") in that
// configuration.

#include <nlohmann/json.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace ldb::python {

// Lazy-initialized CPython embedding. Construction of the singleton is
// thread-safe; once initialized, every Callable::invoke acquires the
// GIL via PyGILState_Ensure before touching PyObject*.
//
// The interpreter is NOT finalized explicitly — process exit handles
// it. Py_Finalize is known-imperfect with held PyObject references
// (Callable destructors at static-storage teardown), and the leak is
// acceptable for a process that's going away anyway.
class Interpreter {
 public:
  // Returns the singleton, initializing CPython on first call.
  // Throws backend::Error if LDB_ENABLE_PYTHON is OFF or Py_Initialize
  // fails for any reason.
  static Interpreter& instance();

  // True if Python is compiled-in AND init succeeded. Test hook;
  // production code should use Callable directly and let the
  // backend::Error propagate.
  static bool available() noexcept;

  Interpreter(const Interpreter&)            = delete;
  Interpreter& operator=(const Interpreter&) = delete;

 private:
  Interpreter();
  ~Interpreter();

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// A compiled Python module + a reference to its top-level `run`
// callable. Callable construction:
//   • Initializes the interpreter on first use.
//   • Compiles `module_source` via Py_CompileString.
//   • Executes the compiled module into a fresh dict (no shared
//     globals across Callable instances — every recipe is isolated).
//   • Looks up `run` in the module dict; failure throws backend::Error.
//
// Callable::invoke:
//   • Acquires the GIL.
//   • Converts the JSON arg into a Python value.
//   • Calls run(arg).
//   • Captures sys.stdout / sys.stderr snapshots from the per-call
//     StringIO buffers; truncates each to 8 KiB.
//   • Converts the return value back to JSON.
//   • On any exception, captures the traceback and throws
//     backend::Error("python: <type>: <msg>") with structured fields
//     accessible via last_exception_*() / last_traceback().
//
// Callables are not thread-safe in v1.4 — the dispatcher is single-
// threaded. Future probe-callback work will need per-Callable mutexes
// or a Callable pool; tracked in docs/20-embedded-python.md §12.
class Callable {
 public:
  // Compile module_source and look up run. `origin` is used in the
  // co_filename slot so tracebacks point at something readable
  // ("<recipe:name>" is the typical value).
  Callable(std::string_view module_source, std::string_view origin);
  ~Callable();

  Callable(const Callable&)            = delete;
  Callable& operator=(const Callable&) = delete;

  // Invoke run(arg). Returns the JSON form of run's return value.
  // Throws backend::Error on any Python-side exception (compile errors
  // are caught at construction; this only sees runtime exceptions).
  nlohmann::json invoke(const nlohmann::json& arg);

  // Snapshot of the last invoke's stdout / stderr capture, truncated
  // to 8 KiB each. Empty before the first invoke.
  const std::string& last_stdout()  const noexcept;
  const std::string& last_stderr()  const noexcept;

  // Structured fields populated by invoke() on a Python exception.
  // Empty when the most recent invoke succeeded.
  const std::string& last_exception_type()    const noexcept;
  const std::string& last_exception_message() const noexcept;
  const std::string& last_traceback()         const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::python
