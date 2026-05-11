// SPDX-License-Identifier: Apache-2.0
#include "python/embed.h"

#include "backend/debugger_backend.h"   // backend::Error

#include <mutex>
#include <optional>
#include <string>

#if defined(LDB_ENABLE_PYTHON) && LDB_ENABLE_PYTHON
#  define PY_SSIZE_T_CLEAN
#  include <Python.h>
#endif

namespace ldb::python {

namespace {

[[noreturn]] void throw_disabled() {
  throw backend::Error(
      "python: embedded Python disabled at build time "
      "(reconfigure with -DLDB_ENABLE_PYTHON=ON and "
      "python3-embed>=3.11 available)");
}

#if defined(LDB_ENABLE_PYTHON) && LDB_ENABLE_PYTHON

constexpr std::size_t kCaptureMax = 8 * 1024;
constexpr int         kRecursionMax = 1024;

// RAII GIL holder. Acquires on construction, releases on destruction.
class GilHold {
 public:
  GilHold() : state_(PyGILState_Ensure()) {}
  ~GilHold() { PyGILState_Release(state_); }
  GilHold(const GilHold&)            = delete;
  GilHold& operator=(const GilHold&) = delete;
 private:
  PyGILState_STATE state_;
};

// RAII owned PyObject*.
class PyRef {
 public:
  PyRef() = default;
  explicit PyRef(PyObject* obj) : obj_(obj) {}
  ~PyRef() { Py_XDECREF(obj_); }
  PyRef(PyRef&& other) noexcept : obj_(other.obj_) { other.obj_ = nullptr; }
  PyRef& operator=(PyRef&& other) noexcept {
    if (this != &other) {
      Py_XDECREF(obj_);
      obj_ = other.obj_;
      other.obj_ = nullptr;
    }
    return *this;
  }
  PyRef(const PyRef&)            = delete;
  PyRef& operator=(const PyRef&) = delete;

  PyObject* get()     const noexcept { return obj_; }
  PyObject* release() noexcept { auto p = obj_; obj_ = nullptr; return p; }
  explicit operator bool() const noexcept { return obj_ != nullptr; }

 private:
  PyObject* obj_ = nullptr;
};

// Forward decls.
nlohmann::json py_to_json(PyObject* obj, int depth);
PyRef          json_to_py(const nlohmann::json& v, int depth);

std::string py_obj_to_str(PyObject* obj) {
  if (!obj) return {};
  PyRef s(PyObject_Str(obj));
  if (!s) { PyErr_Clear(); return "<unprintable>"; }
  const char* c = PyUnicode_AsUTF8(s.get());
  return c ? std::string(c) : std::string("<non-utf8>");
}

nlohmann::json py_to_json(PyObject* obj, int depth) {
  if (depth > kRecursionMax) {
    throw backend::Error("python: return value exceeds recursion limit");
  }
  if (obj == nullptr || obj == Py_None) {
    return nlohmann::json(nullptr);
  }
  if (PyBool_Check(obj)) {
    return nlohmann::json(obj == Py_True);
  }
  if (PyLong_Check(obj)) {
    int overflow = 0;
    long long v = PyLong_AsLongLongAndOverflow(obj, &overflow);
    if (overflow != 0) {
      // Fall back to a string for huge ints — JSON has no notion of
      // arbitrary-precision integers. Surfaced as kInvalidParams in
      // dispatcher.
      throw backend::Error(
          "python: integer out of int64 range cannot round-trip to JSON");
    }
    if (v == -1 && PyErr_Occurred()) {
      PyErr_Clear();
      throw backend::Error("python: failed to convert int to long long");
    }
    return nlohmann::json(static_cast<std::int64_t>(v));
  }
  if (PyFloat_Check(obj)) {
    return nlohmann::json(PyFloat_AsDouble(obj));
  }
  if (PyUnicode_Check(obj)) {
    Py_ssize_t len = 0;
    const char* c = PyUnicode_AsUTF8AndSize(obj, &len);
    if (!c) {
      PyErr_Clear();
      throw backend::Error("python: string is not valid UTF-8");
    }
    return nlohmann::json(std::string(c, static_cast<std::size_t>(len)));
  }
  if (PyList_Check(obj) || PyTuple_Check(obj)) {
    auto out = nlohmann::json::array();
    Py_ssize_t n = PySequence_Size(obj);
    for (Py_ssize_t i = 0; i < n; ++i) {
      PyRef item(PySequence_GetItem(obj, i));
      out.push_back(py_to_json(item.get(), depth + 1));
    }
    return out;
  }
  if (PyDict_Check(obj)) {
    auto out = nlohmann::json::object();
    PyObject *k = nullptr, *v = nullptr;
    Py_ssize_t pos = 0;
    while (PyDict_Next(obj, &pos, &k, &v)) {
      if (!PyUnicode_Check(k)) {
        throw backend::Error(
            "python: dict keys must be strings to round-trip to JSON");
      }
      Py_ssize_t klen = 0;
      const char* c = PyUnicode_AsUTF8AndSize(k, &klen);
      if (!c) {
        PyErr_Clear();
        throw backend::Error("python: dict key is not valid UTF-8");
      }
      out[std::string(c, static_cast<std::size_t>(klen))] =
          py_to_json(v, depth + 1);
    }
    return out;
  }
  if (PyBytes_Check(obj) || PyByteArray_Check(obj)) {
    throw backend::Error(
        "python: bytes / bytearray cannot round-trip to JSON "
        "(decode to str or list of ints in the recipe)");
  }
  // Anything else — set, frozenset, datetime, custom class — is a
  // strict error. The recipe author can convert to a supported shape.
  std::string type = obj->ob_type ? obj->ob_type->tp_name : "<unknown>";
  throw backend::Error(
      "python: return value of unsupported type '" + type + "'");
}

PyRef json_to_py(const nlohmann::json& v, int depth) {
  if (depth > kRecursionMax) {
    throw backend::Error("python: argument exceeds recursion limit");
  }
  if (v.is_null()) {
    Py_INCREF(Py_None);
    return PyRef(Py_None);
  }
  if (v.is_boolean()) {
    if (v.get<bool>()) { Py_INCREF(Py_True); return PyRef(Py_True); }
    Py_INCREF(Py_False); return PyRef(Py_False);
  }
  if (v.is_number_integer() || v.is_number_unsigned()) {
    return PyRef(PyLong_FromLongLong(
        static_cast<long long>(v.get<std::int64_t>())));
  }
  if (v.is_number_float()) {
    return PyRef(PyFloat_FromDouble(v.get<double>()));
  }
  if (v.is_string()) {
    const auto& s = v.get_ref<const std::string&>();
    return PyRef(PyUnicode_FromStringAndSize(
        s.data(), static_cast<Py_ssize_t>(s.size())));
  }
  if (v.is_array()) {
    PyRef list(PyList_New(static_cast<Py_ssize_t>(v.size())));
    if (!list) throw backend::Error("python: PyList_New failed");
    for (std::size_t i = 0; i < v.size(); ++i) {
      auto item = json_to_py(v[i], depth + 1);
      // PyList_SetItem steals the reference — release().
      PyList_SetItem(list.get(),
                     static_cast<Py_ssize_t>(i), item.release());
    }
    return list;
  }
  if (v.is_object()) {
    PyRef dict(PyDict_New());
    if (!dict) throw backend::Error("python: PyDict_New failed");
    for (auto it = v.begin(); it != v.end(); ++it) {
      auto py_v = json_to_py(it.value(), depth + 1);
      // PyDict_SetItemString does NOT steal; PyRef destructor cleans.
      if (PyDict_SetItemString(dict.get(), it.key().c_str(),
                               py_v.get()) != 0) {
        throw backend::Error("python: PyDict_SetItemString failed");
      }
    }
    return dict;
  }
  throw backend::Error("python: unsupported JSON shape for conversion");
}

std::string truncate(std::string s, std::size_t cap) {
  if (s.size() <= cap) return s;
  s.resize(cap);
  s += "\n... [truncated]";
  return s;
}

// Drain sys.stdout / sys.stderr's StringIO buffers, return their
// contents, and reset them to fresh StringIOs. Must be called with the
// GIL held.
struct CaptureSnapshot { std::string out; std::string err; };

CaptureSnapshot drain_and_reset_capture() {
  CaptureSnapshot snap;
  PyRef sys(PyImport_ImportModule("sys"));
  if (!sys) { PyErr_Clear(); return snap; }
  PyRef io_mod(PyImport_ImportModule("io"));
  if (!io_mod) { PyErr_Clear(); return snap; }

  for (auto kv : std::initializer_list<std::pair<const char*, std::string*>>{
           {"stdout", &snap.out}, {"stderr", &snap.err}}) {
    const char* name = kv.first;
    PyRef cur(PyObject_GetAttrString(sys.get(), name));
    if (!cur) { PyErr_Clear(); continue; }
    PyRef getvalue(PyObject_GetAttrString(cur.get(), "getvalue"));
    if (getvalue) {
      PyRef val(PyObject_CallNoArgs(getvalue.get()));
      if (val && PyUnicode_Check(val.get())) {
        const char* c = PyUnicode_AsUTF8(val.get());
        if (c) *kv.second = truncate(c, kCaptureMax);
      } else {
        PyErr_Clear();
      }
    } else {
      PyErr_Clear();
    }
    // Replace with a fresh StringIO so the next invocation starts clean.
    PyRef fresh(PyObject_CallMethod(io_mod.get(), "StringIO", nullptr));
    if (fresh) {
      PyObject_SetAttrString(sys.get(), name, fresh.get());
    } else {
      PyErr_Clear();
    }
  }
  return snap;
}

// Extract the most recent Python error into (type, message, traceback)
// strings and clear the error indicator. Must be called with the GIL
// held and PyErr_Occurred() true.
struct ErrorSnapshot {
  std::string type;
  std::string message;
  std::string traceback;
};

ErrorSnapshot capture_and_clear_error() {
  ErrorSnapshot snap;
  PyObject *etype = nullptr, *evalue = nullptr, *etb = nullptr;
  PyErr_Fetch(&etype, &evalue, &etb);
  PyErr_NormalizeException(&etype, &evalue, &etb);

  if (etype) {
    PyRef name(PyObject_GetAttrString(etype, "__name__"));
    if (name) snap.type = py_obj_to_str(name.get());
    else { PyErr_Clear(); snap.type = py_obj_to_str(etype); }
  }
  if (evalue) {
    snap.message = py_obj_to_str(evalue);
  }
  if (etb) {
    PyRef tb_mod(PyImport_ImportModule("traceback"));
    if (tb_mod) {
      PyRef formatted(PyObject_CallMethod(
          tb_mod.get(), "format_exception", "OOO",
          etype ? etype : Py_None,
          evalue ? evalue : Py_None,
          etb));
      if (formatted && PyList_Check(formatted.get())) {
        Py_ssize_t n = PyList_Size(formatted.get());
        for (Py_ssize_t i = 0; i < n; ++i) {
          PyObject* line = PyList_GetItem(formatted.get(), i);  // borrowed
          if (line && PyUnicode_Check(line)) {
            const char* c = PyUnicode_AsUTF8(line);
            if (c) snap.traceback += c;
          }
        }
      } else {
        PyErr_Clear();
      }
    } else {
      PyErr_Clear();
    }
  } else if (evalue) {
    // SyntaxError has no traceback at compile time; synthesise one.
    snap.traceback = snap.type + ": " + snap.message;
  }
  snap.traceback = truncate(snap.traceback, kCaptureMax);

  Py_XDECREF(etype);
  Py_XDECREF(evalue);
  Py_XDECREF(etb);
  return snap;
}

#endif  // LDB_ENABLE_PYTHON

}  // namespace

// ---------------------------------------------------------------------------
// Interpreter
// ---------------------------------------------------------------------------

#if defined(LDB_ENABLE_PYTHON) && LDB_ENABLE_PYTHON

struct Interpreter::Impl {
  PyThreadState* main_tstate = nullptr;
  bool ok = false;
};

Interpreter::Interpreter() : impl_(std::make_unique<Impl>()) {
  // LLDB embeds Python itself — when SBDebugger initializes its
  // ScriptInterpreterPython, Py_Initialize has already run. We MUST
  // NOT re-init in that case: PyConfig_InitIsolatedConfig clobbers
  // LLDB's chosen path / encoding and crashes the next time LLDB
  // touches Python. The two consumers must share one interpreter.
  const bool we_initialized = !Py_IsInitialized();
  if (we_initialized) {
    // Programmatic isolation: don't read PYTHONHOME / PYTHONPATH from
    // the operator's env. We want determinism — a recipe that ran
    // green in CI must run green on the agent's host.
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    PyStatus status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
      // Best we can do — the error message is in static storage in
      // CPython; just report failure.
      throw backend::Error(
          "python: Py_InitializeFromConfig failed (status_exception)");
    }
    // We own the GIL only if we initialized; otherwise LLDB has
    // already released it and PyGILState_Ensure handles per-thread
    // acquisition.
    impl_->main_tstate = PyEval_SaveThread();
  }
  // Redirect sys.stdout/sys.stderr to StringIO buffers so a stray
  // print() can't corrupt the JSON-RPC channel. Acquire the GIL
  // explicitly — PyGILState_Ensure works whether or not we did the
  // initialization (the API was designed for exactly this case).
  {
    GilHold gil;
    PyRef io_mod(PyImport_ImportModule("io"));
    PyRef sys(PyImport_ImportModule("sys"));
    if (io_mod && sys) {
      for (const char* name : {"stdout", "stderr"}) {
        PyRef fresh(PyObject_CallMethod(io_mod.get(), "StringIO", nullptr));
        if (fresh) {
          PyObject_SetAttrString(sys.get(), name, fresh.get());
        } else {
          PyErr_Clear();
        }
      }
    } else {
      PyErr_Clear();
    }
  }
  impl_->ok = true;
}

Interpreter::~Interpreter() {
  // Intentionally skip Py_Finalize — see docs/20-embedded-python.md §4.
  // CPython's finalizer is known-imperfect with held PyObject refs,
  // and the process is exiting anyway.
}

Interpreter& Interpreter::instance() {
  static std::once_flag once;
  static Interpreter* inst = nullptr;
  std::call_once(once, []() { inst = new Interpreter(); });
  if (!inst) throw_disabled();
  return *inst;
}

bool Interpreter::available() noexcept { return true; }

#else  // !LDB_ENABLE_PYTHON

struct Interpreter::Impl {};

Interpreter::Interpreter() : impl_(std::make_unique<Impl>()) {}
Interpreter::~Interpreter() = default;

Interpreter& Interpreter::instance() {
  throw_disabled();
}

bool Interpreter::available() noexcept { return false; }

#endif

// ---------------------------------------------------------------------------
// Callable
// ---------------------------------------------------------------------------

#if defined(LDB_ENABLE_PYTHON) && LDB_ENABLE_PYTHON

struct Callable::Impl {
  PyObject*   module_dict = nullptr;   // owned
  PyObject*   run         = nullptr;   // owned
  std::string origin;
  std::string last_stdout;
  std::string last_stderr;
  std::string last_exc_type;
  std::string last_exc_msg;
  std::string last_tb;
};

Callable::Callable(std::string_view module_source, std::string_view origin)
    : impl_(std::make_unique<Impl>()) {
  Interpreter::instance();   // ensure init.
  impl_->origin = std::string(origin);

  GilHold gil;

  std::string src(module_source);
  std::string ori(origin);

  PyRef code(Py_CompileString(src.c_str(), ori.c_str(), Py_file_input));
  if (!code) {
    auto err = capture_and_clear_error();
    impl_->last_exc_type = err.type;
    impl_->last_exc_msg  = err.message;
    impl_->last_tb       = err.traceback;
    throw backend::Error("python: " + err.type + ": " + err.message);
  }

  PyRef module_dict(PyDict_New());
  if (!module_dict) throw backend::Error("python: PyDict_New failed");
  // PyEval_EvalCode needs __builtins__ in the globals dict, otherwise
  // every name lookup fails. Borrow the main builtins.
  PyObject* builtins = PyEval_GetBuiltins();
  if (builtins) {
    PyDict_SetItemString(module_dict.get(), "__builtins__", builtins);
  }
  PyDict_SetItemString(module_dict.get(), "__name__",
                       PyUnicode_FromString("<recipe>"));

  PyRef result(PyEval_EvalCode(code.get(), module_dict.get(),
                                module_dict.get()));
  if (!result) {
    auto err = capture_and_clear_error();
    impl_->last_exc_type = err.type;
    impl_->last_exc_msg  = err.message;
    impl_->last_tb       = err.traceback;
    throw backend::Error("python: " + err.type + ": " + err.message);
  }

  PyObject* run = PyDict_GetItemString(module_dict.get(), "run");  // borrowed
  if (!run || !PyCallable_Check(run)) {
    throw backend::Error(
        "python: module must define a top-level callable named 'run'");
  }
  Py_INCREF(run);
  impl_->run = run;
  impl_->module_dict = module_dict.release();
}

Callable::~Callable() {
  if (!impl_) return;
  if (impl_->module_dict || impl_->run) {
    GilHold gil;
    Py_XDECREF(impl_->run);
    Py_XDECREF(impl_->module_dict);
  }
}

nlohmann::json Callable::invoke(const nlohmann::json& arg) {
  GilHold gil;
  impl_->last_stdout.clear();
  impl_->last_stderr.clear();
  impl_->last_exc_type.clear();
  impl_->last_exc_msg.clear();
  impl_->last_tb.clear();

  PyRef py_arg = json_to_py(arg, 0);
  if (!py_arg) {
    throw backend::Error("python: argument conversion to Python failed");
  }

  PyRef result(PyObject_CallOneArg(impl_->run, py_arg.get()));

  // If the call raised, capture the error BEFORE the stdout drain
  // (which itself makes Python calls and would clobber the error
  // indicator). Then drain stdout/stderr; both paths see prints.
  std::optional<ErrorSnapshot> err_snap;
  if (!result) {
    err_snap = capture_and_clear_error();
  }

  auto cap = drain_and_reset_capture();
  impl_->last_stdout = std::move(cap.out);
  impl_->last_stderr = std::move(cap.err);

  if (err_snap) {
    impl_->last_exc_type = err_snap->type;
    impl_->last_exc_msg  = err_snap->message;
    impl_->last_tb       = err_snap->traceback;
    throw backend::Error(
        "python: " + err_snap->type + ": " + err_snap->message);
  }
  return py_to_json(result.get(), 0);
}

const std::string& Callable::last_stdout() const noexcept {
  return impl_->last_stdout;
}
const std::string& Callable::last_stderr() const noexcept {
  return impl_->last_stderr;
}
const std::string& Callable::last_exception_type() const noexcept {
  return impl_->last_exc_type;
}
const std::string& Callable::last_exception_message() const noexcept {
  return impl_->last_exc_msg;
}
const std::string& Callable::last_traceback() const noexcept {
  return impl_->last_tb;
}

#else  // !LDB_ENABLE_PYTHON

struct Callable::Impl {
  std::string empty;
};

Callable::Callable(std::string_view, std::string_view)
    : impl_(std::make_unique<Impl>()) {
  throw_disabled();
}
Callable::~Callable() = default;

nlohmann::json Callable::invoke(const nlohmann::json&) { throw_disabled(); }

const std::string& Callable::last_stdout()            const noexcept {
  return impl_->empty;
}
const std::string& Callable::last_stderr()            const noexcept {
  return impl_->empty;
}
const std::string& Callable::last_exception_type()    const noexcept {
  return impl_->empty;
}
const std::string& Callable::last_exception_message() const noexcept {
  return impl_->empty;
}
const std::string& Callable::last_traceback()         const noexcept {
  return impl_->empty;
}

#endif

}  // namespace ldb::python
