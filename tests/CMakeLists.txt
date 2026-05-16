# Fixture binaries (real ELF/Mach-O with known DWARF, used by endpoint
# tests). Build them before any target that depends on them.
add_subdirectory(fixtures)

# Pin every test's artifact-store root inside the build directory so
# that ldbd's default-to-${HOME}/.ldb fallback never writes to the
# operator's home directory during testing. Tests that need a clean
# per-run root (smoke_artifact, the unit fixture) override this with
# their own tmpdir; tests that don't touch the store at all are
# unaffected.
set(LDB_TEST_STORE_ROOT "${CMAKE_BINARY_DIR}/test-store-root")
file(MAKE_DIRECTORY "${LDB_TEST_STORE_ROOT}")

# Smoke tests — end-to-end against the built ldbd binary.
add_test(
  NAME smoke_hello
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/run.sh" "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_hello PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_hello_capabilities
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_hello_capabilities.py"
          "$<TARGET_FILE:ldbd>"
          "$<IF:$<BOOL:${LDB_ENABLE_CAPSTONE}>,capstone,lldb>"
)
set_tests_properties(smoke_hello_capabilities PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_type_layout
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_type_layout.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_type_layout PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_symbol_find
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_symbol_find.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_symbol_find PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_string_list
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_string_list.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_string_list PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_disasm
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_disasm.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_disasm PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_xref_addr
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_xref_addr.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_xref_addr PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_string_xref
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_string_xref.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_string_xref PROPERTIES
  TIMEOUT 30
)

# docs/35-field-report-followups.md §3 phase 2 — xref.addr must follow
# chained-fixup slot indirection on Apple silicon arm64 builds with
# -Wl,-fixup_chains. The fixture only builds on that host; the test
# is gated identically. Linux + non-arm64 macOS skip it cleanly because
# the fixture target doesn't exist there.
if(APPLE AND CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64")
  add_test(
    NAME smoke_xref_chained_fixup
    COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_xref_chained_fixup.sh"
            "$<TARGET_FILE:ldbd>"
            "$<TARGET_FILE:ldb_fix_chain_slot>"
  )
  set_tests_properties(smoke_xref_chained_fixup PROPERTIES
    TIMEOUT 30
  )

  # Phase-3 adversarial smoke tests for the ADRP-pair resolver
  # (docs/35-field-report-followups.md §3 phase 3). Each one targets
  # one specific phase-2 false-positive mode: ADD-clobber, cross-
  # function leak, BL-clobber. All three were silently wrong against
  # 25f35de; phase 3's deterministic register-state clobber rules
  # turn them green.
  foreach(_phase3_smoke
      xref_addclobber
      xref_fnleak
      xref_callclobber
      xref_subclobber
      xref_writeback_ldr
      xref_str)
    add_test(
      NAME smoke_${_phase3_smoke}
      COMMAND python3
              "${CMAKE_SOURCE_DIR}/tests/smoke/test_${_phase3_smoke}.py"
              "$<TARGET_FILE:ldbd>"
              "$<TARGET_FILE:ldb_fix_${_phase3_smoke}>"
    )
    set_tests_properties(smoke_${_phase3_smoke} PROPERTIES TIMEOUT 30)
  endforeach()

  # Phase-3 post-review PAC-call smoke. Gated on the arm64e toolchain
  # probe in tests/fixtures/CMakeLists.txt — without it the fixture
  # target doesn't exist and the test would fail to resolve
  # $<TARGET_FILE:ldb_fix_xref_pac_callclobber> at generate time.
  if(LDB_CAN_COMPILE_ARM64E)
    add_test(
      NAME smoke_xref_pac_callclobber
      COMMAND python3
              "${CMAKE_SOURCE_DIR}/tests/smoke/test_xref_pac_callclobber.py"
              "$<TARGET_FILE:ldbd>"
              "$<TARGET_FILE:ldb_fix_xref_pac_callclobber>"
    )
    set_tests_properties(smoke_xref_pac_callclobber PROPERTIES TIMEOUT 30)
  endif()
endif()

add_test(
  NAME smoke_view_module_list
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_view_module_list.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_view_module_list PROPERTIES
  TIMEOUT 30
)

# Asserts target.open is summary-by-default and gates the section
# walk behind view.include_sections=true. Motivated by the 503 MB
# Mach-O case where the inline section table was 2.2 MB of wire data
# per call (and the section walk itself was expensive). See worklog
# 2026-05-16.
add_test(
  NAME smoke_target_open_view
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_target_open_view.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_target_open_view PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_process
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_process.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_process PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_threads
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_threads.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_threads PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_frame_values
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_frame_values.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_frame_values PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_attach
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_attach.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_attach PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_memory
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_memory.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_memory PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_core
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_core.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_core PROPERTIES
  TIMEOUT 60
)
if(APPLE)
  # macOS CI runner (macos-14) is ~3x slower than Linux for LLDB/core ops.
  # Hosted runners have also shown core save/load spikes beyond 180s.
  set_tests_properties(smoke_core PROPERTIES TIMEOUT 600)
endif()

add_test(
  NAME smoke_step
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_step.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_step PROPERTIES
  TIMEOUT 60
)

# Tier 4 §14 (scoped): thread.continue + process.continue+tid.
# Pins the v0.3 sync-passthrough wire shape so v0.4 async-mode
# work can switch behavior without a client-side rewrite.
add_test(
  NAME smoke_thread_continue
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_thread_continue.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_thread_continue PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_value_eval
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_value_eval.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_value_eval PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_value_read
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_value_read.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_value_read PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_connect_remote
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_connect_remote.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_connect_remote PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_connect_remote_ssh
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_connect_remote_ssh.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_connect_remote_ssh PROPERTIES
  TIMEOUT 60
)

# Post-V1 plan #17 phase-1 (docs/25-own-rsp-client.md §3): own RSP
# client end-to-end. SKIPs cleanly when lldb-server isn't on PATH.
add_test(
  NAME smoke_rsp_connect
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_rsp_connect.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_rsp_connect PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_connect_rr
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_connect_rr.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_connect_rr PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_reverse_exec
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_reverse_exec.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_reverse_exec PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_artifact
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_artifact.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_artifact PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_artifact_relations
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_artifact_relations.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_artifact_relations PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_session
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_session.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_session PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_static_globals
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_static_globals.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_static_globals PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_session_diff
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_session_diff.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_session_diff PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #16 phase-1: session.fork + session.replay end-to-end.
add_test(
  NAME smoke_session_replay
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_session_replay.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_session_replay PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_multi_binary
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_multi_binary.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_multi_binary PROPERTIES
  TIMEOUT 30
)

# Cross-binary correlation (Tier 3 §10, post-v0.1 scoped slice). Drives
# correlate.types/symbols/strings against structs+sleeper to exercise
# both symmetric and asymmetric lookup paths.
add_test(
  NAME smoke_correlate
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_correlate.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_correlate PROPERTIES
  TIMEOUT 30
)

# Post-V1 #18 phase-1: SymbolIndex cold→warm path. Asserts the second
# correlate.types call hits the cache (faster + wire-identical) after
# the first walks LLDB and writes the index. docs/23-symbol-index.md.
add_test(
  NAME smoke_index_cold_warm
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_index_cold_warm.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_index_cold_warm PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_recipe
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_recipe.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_recipe PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #9 phase-2: python-v1 recipe format end-to-end.
# SKIPs when ldbd was built without LDB_ENABLE_PYTHON.
add_test(
  NAME smoke_recipe_python
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_recipe_python.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_recipe_python PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #12 phase-2: agent.hello round-trip through ldbd.
# SKIPs when ldb-probe-agent wasn't built (no libbpf on the host).
if(LDB_BPF_AGENT_BUILD)
  add_test(
    NAME smoke_probe_agent
    COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_probe_agent.py"
            "$<TARGET_FILE:ldbd>"
            "$<TARGET_FILE:ldb-probe-agent>"
  )
  set_tests_properties(smoke_probe_agent PROPERTIES
    TIMEOUT 30
  )

  # Post-V1 plan #12 phase-3: orchestrator routing of kind=agent probes.
  # Accepts both the live happy path and the no-BPF-toolchain "agent
  # returns not_supported" path so it passes on dev boxes without
  # clang+bpftool+CAP_BPF.
  add_test(
    NAME smoke_probe_agent_route
    COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_probe_agent_route.py"
            "$<TARGET_FILE:ldbd>"
            "$<TARGET_FILE:ldb-probe-agent>"
  )
  set_tests_properties(smoke_probe_agent_route PROPERTIES
    TIMEOUT 30
  )
endif()

# Post-V1 plan #14 phase-1: Python frame unwinders.
# SKIPs cleanly when ldbd was built without LDB_ENABLE_PYTHON
# (test self-detects via describe.endpoints).
add_test(
  NAME smoke_python_unwinder
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_python_unwinder.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_python_unwinder PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #14 phase-2: multi-step process.list_frames_python walk.
# Same skip-gate as the single-step phase-1 smoke.
add_test(
  NAME smoke_python_unwinder_walk
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_python_unwinder_walk.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_python_unwinder_walk PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_probe
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_probe.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_probe PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_mem_dump
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_mem_dump.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_mem_dump PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_observer
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_observer_igmp
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer_igmp.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer_igmp PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_uprobe_bpf
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_uprobe_bpf.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_uprobe_bpf PROPERTIES
  TIMEOUT 60
)

# Post-V1 plan #13: perf record/report integration. SKIPs cleanly on
# hosts without `perf` (no linux-tools) or with kernel.perf_event_paranoid
# too strict for unprivileged use.
add_test(
  NAME smoke_perf_record
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_perf_record.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_perf_record PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_observer_tcpdump
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer_tcpdump.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer_tcpdump PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_observer_exec
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer_exec.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer_exec PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_cost
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_cost.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_cost PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_cbor
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_cbor.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_cbor PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_describe_endpoints
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_describe_endpoints.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_describe_endpoints PROPERTIES
  TIMEOUT 15
)

add_test(
  NAME smoke_hello_handshake
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_hello_handshake.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_hello_handshake PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_ldb_cli
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_ldb_cli.py"
          "$<TARGET_FILE:ldbd>"
          "${CMAKE_SOURCE_DIR}/tools/ldb/ldb"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_ldb_cli PROPERTIES
  TIMEOUT 30
)

# docs/35-field-report-followups.md §1: when neither the script nor the
# daemon is on $PATH, the CLI must still find the in-tree daemon as a
# sibling of the script. Pins the new precedence layer between $PATH
# and the CWD-relative fallback.
add_test(
  NAME smoke_cli_sibling_lookup
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_cli_sibling_lookup.py"
          "$<TARGET_FILE:ldbd>"
          "${CMAKE_SOURCE_DIR}/tools/ldb/ldb"
)
set_tests_properties(smoke_cli_sibling_lookup PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_ldbpack
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_ldbpack.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_ldbpack PROPERTIES
  TIMEOUT 30
)

# V1 gate: one agent-style static RE workflow plus durable session
# export/import across a daemon restart.
add_test(
  NAME smoke_agent_workflow
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_agent_workflow.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_agent_workflow PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #7: token-budget regression CI gate. Pins _cost.tokens_est
# totals for a canonical agent-workflow RPC sequence. Update the baseline
# (tests/baselines/agent_workflow_tokens.json) by re-running with
# LDB_UPDATE_BASELINE=1 after an intentional wire-shape change.
add_test(
  NAME smoke_token_budget
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_token_budget.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
          "${CMAKE_SOURCE_DIR}/tests/baselines/agent_workflow_tokens.json"
)
set_tests_properties(smoke_token_budget PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #3: recipe.reload + LDB_RECIPE_DIR startup scan.
add_test(
  NAME smoke_recipe_reload
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_recipe_reload.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_recipe_reload PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #6: hypothesis-v1 artifact type validation +
# artifact.hypothesis_template helper.
add_test(
  NAME smoke_hypothesis
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_hypothesis.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_hypothesis PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #5: view.diff_against on module.list / thread.list.
add_test(
  NAME smoke_view_diff
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_view_diff.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_view_diff PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #4: measured cost preview in describe.endpoints.
add_test(
  NAME smoke_cost_p50
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_cost_p50.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_cost_p50 PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #10: interactive REPL with persistent daemon, meta-
# commands (:explain / :cost / :replay / :quit), tab completion via
# prompt_toolkit-or-readline fallback.
add_test(
  NAME smoke_cli_repl
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_cli_repl.py"
          "$<TARGET_FILE:ldbd>"
          "${CMAKE_SOURCE_DIR}/tools/ldb/ldb"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_cli_repl PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #11: --ssh transport on the `ldb` CLI. A shell shim on
# PATH stands in for `ssh`, so this test runs without a real remote.
add_test(
  NAME smoke_cli_ssh
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_ldb_cli_ssh.py"
          "$<TARGET_FILE:ldbd>"
          "${CMAKE_SOURCE_DIR}/tools/ldb/ldb"
)
set_tests_properties(smoke_cli_ssh PROPERTIES
  TIMEOUT 30
)

# Post-V1 plan #8: cross-backend smoke under ldbd --backend=gdb.
# SKIPs cleanly when gdb is not on PATH.
add_test(
  NAME smoke_gdbmi_backend
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_gdbmi_backend.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_gdbmi_backend PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_provenance_replay
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_provenance_replay.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_provenance_replay PROPERTIES
  TIMEOUT 60
)
if(APPLE)
  # Replays include core-backed provenance checks; keep this aligned with
  # smoke_core's macOS budget.
  set_tests_properties(smoke_provenance_replay PROPERTIES TIMEOUT 600)
endif()

add_test(
  NAME smoke_live_provenance
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_live_provenance.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_live_provenance PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_live_dlopen
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_live_dlopen.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_dlopener>"
)
set_tests_properties(smoke_live_dlopen PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_live_determinism_gate
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_live_determinism_gate.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_live_determinism_gate PROPERTIES
  TIMEOUT 90
)
if(APPLE)
  set_tests_properties(smoke_live_determinism_gate PROPERTIES TIMEOUT 240)
endif()

add_test(
  NAME smoke_live_continue_provenance
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_live_continue_provenance.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_looper>"
)
set_tests_properties(smoke_live_continue_provenance PROPERTIES
  TIMEOUT 60
)

# DAP shim end-to-end (Tier 2 §4). Spawns ldb-dap which itself spawns
# ldbd; drives DAP requests over the shim's stdio to the sleeper
# fixture.
add_test(
  NAME smoke_dap_shim
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_dap_shim.py"
          "$<TARGET_FILE:ldb-dap>"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_dap_shim PROPERTIES
  TIMEOUT 60
)

# Field-report follow-up §2 phase 1 — persistent unix-socket daemon.
# `--listen unix:PATH` is single-client (one connection at a time);
# `target_id` and other dispatcher state survive across a disconnect.
# This test exercises the cross-cutting promise — daemon stays up,
# client reconnects, target_id remains valid.
add_test(
  NAME smoke_socket_lifecycle
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_socket_lifecycle.py"
          "$<TARGET_FILE:ldbd>"
          "${CMAKE_SOURCE_DIR}/tools/ldb/ldb"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_socket_lifecycle PROPERTIES
  TIMEOUT 30
)

# Two `ldbd --listen unix:$same_path` daemons must not coexist — flock
# on `${sock}.lock` makes the second fail fast with a clear message.
add_test(
  NAME smoke_socket_collision
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_socket_collision.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_socket_collision PROPERTIES
  TIMEOUT 30
)

# Phase-1 access control is filesystem-permission only: socket mode 0600
# and (when we create the parent dir) 0700. Pin the invariant.
add_test(
  NAME smoke_socket_perms
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_socket_perms.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_socket_perms PROPERTIES
  TIMEOUT 30
)

# §2 phase 2: two concurrent socket clients exercising target.open +
# module.list against the same daemon. Fails if the accept loop is
# still single-client (the second connection's accept blocks until
# the first disconnects, the barrier times out).
add_test(
  NAME smoke_socket_multiclient
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_socket_multiclient.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_socket_multiclient PROPERTIES
  TIMEOUT 60
)

# §2 phase 2: `ldb --socket PATH` auto-spawns a daemon when the socket
# isn't backed by a running ldbd. Daemon is detached so it outlives
# the client; a second invocation reuses it.
add_test(
  NAME smoke_socket_autospawn
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_socket_autospawn.py"
          "$<TARGET_FILE:ldbd>"
          "${CMAKE_SOURCE_DIR}/tools/ldb/ldb"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_socket_autospawn PROPERTIES
  TIMEOUT 60
)

# §2 phase 2: `daemon.shutdown` RPC tears the daemon down cleanly.
# Reply ok=true is sent first; then the accept loop wakes (self-pipe)
# and the listener / lockfile / socket inode are unlinked.
add_test(
  NAME smoke_daemon_shutdown_rpc
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_daemon_shutdown_rpc.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_daemon_shutdown_rpc PROPERTIES
  TIMEOUT 30
)

# §2 phase 2: SIGTERM with an idle connection still alive — the
# self-pipe wakes the accept loop within ~100ms so shutdown
# completes within a few seconds (vs hanging in pre-fix
# blocking accept).
add_test(
  NAME smoke_socket_interruption
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_socket_interruption.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_socket_interruption PROPERTIES
  TIMEOUT 30
)

# Infrastructure sanity check — parse `.github/workflows/ci.yml` and
# assert the documented shape. Cheap, fast, runs without ldbd.
add_test(
  NAME check_ci_yaml
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/check_ci_yaml.py"
          "${CMAKE_SOURCE_DIR}"
)
set_tests_properties(check_ci_yaml PROPERTIES
  TIMEOUT 10
)

# Unit tests — Catch2 against compiled-in source modules.
add_subdirectory(unit)

# Apply LDB_STORE_ROOT to every test we registered above. Tests that set
# their own value in subprocess env (smoke_artifact) override this; the
# unit fixture uses std::filesystem::temp_directory_path() and ignores
# the env var entirely. The point is to make absolutely sure no test —
# present or future — silently writes to the operator's $HOME/.ldb.
get_directory_property(_LDB_TESTS TESTS)
foreach(_t IN LISTS _LDB_TESTS)
  set_property(TEST ${_t} APPEND PROPERTY
    ENVIRONMENT "LDB_STORE_ROOT=${LDB_TEST_STORE_ROOT}")
  if(LDB_DEBUGSERVER_BIN)
    set_property(TEST ${_t} APPEND PROPERTY
      ENVIRONMENT "LLDB_DEBUGSERVER_PATH=${LDB_DEBUGSERVER_BIN}")
  endif()
endforeach()
