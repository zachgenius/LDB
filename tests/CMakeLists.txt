# M0: placeholder. Real test corpus arrives in M1.
# Smoke test driven by tests/smoke/run.sh against the built ldbd binary.

add_test(
  NAME smoke_hello
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/run.sh" "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_hello PROPERTIES
  TIMEOUT 30
)
