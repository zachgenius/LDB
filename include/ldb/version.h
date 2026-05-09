// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace ldb {

#ifndef LDB_VERSION_STRING
#define LDB_VERSION_STRING "0.0.0-dev"
#endif

constexpr const char* kVersionString = LDB_VERSION_STRING;

// Wire protocol version. Bump on incompatible changes.
constexpr int kProtocolMajor = 0;
constexpr int kProtocolMinor = 1;

}  // namespace ldb
