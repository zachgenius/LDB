// SPDX-License-Identifier: Apache-2.0
#include "protocol/output_channel.h"

namespace ldb::protocol {

void OutputChannel::write_response(const json& reply) {
  std::lock_guard lk(mu_);
  write_message(out_, reply, fmt_);
}

void OutputChannel::write_notification(std::string_view method, json params) {
  json frame = make_notification(method, std::move(params));
  std::lock_guard lk(mu_);
  write_message(out_, frame, fmt_);
}

}  // namespace ldb::protocol
