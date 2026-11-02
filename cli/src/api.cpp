#include "api.hpp"

#include <httplib.h>

Api::Api(const Config& c) : base_(c.admin_path + "/api/v1"), http_(std::make_unique<httplib::Client>(c.url)) {
  http_->set_bearer_token_auth(c.api_key);
  http_->set_connection_timeout(5);
  http_->set_read_timeout(15);
  http_->enable_server_certificate_verification(true);
  http_->set_default_headers({{"User-Agent", "palisade-cli/" PALISADE_CLI_VERSION}});
}

Api::~Api() = default;

nlohmann::json Api::get(const std::string& path) {
  auto res = http_->Get(base_ + path);
  if (!res) {
    auto msg = httplib::to_string(res.error());
    if (res.error() == httplib::Error::SSLServerVerification)
      msg += " (a self-signed certificate must be in the system trust store)";
    throw ApiError("request failed: " + msg);
  }
  if (res->status < 200 || res->status >= 300) {
    std::string msg = "HTTP " + std::to_string(res->status);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    if (body.is_object() && body.contains("error") && body["error"].is_string())
      msg += ": " + body["error"].get<std::string>();
    else if (res->status == 404)
      msg += ": not found (is the admin path right, and is the server v3.2+?)";
    throw ApiError(msg);
  }
  auto body = nlohmann::json::parse(res->body, nullptr, false);
  if (body.is_discarded()) throw ApiError("server sent invalid JSON");
  return body;
}
