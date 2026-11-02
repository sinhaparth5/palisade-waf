#include "api.hpp"

#include <httplib.h>

namespace {

std::unique_ptr<httplib::Client> client(const Config& c, int read_timeout) {
  auto h = std::make_unique<httplib::Client>(c.url);
  h->set_bearer_token_auth(c.api_key);
  h->set_connection_timeout(5);
  h->set_read_timeout(read_timeout);
  h->enable_server_certificate_verification(true);
  h->set_default_headers({{"User-Agent", "palisade-cli/" PALISADE_CLI_VERSION}});
  return h;
}

std::string transport_error(httplib::Error e) {
  auto msg = httplib::to_string(e);
  if (e == httplib::Error::SSLServerVerification) msg += " (a self-signed certificate must be in the system trust store)";
  return "request failed: " + msg;
}

std::string status_error(int status, const std::string& raw) {
  std::string msg = "HTTP " + std::to_string(status);
  auto body = nlohmann::json::parse(raw, nullptr, false);
  if (body.is_object() && body.contains("error") && body["error"].is_string())
    msg += ": " + body["error"].get<std::string>();
  else if (status == 404)
    msg += ": not found (is the admin path right, and is the server v3.2+?)";
  return msg;
}

}  // namespace

std::string with_query(std::string path, const std::vector<std::pair<std::string, std::string>>& q) {
  char sep = '?';
  for (const auto& [k, v] : q) {
    if (v.empty()) continue;
    path += sep + k + "=" + httplib::encode_uri_component(v);
    sep = '&';
  }
  return path;
}

Api::Api(const Config& c) : cfg_(c), base_(c.admin_path + "/api/v1"), http_(client(c, 15)) {}

Api::~Api() = default;

void Api::stream(const std::string& path, const std::function<void(const nlohmann::json&)>& on_event, Stop& stop) {
  auto h = client(cfg_, 75);  // the server pings every 30s
  {
    std::lock_guard lock(stop.mu_);
    if (stop.stopped_) return;
    stop.client_ = h.get();
  }
  int status = 0;
  std::string buf, err_body;
  auto res = h->Get(
      base_ + path,
      [&](const httplib::Response& r) {
        status = r.status;
        return true;
      },
      [&](const char* data, size_t n) {
        if (status != 200) {
          err_body.append(data, n);
          return err_body.size() < 4096;
        }
        buf.append(data, n);
        for (size_t nl; (nl = buf.find('\n')) != std::string::npos; buf.erase(0, nl + 1)) {
          auto line = buf.substr(0, nl);
          if (line.rfind("data: ", 0) != 0) continue;  // ": ping", blank separators
          auto ev = nlohmann::json::parse(line.substr(6), nullptr, false);
          if (!ev.is_discarded()) on_event(ev);
        }
        return !stop.stopped_;
      });
  {
    std::lock_guard lock(stop.mu_);
    stop.client_ = nullptr;
  }
  if (stop.stopped_) return;
  if (status != 0 && status != 200) throw ApiError(status_error(status, err_body));
  if (!res) throw ApiError(transport_error(res.error()));
  throw ApiError("stream closed by the server");
}

void Api::Stop::stop() {
  std::lock_guard lock(mu_);
  stopped_ = true;
  if (client_) client_->stop();
}

nlohmann::json Api::get(const std::string& path) {
  auto res = http_->Get(base_ + path);
  if (!res) throw ApiError(transport_error(res.error()));
  if (res->status < 200 || res->status >= 300) throw ApiError(status_error(res->status, res->body));
  auto body = nlohmann::json::parse(res->body, nullptr, false);
  if (body.is_discarded()) throw ApiError("server sent invalid JSON");
  return body;
}
