#undef NDEBUG  // Release builds would otherwise compile the asserts away
#include <cassert>
#include <cstdio>

#include "logs.hpp"

using nlohmann::json;

int main() {
  // Empty filters are left out; values are URL-encoded.
  assert(logs_path({}, 50, 0) == "/logs?limit=50");
  assert(logs_path({"my shop", "2001:db8::1", true}, 50, 100) ==
         "/logs?app=my%20shop&ip=2001%3Adb8%3A%3A1&status=blocked&limit=50&offset=100");

  json row = {{"AppName", "shop"}, {"RealIP", "203.0.113.9"}, {"Blocked", true}, {"Status", 403},
              {"Method", "GET"}, {"Host", "shop.example"}, {"Path", "/cart"}, {"Action", "waf_blocked"},
              {"Timestamp", "2026-11-02T10:04:05.123Z"}};
  assert(log_matches({}, row));
  assert(log_matches({"shop", "203.0.113.9", true}, row));
  assert(!log_matches({"api", "", false}, row));
  assert(!log_matches({"", "203.0.113.10", false}, row));
  row["Blocked"] = false;
  assert(!log_matches({"", "", true}, row));

  auto line = log_line(row);
  assert(line.rfind("11-02 10:04:05 403 GET    shop", 0) == 0);
  assert(line.find("shop.example/cart  waf_blocked") != std::string::npos);
  assert(log_line(json::object()).size() > 0);  // missing fields don't throw

  json d = {{"method", "POST"}, {"host", "h"}, {"path", "/p"}, {"query", "a=1"}, {"status", 403},
            {"blocked", true}, {"rule_id", 0}, {"headers", {{"Cookie", "[redacted]"}}}};
  auto rows = log_detail(d);
  auto get = [&](const std::string& k) {
    for (auto& [key, v] : rows)
      if (key == k) return v;
    return std::string("<missing>");
  };
  assert(get("Request") == "POST h/p?a=1");
  assert(get("Status") == "403 (blocked)");
  assert(get("Rule") == "");
  assert(get("Cookie") == "[redacted]");
  std::puts("logs_test ok");
}
