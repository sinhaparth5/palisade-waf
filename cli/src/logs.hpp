#pragma once
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Filters shared by GET /logs (server side) and the live tail (client side,
// since /logs/stream sends every request).
struct LogFilter {
  std::string app;  // service name, exact
  std::string ip;   // client IP, exact
  bool blocked = false;
};

std::string logs_path(const LogFilter& f, int limit, int offset);
bool log_matches(const LogFilter& f, const nlohmann::json& row);

// One line per request: "MM-DD HH:MM:SS status method service ip host+path action".
std::string log_line(const nlohmann::json& row);

// Label/value rows for GET /logs/:id, headers last.
std::vector<std::pair<std::string, std::string>> log_detail(const nlohmann::json& d);
