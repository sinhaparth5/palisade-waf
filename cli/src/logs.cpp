#include "logs.hpp"

#include <cstdio>

#include "api.hpp"

using nlohmann::json;

std::string logs_path(const LogFilter& f, int limit, int offset) {
  return with_query("/logs", {{"app", f.app},
                              {"ip", f.ip},
                              {"status", f.blocked ? "blocked" : ""},
                              {"limit", std::to_string(limit)},
                              {"offset", offset ? std::to_string(offset) : ""}});
}

bool log_matches(const LogFilter& f, const json& row) {
  return (f.app.empty() || row.value("AppName", "") == f.app) && (f.ip.empty() || row.value("RealIP", "") == f.ip) &&
         (!f.blocked || row.value("Blocked", false));
}

std::string log_line(const json& row) {
  auto ts = row.value("Timestamp", "");
  auto when = ts.size() >= 19 ? ts.substr(5, 5) + " " + ts.substr(11, 8) : ts;
  auto action = row.value("Action", "");
  char buf[160];
  std::snprintf(buf, sizeof buf, "%s %3d %-6.6s %-14.14s %-15.15s ", when.c_str(), row.value("Status", 0),
                row.value("Method", "").c_str(), row.value("AppName", "").c_str(), row.value("RealIP", "").c_str());
  return buf + row.value("Host", "") + row.value("Path", "") + (action.empty() ? "" : "  " + action);
}

std::vector<std::pair<std::string, std::string>> log_detail(const json& d) {
  auto s = [&](const char* k) { return d.contains(k) && d[k].is_string() ? d[k].get<std::string>() : ""; };
  auto n = [&](const char* k) { return d.contains(k) && d[k].is_number() ? std::to_string(d[k].get<long long>()) : ""; };
  auto q = s("query");
  std::vector<std::pair<std::string, std::string>> rows = {
      {"Time", s("timestamp")},
      {"Request ID", s("request_id")},
      {"Service", s("app_name")},
      {"Request", s("method") + " " + s("host") + s("path") + (q.empty() ? "" : "?" + q)},
      {"Status", n("status") + (d.value("blocked", false) ? " (blocked)" : "")},
      {"Action", s("action")},
      {"Rule", n("rule_id") == "0" ? "" : n("rule_id")},
      {"Duration", n("duration_ms") + " ms"},
      {"Client IP", s("real_ip")},
      {"Proxy IP", s("proxy_ip")},
      {"Country", s("country")},
      {"ASN", n("asn") == "0" ? "" : "AS" + n("asn") + " " + s("org")},
      {"User agent", s("user_agent")},
      {"Protocol", s("proto")},
      {"TLS", s("tls_version") + (s("tls_cipher").empty() ? "" : " " + s("tls_cipher"))},
      {"SNI", s("tls_sni")},
      {"JA4", s("ja4")},
      {"Bot score", n("bot_score")},
      {"Cache", s("cache_status")},
  };
  if (d.value("has_threat_score", false)) rows.push_back({"Threat score", n("threat_score")});
  if (d.contains("headers") && d["headers"].is_object()) rows.push_back({"Headers", ""});
  if (d.contains("headers") && d["headers"].is_object())
    for (auto& [k, v] : d["headers"].items()) rows.push_back({k, v.is_string() ? v.get<std::string>() : v.dump()});
  return rows;
}
