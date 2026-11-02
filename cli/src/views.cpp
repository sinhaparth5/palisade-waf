#include "views.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

using nlohmann::json;

namespace {

std::string fmt(const char* f, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, f);
  std::vsnprintf(buf, sizeof buf, f, ap);
  va_end(ap);
  return buf;
}

std::string str(const json& o, const char* k) { return o.contains(k) && o[k].is_string() ? o[k].get<std::string>() : ""; }
int num(const json& o, const char* k) { return o.contains(k) && o[k].is_number() ? o[k].get<int>() : 0; }
std::string date(const json& o) { return str(o, "CreatedAt").substr(0, 10); }
std::string scope(const json& o, const char* k) {
  auto s = str(o, k);
  return s.empty() ? "global" : s;
}

// "+12" / "-3" against the previous window; "" when both are zero.
std::string delta(int now, int prev) {
  if (now == 0 && prev == 0) return "";
  return fmt("  (%+d)", now - prev);
}

const json& arr(const json& o, const char* k) {
  static const json empty = json::array();
  return o.contains(k) && o[k].is_array() ? o[k] : empty;
}

std::string first_line(std::string s) {
  if (auto nl = s.find('\n'); nl != std::string::npos) s = s.substr(0, nl) + " …";
  return s;
}

}  // namespace

const std::vector<RuleView> kRuleViews = {
    {"ip", "IP rules", "/ip-rules"},
    {"bans", "Bans", "/bans"},
    {"geo", "Geo rules", "/geo-rules"},
    {"custom", "Custom WAF rules", "/waf-rules/custom"},
    {"exceptions", "Rule exceptions", "/rule-exceptions"},
    {"vpatches", "Virtual patches", "/vpatches"},
};

const RuleView* find_rule_view(const std::string& key) {
  for (const auto& v : kRuleViews)
    if (key == v.key) return &v;
  return nullptr;
}

std::vector<std::string> stats_lines(const json& s) {
  const json& t = s.value("totals", json::object());
  const json& g = s.value("at_a_glance", json::object());
  std::vector<std::string> out = {
      "Requests",
      fmt("  today          %8d   blocked %d", num(t, "TotalToday"), num(t, "BlockedToday")),
      fmt("  all time       %8d   blocked %d", num(t, "TotalAll"), num(t, "BlockedAll")),
      "",
      "Last minute",
      fmt("  requests       %8d%s", num(g, "RequestsLastMinute"),
          delta(num(g, "RequestsLastMinute"), num(g, "RequestsPrevMinute")).c_str()),
      fmt("  blocked        %8d%s", num(g, "BlockedLastMinute"),
          delta(num(g, "BlockedLastMinute"), num(g, "BlockedPrevMinute")).c_str()),
      fmt("  avg latency    %6d ms%s", num(g, "AvgLatencyMS"),
          delta(num(g, "AvgLatencyMS"), num(g, "PrevAvgLatencyMS")).c_str()),
      "",
      "Today vs yesterday",
      fmt("  WAF hits       %8d%s", num(g, "WAFRuleHitsToday"),
          delta(num(g, "WAFRuleHitsToday"), num(g, "WAFRuleHitsPreviousDay")).c_str()),
      fmt("  visitors       %8d%s", num(g, "UniqueVisitorsToday"),
          delta(num(g, "UniqueVisitorsToday"), num(g, "UniqueVisitorsPrevDay")).c_str()),
      "",
      "Top blocked IPs (24h)",
  };
  for (const auto& r : arr(s, "top_blocked_ips")) out.push_back(fmt("  %-40s %6d", str(r, "IP").c_str(), num(r, "Count")));
  out.push_back("");
  out.push_back("Top blocked countries (24h)");
  for (const auto& r : arr(s, "top_blocked_countries"))
    out.push_back(fmt("  %-40s %6d", str(r, "Country").c_str(), num(r, "Count")));
  out.push_back("");
  out.push_back("Top WAF rules");
  for (const auto& r : arr(s, "top_rules"))
    out.push_back(fmt("  %-40d %6d%s", num(r, "RuleID"), num(r, "HitCount"), r.value("Disabled", false) ? "  (off)" : ""));
  return out;
}

std::vector<std::string> rule_lines(const RuleView& v, const json& body) {
  std::string key = v.key;
  std::vector<std::string> out;
  const json& list = body.is_array() ? body : json::array();
  if (key == "ip" || key == "bans") {
    out.push_back(fmt("%-6s %-40s %-16s %-10s %s", "TYPE", "IP", "SCOPE", "ADDED", "NOTE"));
    for (const auto& r : list)
      out.push_back(fmt("%-6s %-40s %-16s %-10s %s", str(r, "RuleType").c_str(), str(r, "IP").c_str(),
                        scope(r, "AppName").c_str(), date(r).c_str(), str(r, "Note").c_str()));
  } else if (key == "geo") {
    out.push_back(fmt("%-6s %-8s %-16s %s", "TYPE", "COUNTRY", "SCOPE", "ADDED"));
    for (const auto& r : list)
      out.push_back(fmt("%-6s %-8s %-16s %s", str(r, "RuleType").c_str(), str(r, "CountryCode").c_str(),
                        scope(r, "AppName").c_str(), date(r).c_str()));
  } else if (key == "custom") {
    out.push_back(fmt("%-4s %-16s %-24s %s", "ON", "SCOPE", "NOTE", "RULE"));
    for (const auto& r : list)
      out.push_back(fmt("%-4s %-16s %-24.24s %s", r.value("Enabled", false) ? "on" : "off",
                        scope(r, "ServiceName").c_str(), str(r, "Note").c_str(), first_line(str(r, "Rule")).c_str()));
  } else if (key == "exceptions") {
    out.push_back(fmt("%-8s %-16s %-10s %s", "RULE", "SCOPE", "ADDED", "REASON"));
    for (const auto& r : arr(body, "global"))
      out.push_back(fmt("%-8d %-16s %-10s %s", num(r, "RuleID"), "global", date(r).c_str(), str(r, "Reason").c_str()));
    for (const auto& r : arr(body, "services"))
      out.push_back(fmt("%-8d %-16s %-10s %s", num(r, "RuleID"), str(r, "ServiceName").c_str(), date(r).c_str(),
                        str(r, "Reason").c_str()));
  } else if (key == "vpatches") {
    out.push_back(fmt("%-8s %-18s %-6s %6s  %s", "RULE", "CVE", "STATE", "HITS", "PRODUCT"));
    for (const auto& r : list) {
      std::string state = r.value("GlobalOff", false) ? "off" : "on";
      std::string off_for;
      for (const auto& s : arr(r, "OffFor")) off_for += (off_for.empty() ? "  off for " : ", ") + s.get<std::string>();
      out.push_back(fmt("%-8d %-18s %-6s %6d  %s", num(r, "RuleID"), str(r, "CVE").c_str(), state.c_str(),
                        num(r, "Hits"), str(r, "Product").c_str()) +
                    off_for);
    }
  }
  if (out.size() == 1) out.push_back("(none)");
  return out;
}
