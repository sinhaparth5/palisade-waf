#undef NDEBUG
#include <cassert>
#include <iostream>

#include "views.hpp"

using nlohmann::json;

static bool has(const std::vector<std::string>& lines, const std::string& needle) {
  for (const auto& l : lines)
    if (l.find(needle) != std::string::npos) return true;
  return false;
}

int main() {
  auto stats = stats_lines(json::parse(R"({
    "totals": {"TotalToday": 12, "BlockedToday": 3, "TotalAll": 90, "BlockedAll": 9},
    "at_a_glance": {"RequestsLastMinute": 5, "RequestsPrevMinute": 2},
    "top_blocked_ips": [{"IP": "203.0.113.7", "Count": 4}],
    "top_blocked_countries": [{"Country": "CN", "Count": 2}],
    "top_rules": [{"RuleID": 942100, "HitCount": 7, "Disabled": true}]})"));
  assert(has(stats, "blocked 3"));
  assert(has(stats, "(+3)"));
  assert(has(stats, "203.0.113.7"));
  assert(has(stats, "CN"));
  assert(has(stats, "942100") && has(stats, "(off)"));
  assert(!stats_lines(json::object()).empty());  // missing keys don't throw

  auto ip = rule_lines(*find_rule_view("ip"), json::parse(R"([
    {"RuleType": "block", "IP": "198.51.100.1", "AppName": "", "Note": "Auto-banned — sqli", "CreatedAt": "2026-11-02T10:00:00Z"},
    {"RuleType": "allow", "IP": "10.0.0.0/8", "AppName": "shop", "CreatedAt": "2026-11-01T10:00:00Z"}])"));
  assert(ip.size() == 3);
  assert(has(ip, "global") && has(ip, "2026-11-02") && has(ip, "Auto-banned"));
  assert(has(ip, "shop"));

  auto exc = rule_lines(*find_rule_view("exceptions"), json::parse(R"({
    "global": [{"RuleID": 920350, "Reason": "ip host"}],
    "services": [{"RuleID": 942100, "ServiceName": "api", "Reason": "json"}]})"));
  assert(exc.size() == 3 && has(exc, "920350") && has(exc, "api"));

  auto vp = rule_lines(*find_rule_view("vpatches"), json::parse(R"([
    {"RuleID": 2000001, "CVE": "CVE-2025-1", "Product": "X", "Hits": 2, "GlobalOff": false, "OffFor": ["shop"]}])"));
  assert(has(vp, "2000001") && has(vp, "off for shop"));

  auto custom = rule_lines(*find_rule_view("custom"), json::parse(R"([
    {"Enabled": true, "ServiceName": "", "Rule": "SecRule ARGS \"@rx x\" \\\n  \"id:1000001,deny\""}])"));
  assert(has(custom, "…") && !has(custom, "id:1000001"));  // only the first line

  assert(rule_lines(*find_rule_view("geo"), json::array()).back() == "(none)");
  assert(find_rule_view("nope") == nullptr);
  std::cout << "views_test ok\n";
}
