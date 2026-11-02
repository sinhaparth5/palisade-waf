#pragma once
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Plain-text renderings of the read-only list endpoints, shared by the TUI
// and the one-shot commands.

// GET /stats as label/value-ish lines.
std::vector<std::string> stats_lines(const nlohmann::json& s);

struct RuleView {
  const char* key;    // command-line name
  const char* label;  // TUI menu entry
  const char* path;   // API path
};
extern const std::vector<RuleView> kRuleViews;
const RuleView* find_rule_view(const std::string& key);

// One line per rule for the view's API response; a header line first.
std::vector<std::string> rule_lines(const RuleView& v, const nlohmann::json& body);
