// Plain asserts: run via ctest. Release builds define NDEBUG, so undo it.
#undef NDEBUG
#include <cassert>
#include <iostream>
#include <stdexcept>

#include "config.hpp"

static std::string check(std::string url, std::string admin, bool allow_http = false) {
  Config c{url, admin, "cwaf_abc"};
  return validate_config(c, allow_http);
}

int main() {
  // Round trip, including characters TOML needs escaped.
  Config c{"https://waf.example.com", "/admin", "cwaf_\"q\\x"};
  Config back = parse_config(format_config(c));
  assert(back.url == c.url && back.admin_path == c.admin_path && back.api_key == c.api_key);

  // Comments, blank lines and unknown keys are ignored; bad lines throw.
  assert(parse_config("# hi\n\nother = \"x\"\nurl = \"https://a\"\n").url == "https://a");
  bool threw = false;
  try { parse_config("url = https://a\n"); } catch (const std::runtime_error&) { threw = true; }
  assert(threw);

  // Validation.
  Config n{"https://waf.example.com/", "admin/", "cwaf_k"};
  assert(validate_config(n, false).empty() && n.url == "https://waf.example.com" && n.admin_path == "/admin");
  assert(check("https://waf.example.com", "/admin").empty());
  assert(check("http://localhost:8080", "/admin").empty());
  assert(check("http://127.0.0.1:8080", "/admin").empty());
  assert(check("http://[::1]:8080", "/admin").empty());
  assert(!check("http://waf.example.com", "/admin").empty());
  assert(check("http://waf.example.com", "/admin", true).empty());
  assert(!check("http://localhost.evil.com", "/admin").empty());
  assert(!check("ftp://waf", "/admin").empty());
  assert(!check("https://waf.example.com/admin", "/admin").empty());
  Config bad{"https://w", "/admin", "sk_live"};
  assert(!validate_config(bad, false).empty());

  std::cout << "config_test ok\n";
}
