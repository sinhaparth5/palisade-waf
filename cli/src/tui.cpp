#include "tui.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <cstdio>
#include <string>
#include <vector>

using namespace ftxui;
using nlohmann::json;

namespace {

std::string join(const json& arr) {
  std::string out;
  if (!arr.is_array()) return out;
  for (const auto& v : arr) {
    if (!v.is_string()) continue;
    if (!out.empty()) out += ", ";
    out += v.get<std::string>();
  }
  return out;
}

std::string onoff(const json& s, const char* key) { return s.value(key, false) ? "on" : "off"; }

std::string or_dash(std::string v) { return v.empty() ? "-" : v; }

std::string rate_limit(const json& s) {
  double rps = s.value("RateLimitRPS", 0.0);
  if (rps <= 0) return "global";
  char buf[64];
  std::snprintf(buf, sizeof buf, "%g rps, burst %d", rps, s.value("RateLimitBurst", 0));
  return buf;
}

Element service_detail(const json& s) {
  auto host = s.value("Host", "");
  std::vector<std::pair<std::string, std::string>> rows = {
      {"ID", std::to_string(s.value("ID", 0))},
      {"Match", host.empty() ? "prefix " + s.value("Prefix", "") : "host " + host},
      {"Aliases", or_dash(join(s.value("HostAliases", json::array())))},
      {"Canonical", or_dash(s.value("CanonicalHost", ""))},
      {"Backend", s.value("Backend", "")},
      {"More backends", or_dash(join(s.value("ExtraBackends", json::array())))},
      {"Balancing", or_dash(s.value("LBPolicy", ""))},
      {"Health path", or_dash(s.value("HealthPath", ""))},
      {"TLS", or_dash(s.value("TLSMode", ""))},
      {"Rate limit", rate_limit(s)},
      {"Bot mode", or_dash(s.value("BotMode", ""))},
      {"Cache", onoff(s, "CacheEnabled")},
      {"Compression", onoff(s, "CompressEnabled")},
      {"HTTP/3", onoff(s, "HTTP3Enabled")},
      {"Response inspect", or_dash(s.value("ResponseInspect", ""))},
      {"Login paths", or_dash(join(s.value("LoginPaths", json::array())))},
  };
  Elements lines;
  for (auto& [k, v] : rows) lines.push_back(hbox({text(k) | dim | size(WIDTH, EQUAL, 18), paragraph(v)}));
  return vbox({text(s.value("Name", "")) | bold, separator(), vbox(lines)});
}

}  // namespace

int run_tui(Api& api) {
  auto screen = ScreenInteractive::Fullscreen();
  json services = json::array();
  std::vector<std::string> names;
  std::string status;
  int selected = 0;

  auto refresh = [&] {
    try {
      services = api.get("/services");
      names.clear();
      for (const auto& s : services) names.push_back(s.value("Name", "?"));
      selected = std::min(selected, std::max(0, static_cast<int>(names.size()) - 1));
      status = std::to_string(names.size()) + " services";
    } catch (const std::exception& e) {
      status = e.what();
    }
  };
  refresh();

  auto menu = Menu(&names, &selected);
  auto view = Renderer(menu, [&] {
    Element detail = names.empty() ? text("No services.") | dim : service_detail(services[selected]);
    return vbox({
        hbox({text(" Palisade ") | bold | inverted, text(" Services ")}),
        separator(),
        hbox({menu->Render() | vscroll_indicator | frame | size(WIDTH, EQUAL, 28), separator(),
              detail | flex}) | flex,
        separator(),
        hbox({text(" " + status) | flex, text("↑↓ select  r refresh  q quit ") | dim}),
    });
  });
  auto app = CatchEvent(view, [&](Event e) {
    if (e == Event::Character('q') || e == Event::Escape) {
      screen.Exit();
      return true;
    }
    if (e == Event::Character('r')) {
      refresh();
      return true;
    }
    return false;
  });
  screen.Loop(app);
  return 0;
}
