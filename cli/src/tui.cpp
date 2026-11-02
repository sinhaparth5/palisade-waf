#include "tui.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "logs.hpp"

using namespace ftxui;
using nlohmann::json;

namespace {

constexpr int kPage = 50;      // rows per page in the logs view
constexpr int kTailMax = 500;  // rows the live tail keeps

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

Element tab_label(const std::string& label, bool active) {
  auto t = text(" " + label + " ");
  return active ? t | bold | underlined : t | dim;
}

}  // namespace

int run_tui(Api& api) {
  auto screen = ScreenInteractive::Fullscreen();
  int tab = 0;
  std::string status;

  // Services tab.
  json services = json::array();
  std::vector<std::string> names;
  int svc_sel = 0;
  auto load_services = [&] {
    try {
      services = api.get("/services");
      names.clear();
      for (const auto& s : services) names.push_back(s.value("Name", "?"));
      svc_sel = std::min(svc_sel, std::max(0, static_cast<int>(names.size()) - 1));
      status = std::to_string(names.size()) + " services";
    } catch (const std::exception& e) {
      status = e.what();
    }
  };

  // Logs tab. rows and lines stay index-aligned.
  std::string ip_text, app_text;
  bool blocked = false, logs_loaded = false, tailing = false;
  json rows = json::array();
  std::vector<std::string> lines;
  int log_sel = 0, offset = 0, total = 0;
  std::thread tail;
  std::shared_ptr<Api::Stop> tail_stop;
  int tail_gen = 0;  // bumped on every stop, so late posts from an old stream are dropped

  auto filter = [&] { return LogFilter{app_text, ip_text, blocked}; };
  auto set_rows = [&](json r) {
    rows = std::move(r);
    lines.clear();
    for (const auto& row : rows) lines.push_back(log_line(row));
    log_sel = 0;
  };
  auto load_logs = [&] {
    logs_loaded = true;
    try {
      auto r = api.get(logs_path(filter(), kPage, offset));
      total = r.value("total", 0);
      set_rows(r.value("logs", json::array()));
      int pages = std::max(1, (total + kPage - 1) / kPage);
      status = std::to_string(total) + " requests, page " + std::to_string(offset / kPage + 1) + "/" +
               std::to_string(pages);
    } catch (const std::exception& e) {
      status = e.what();
    }
  };
  auto stop_tail = [&] {
    tail_gen++;
    if (tail_stop) tail_stop->stop();
    if (tail.joinable()) tail.join();
    tailing = false;
  };
  auto start_tail = [&] {
    stop_tail();
    tailing = true;
    set_rows(json::array());
    status = "live tail: waiting for requests";
    int gen = tail_gen;
    tail_stop = std::make_shared<Api::Stop>();
    tail = std::thread([&, gen, f = filter(), stop = tail_stop] {
      try {
        api.stream("/logs/stream", [&, gen, f](const json& ev) {
          if (!log_matches(f, ev)) return;
          screen.Post([&, gen, ev] {
            if (gen != tail_gen) return;
            rows.insert(rows.begin(), ev);
            lines.insert(lines.begin(), log_line(ev));
            if (static_cast<int>(rows.size()) > kTailMax) {
              rows.erase(rows.end() - 1);
              lines.pop_back();
            }
            if (log_sel > 0) log_sel = std::min(log_sel + 1, static_cast<int>(rows.size()) - 1);
            status = "live tail: " + std::to_string(rows.size()) + " requests";
          });
          screen.PostEvent(Event::Custom);
        }, *stop);
      } catch (const std::exception& e) {
        screen.Post([&, gen, msg = std::string(e.what())] {
          if (gen != tail_gen) return;
          tailing = false;
          status = "live tail stopped: " + msg;
        });
        screen.PostEvent(Event::Custom);
      }
    });
  };

  // Request detail modal.
  bool show_detail = false;
  std::vector<std::string> detail_lines;
  std::string detail_title;
  int detail_sel = 0;
  auto open_detail = [&] {
    if (rows.empty()) return;
    int id = rows[log_sel].value("ID", 0);
    try {
      detail_lines.clear();
      for (auto& [k, v] : log_detail(api.get("/logs/" + std::to_string(id)))) {
        char label[32];
        std::snprintf(label, sizeof label, "%-16.16s", k.c_str());
        detail_lines.push_back(label + (v.empty() && k != "Headers" ? std::string("-") : v));
      }
      detail_title = " Request #" + std::to_string(id) + " ";
      detail_sel = 0;
      show_detail = true;
    } catch (const std::exception& e) {
      status = e.what();
    }
  };

  auto svc_menu = Menu(&names, &svc_sel);
  auto services_view = Renderer(svc_menu, [&] {
    Element detail = names.empty() ? text("No services.") | dim : service_detail(services[svc_sel]);
    return hbox({svc_menu->Render() | vscroll_indicator | frame | size(WIDTH, EQUAL, 28), separator(),
                 detail | flex});
  });

  Component log_menu;
  auto apply_filters = [&] {
    log_menu->TakeFocus();
    if (tailing) {
      start_tail();
    } else {
      offset = 0;
      load_logs();
    }
  };
  InputOption in_opt;
  in_opt.multiline = false;
  in_opt.on_enter = apply_filters;
  auto ip_in = Input(&ip_text, "any", in_opt);
  auto app_in = Input(&app_text, "any", in_opt);

  MenuOption log_opt;
  log_opt.on_enter = open_detail;
  log_opt.entries_option.transform = [&](const EntryState& s) {
    auto e = text(s.label);
    if (s.index >= 0 && s.index < static_cast<int>(rows.size()) && rows[s.index].value("Blocked", false))
      e |= color(Color::Red);
    if (s.focused) e |= inverted;
    if (s.active) e |= bold;
    return e;
  };
  log_menu = Menu(&lines, &log_sel, log_opt);
  auto logs_body = Container::Vertical({Container::Horizontal({ip_in, app_in}), log_menu});
  auto logs_view = Renderer(logs_body, [&] {
    auto mark = blocked ? "[x]" : "[ ]";
    auto bar = hbox({text(" IP: "), ip_in->Render() | size(WIDTH, EQUAL, 20), text("  Service: "),
                     app_in->Render() | size(WIDTH, EQUAL, 20), text(std::string("  ") + mark + " blocked only"),
                     filler(), tailing ? text(" ● LIVE ") | color(Color::Green) | bold : text("")});
    Element body = lines.empty() ? text(tailing ? "Waiting for requests…" : "No requests.") | dim
                                 : log_menu->Render() | vscroll_indicator | frame;
    return vbox({bar, separator(), body | flex});
  });

  auto tabs = Container::Tab({services_view, logs_view}, &tab);
  auto detail_menu = Menu(&detail_lines, &detail_sel);
  auto detail_view = Renderer(detail_menu, [&] {
    return window(text(detail_title) | bold, detail_menu->Render() | vscroll_indicator | frame) |
           size(WIDTH, LESS_THAN, 120) | size(HEIGHT, LESS_THAN, 40) | clear_under;
  });

  auto main_view = Renderer(tabs, [&] {
    std::string keys = tab == 0 ? "↑↓ select  r refresh  2 logs  q quit "
                       : tailing ? "enter details  f filter  b blocked  t stop tail  1 services  q quit "
                                 : "enter details  f filter  b blocked  n/p page  t live tail  r refresh  q quit ";
    return vbox({
        hbox({text(" Palisade ") | bold | inverted, tab_label("1 Services", tab == 0),
              tab_label("2 Logs", tab == 1)}),
        separator(),
        tabs->Render() | flex,
        separator(),
        hbox({text(" " + status) | flex, text(keys) | dim}),
    });
  });
  auto root = Modal(main_view, detail_view, &show_detail);

  auto app = CatchEvent(root, [&](Event e) {
    if (show_detail) {
      if (e == Event::Escape || e == Event::Character('q') || e == Event::Return) {
        show_detail = false;
        return true;
      }
      return false;
    }
    if (ip_in->Focused() || app_in->Focused()) {  // typing: only Esc is ours
      if (e == Event::Escape) {
        log_menu->TakeFocus();
        return true;
      }
      return false;
    }
    if (e == Event::Character('q') || e == Event::Escape) {
      screen.Exit();
      return true;
    }
    if (e == Event::Character('1')) {
      tab = 0;
      status = std::to_string(names.size()) + " services";
      return true;
    }
    if (e == Event::Character('2')) {
      tab = 1;
      if (!logs_loaded) load_logs();
      log_menu->TakeFocus();
      return true;
    }
    if (tab == 0) {
      if (e == Event::Character('r')) load_services();
      return e == Event::Character('r');
    }
    if (e == Event::Character('f')) {
      ip_in->TakeFocus();
      return true;
    }
    if (e == Event::Character('b')) {
      blocked = !blocked;
      apply_filters();
      return true;
    }
    if (e == Event::Character('t')) {
      if (tailing) {
        stop_tail();
        offset = 0;
        load_logs();
      } else {
        start_tail();
      }
      return true;
    }
    if (tailing) return false;
    if (e == Event::Character('r')) {
      load_logs();
      return true;
    }
    if (e == Event::Character('n') && offset + kPage < total) {
      offset += kPage;
      load_logs();
      return true;
    }
    if (e == Event::Character('p') && offset > 0) {
      offset = std::max(0, offset - kPage);
      load_logs();
      return true;
    }
    return false;
  });

  load_services();
  screen.Loop(app);
  stop_tail();
  return 0;
}
