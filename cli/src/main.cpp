#include <termios.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "api.hpp"
#include "config.hpp"
#include "logs.hpp"
#include "tui.hpp"
#include "views.hpp"

namespace {

constexpr const char* kUsage = R"(palisade-cli: browse a Palisade WAF from your terminal

Usage:
  palisade-cli                 open the interactive view
  palisade-cli login --url https://waf.example.com [--admin-path /admin] [--allow-http]
                               save the server and an API key (read from stdin)
  palisade-cli services        list services
  palisade-cli logs [--blocked] [--ip IP] [--service NAME] [--limit N] [-f]
                               recent requests, newest first; -f follows live
  palisade-cli stats           traffic totals, top blocked IPs, countries and rules
  palisade-cli rules ip|bans|geo|custom|exceptions|vpatches
  palisade-cli --version

Config: ~/.config/palisade/config.toml (0600). PALISADE_URL, PALISADE_ADMIN_PATH
and PALISADE_API_KEY override it. A read-only API key is enough.
)";

// Reads one line from stdin without echo when it is a terminal.
std::string read_secret(const char* prompt) {
  bool tty = isatty(STDIN_FILENO);
  termios old{};
  if (tty) {
    std::cerr << prompt << std::flush;
    tcgetattr(STDIN_FILENO, &old);
    termios quiet = old;
    quiet.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
  }
  std::string line;
  std::getline(std::cin, line);
  if (tty) {
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    std::cerr << "\n";
  }
  while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
  return line;
}

int login(const std::vector<std::string>& args) {
  Config c;
  bool allow_http = false;
  for (size_t i = 0; i < args.size(); i++) {
    if (args[i] == "--url" && i + 1 < args.size()) c.url = args[++i];
    else if (args[i] == "--admin-path" && i + 1 < args.size()) c.admin_path = args[++i];
    else if (args[i] == "--allow-http") allow_http = true;
    else {
      std::cerr << "login: unknown argument " << args[i] << "\n" << kUsage;
      return 2;
    }
  }
  if (c.url.empty()) {
    std::cerr << "login: --url is required\n";
    return 2;
  }
  c.api_key = read_secret("API key: ");
  if (auto err = validate_config(c, allow_http); !err.empty()) {
    std::cerr << "login: " << err << "\n";
    return 2;
  }
  try {
    auto services = Api(c).get("/services");
    save_config(c);
    std::cout << "Connected to " << c.url << " (" << services.size() << " services). Saved "
              << config_path().string() << "\n";
  } catch (const std::exception& e) {
    std::cerr << "login: " << e.what() << "\n";
    return 1;
  }
  return 0;
}

int list_services(Api& api) {
  auto list = api.get("/services");
  std::printf("%-5s %-24s %-32s %s\n", "ID", "NAME", "MATCH", "BACKEND");
  for (const auto& s : list) {
    auto host = s.value("Host", "");
    auto match = host.empty() ? "prefix " + s.value("Prefix", "") : host;
    std::printf("%-5d %-24s %-32s %s\n", s.value("ID", 0), s.value("Name", "").c_str(), match.c_str(),
                s.value("Backend", "").c_str());
  }
  return 0;
}

int logs(Api& api, const std::vector<std::string>& args) {
  LogFilter f;
  int limit = 50;
  bool follow = false;
  for (size_t i = 0; i < args.size(); i++) {
    if (args[i] == "--blocked") f.blocked = true;
    else if (args[i] == "-f" || args[i] == "--follow") follow = true;
    else if (args[i] == "--ip" && i + 1 < args.size()) f.ip = args[++i];
    else if (args[i] == "--service" && i + 1 < args.size()) f.app = args[++i];
    else if (args[i] == "--limit" && i + 1 < args.size()) limit = std::atoi(args[++i].c_str());
    else {
      std::cerr << "logs: unknown argument " << args[i] << "\n" << kUsage;
      return 2;
    }
  }
  if (follow) {
    Api::Stop never;
    api.stream(
        "/logs/stream", [&](const nlohmann::json& ev) {
          if (log_matches(f, ev)) std::cout << log_line(ev) << std::endl;
        },
        never);
    return 0;
  }
  if (limit < 1) {
    std::cerr << "logs: --limit must be a positive number\n";
    return 2;
  }
  for (const auto& row : api.get(logs_path(f, limit, 0)).value("logs", nlohmann::json::array()))
    std::cout << log_line(row) << "\n";
  return 0;
}

int print_lines(const std::vector<std::string>& lines) {
  for (const auto& l : lines) std::cout << l << "\n";
  return 0;
}

int rules(Api& api, const std::vector<std::string>& args) {
  const RuleView* v = args.size() == 1 ? find_rule_view(args[0]) : nullptr;
  if (!v) {
    std::cerr << "rules: pick one of ip, bans, geo, custom, exceptions, vpatches\n";
    return 2;
  }
  return print_lines(rule_lines(*v, api.get(v->path)));
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> args(argv + 1, argv + argc);
  std::string cmd = args.empty() ? "" : args[0];
  if (cmd == "-h" || cmd == "--help" || cmd == "help") {
    std::cout << kUsage;
    return 0;
  }
  if (cmd == "--version") {
    std::cout << "palisade-cli " PALISADE_CLI_VERSION "\n";
    return 0;
  }
  if (cmd == "login") return login({args.begin() + 1, args.end()});

  try {
    Config c = load_config();
    if (c.url.empty() || c.api_key.empty()) {
      std::cerr << "Not logged in. Run: palisade-cli login --url https://your-waf\n";
      return 2;
    }
    // Saved configs were checked at login; env overrides are trusted as given.
    if (auto err = validate_config(c, true); !err.empty()) {
      std::cerr << err << "\n";
      return 2;
    }
    Api api(c);
    if (cmd.empty()) return run_tui(api);
    if (cmd == "services") return list_services(api);
    if (cmd == "logs") return logs(api, {args.begin() + 1, args.end()});
    if (cmd == "stats") return print_lines(stats_lines(api.get("/stats")));
    if (cmd == "rules") return rules(api, {args.begin() + 1, args.end()});
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
  std::cerr << "unknown command " << cmd << "\n" << kUsage;
  return 2;
}
