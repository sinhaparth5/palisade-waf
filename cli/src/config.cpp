#include "config.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace {

std::string trim(const std::string& s) {
  auto b = s.find_first_not_of(" \t\r");
  if (b == std::string::npos) return "";
  return s.substr(b, s.find_last_not_of(" \t\r") - b + 1);
}

std::string env(const char* name) {
  const char* v = std::getenv(name);
  return v ? v : "";
}

// TOML basic strings: escape backslash and quote; nothing else we write needs it.
std::string quote(const std::string& v) {
  std::string out = "\"";
  for (char ch : v) {
    if (ch == '"' || ch == '\\') out += '\\';
    out += ch;
  }
  return out + "\"";
}

std::string unquote(const std::string& v, int line) {
  if (v.size() < 2 || v.front() != '"' || v.back() != '"')
    throw std::runtime_error("config line " + std::to_string(line) + ": value must be a quoted string");
  std::string out;
  for (size_t i = 1; i + 1 < v.size(); i++) {
    if (v[i] == '\\' && i + 2 < v.size()) i++;
    out += v[i];
  }
  return out;
}

}  // namespace

fs::path config_path() {
  if (auto x = env("XDG_CONFIG_HOME"); !x.empty()) return fs::path(x) / "palisade" / "config.toml";
  return fs::path(env("HOME")) / ".config" / "palisade" / "config.toml";
}

Config parse_config(const std::string& text) {
  Config c;
  std::istringstream in(text);
  std::string raw;
  for (int n = 1; std::getline(in, raw); n++) {
    auto line = trim(raw);
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos)
      throw std::runtime_error("config line " + std::to_string(n) + ": expected key = \"value\"");
    auto key = trim(line.substr(0, eq));
    auto val = unquote(trim(line.substr(eq + 1)), n);
    if (key == "url") c.url = val;
    else if (key == "admin_path") c.admin_path = val;
    else if (key == "api_key") c.api_key = val;
  }
  return c;
}

std::string format_config(const Config& c) {
  return "# palisade-cli config. Holds an API key: keep it private.\n"
         "url = " + quote(c.url) + "\n"
         "admin_path = " + quote(c.admin_path) + "\n"
         "api_key = " + quote(c.api_key) + "\n";
}

Config load_config() {
  Config c;
  std::ifstream f(config_path());
  if (f) {
    std::stringstream ss;
    ss << f.rdbuf();
    c = parse_config(ss.str());
  }
  if (auto v = env("PALISADE_URL"); !v.empty()) c.url = v;
  if (auto v = env("PALISADE_ADMIN_PATH"); !v.empty()) c.admin_path = v;
  if (auto v = env("PALISADE_API_KEY"); !v.empty()) c.api_key = v;
  return c;
}

void save_config(const Config& c) {
  auto path = config_path();
  fs::create_directories(path.parent_path());
  fs::permissions(path.parent_path(), fs::perms::owner_all);
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) throw std::runtime_error("cannot write " + path.string());
  ::fchmod(fd, 0600);  // an existing file keeps its old mode otherwise
  auto body = format_config(c);
  bool ok = ::write(fd, body.data(), body.size()) == static_cast<ssize_t>(body.size());
  ::close(fd);
  if (!ok) throw std::runtime_error("short write to " + path.string());
}

std::string validate_config(Config& c, bool allow_http) {
  while (!c.url.empty() && c.url.back() == '/') c.url.pop_back();
  std::string rest;
  bool http = false;
  if (c.url.rfind("https://", 0) == 0) {
    rest = c.url.substr(8);
  } else if (c.url.rfind("http://", 0) == 0) {
    rest = c.url.substr(7);
    http = true;
  } else {
    return "url must start with https:// (e.g. https://waf.example.com)";
  }
  if (rest.empty() || rest.find('/') != std::string::npos)
    return "url is scheme://host[:port] only; put the admin path in --admin-path";
  if (http) {
    auto host = rest.front() == '[' ? rest.substr(0, rest.find(']') + 1) : rest.substr(0, rest.find(':'));
    bool loopback = host == "localhost" || host.rfind("127.", 0) == 0 || host == "[::1]";
    if (!loopback && !allow_http)
      return "refusing plain http to " + host + ": the API key would be sent unencrypted (use https, or --allow-http)";
  }
  if (c.admin_path.empty() || c.admin_path.front() != '/') c.admin_path = "/" + c.admin_path;
  while (c.admin_path.size() > 1 && c.admin_path.back() == '/') c.admin_path.pop_back();
  if (c.api_key.rfind("cwaf_", 0) != 0) return "API key must start with cwaf_ (create one in Settings → API keys)";
  return "";
}
