#pragma once
#include <filesystem>
#include <string>

// Where the CLI finds a Palisade server. Saved as a small TOML file
// (flat `key = "value"` lines only) and overridable by environment.
struct Config {
  std::string url;                 // scheme://host[:port], no trailing slash
  std::string admin_path = "/admin";
  std::string api_key;             // cwaf_...
};

// $XDG_CONFIG_HOME/palisade/config.toml, else ~/.config/palisade/config.toml.
std::filesystem::path config_path();

// Parses the file's text. Unknown keys are ignored; throws on a malformed line.
Config parse_config(const std::string& text);
std::string format_config(const Config& c);

// Loads the file (missing = empty config), then applies PALISADE_URL,
// PALISADE_ADMIN_PATH and PALISADE_API_KEY.
Config load_config();

// Writes the file 0600 (directory 0700), since the key grants API access.
void save_config(const Config& c);

// Normalises and checks url/admin_path. Plain http is refused except to a
// loopback host unless allow_http, because the key would cross in clear.
// Returns an error message, or "" when valid.
std::string validate_config(Config& c, bool allow_http);
