#pragma once
#include <memory>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "config.hpp"

namespace httplib { class Client; }

struct ApiError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// Thin bearer-key client for {admin_path}/api/v1. Certificates are verified
// against the system trust store.
class Api {
 public:
  explicit Api(const Config& c);
  ~Api();

  // GET {admin_path}/api/v1{path}; throws ApiError on transport errors and
  // non-2xx responses (using the server's {"error": ...} text when present).
  nlohmann::json get(const std::string& path);

 private:
  std::string base_;
  std::unique_ptr<httplib::Client> http_;
};
