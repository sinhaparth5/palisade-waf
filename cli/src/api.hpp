#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

  // Stops one stream() call from another thread, even before it connects.
  // Use a fresh one per stream.
  class Stop {
   public:
    void stop();

   private:
    friend class Api;
    std::mutex mu_;
    httplib::Client* client_ = nullptr;  // guarded by mu_
    std::atomic<bool> stopped_ = false;
  };

  // Reads the server-sent events at path, calling on_event with each data
  // payload, until the server closes or the read fails (throws ApiError), or
  // until stop.stop() (returns normally). Uses its own connection, so get()
  // stays usable meanwhile.
  void stream(const std::string& path, const std::function<void(const nlohmann::json&)>& on_event, Stop& stop);

 private:
  Config cfg_;
  std::string base_;
  std::unique_ptr<httplib::Client> http_;
};

// path?k=v&..., values URL-encoded, empty values left out.
std::string with_query(std::string path, const std::vector<std::pair<std::string, std::string>>& q);
