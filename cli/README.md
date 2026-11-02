# palisade-cli

A terminal client for a Palisade server, over the REST API with a bearer key.
A read-only key is enough.

## Build

Needs CMake 3.24+, a C++20 compiler and OpenSSL 3 headers (`libssl-dev`).
FTXUI, cpp-httplib and nlohmann/json are fetched at configure time.

```bash
cmake -S cli -B cli/build -G Ninja
cmake --build cli/build
ctest --test-dir cli/build
```

## Use

```bash
# Create a key in Settings → API keys, then paste it at the prompt:
palisade-cli login --url https://waf.example.com --admin-path /admin
palisade-cli            # interactive view (↑↓ select, r refresh, q quit)
palisade-cli services   # plain list
```

The config lives at `~/.config/palisade/config.toml` (mode 0600).
`PALISADE_URL`, `PALISADE_ADMIN_PATH` and `PALISADE_API_KEY` override it.
Plain `http://` is refused except to localhost, since the key would travel
unencrypted; `--allow-http` overrides that. Certificates are checked against
the system trust store.
