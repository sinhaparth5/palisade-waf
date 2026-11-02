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
palisade-cli            # interactive view
palisade-cli services   # plain list
palisade-cli logs --blocked --ip 203.0.113.9 --service shop --limit 100
palisade-cli logs -f    # follow new requests (same filters apply)
palisade-cli stats      # totals, top blocked IPs, countries and rules
palisade-cli rules bans # also: ip, geo, custom, exceptions, vpatches
```

Release builds attach `palisade-cli-linux-amd64` (listed in `checksums.txt`).
It needs OpenSSL 3 (`libssl3`) on the machine running it.

In the interactive view, `1`–`4` switch between Services, Logs, Stats and
Rules (`r` refreshes; in Rules, `←`/`→` move between the list picker and its
rows). In
Logs: `enter` opens a request (headers arrive already redacted), `f` edits
the IP/service filters (enter applies, esc leaves), `b` toggles blocked
only, `n`/`p` page, `t` toggles the live tail (newest 500 kept), `q` quits.

The config lives at `~/.config/palisade/config.toml` (mode 0600).
`PALISADE_URL`, `PALISADE_ADMIN_PATH` and `PALISADE_API_KEY` override it.
Plain `http://` is refused except to localhost, since the key would travel
unencrypted; `--allow-http` overrides that. Certificates are checked against
the system trust store.
