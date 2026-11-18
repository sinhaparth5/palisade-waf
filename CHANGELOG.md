# Changelog

All notable changes to **Palisade** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file deliberately keeps only two sections: **[Unreleased]**, where changes
accumulate, and the **most recently published version**, kept so the current
release is readable without leaving the repo. `make tag VERSION=vX.Y.Z` promotes
Unreleased into a new version section, drops the previous one, and opens a fresh
Unreleased — older entries stay available in their git tags and GitHub releases
rather than growing this file forever.

## [Unreleased]

- (#324) Optional IP2Proxy database path for the hosting/VPN threat score signal

## [3.4.0] - 2026-11-17

- (#328) Helm chart: single-replica deployment with a persistent /data volume
- (#329) Keep the database across Kubernetes upgrades, rollbacks and uninstalls
- (#330) Load the DB key, first admin and TLS files from Kubernetes Secrets
- (#331) Resolve the real client IP behind Kubernetes Ingress and cloud load balancers
- (#332) TLS options on Kubernetes: Ingress termination, built-in ACME, cert-manager
- (#333) Separate admin Service and NetworkPolicy in the Helm chart
- (#334) Optional Varnish sidecar in the Helm chart
- (#335) Prometheus ServiceMonitor and Grafana dashboard
- (#336) Write the access log to stdout for kubectl logs and log shippers
- (#337) Declarative config for GitOps: import a config file on install
- (#338) Publish the Helm chart with each release and test it in CI
- (#339) Kubernetes and Helm documentation

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.4.0...main
[3.4.0]: https://github.com/sinhaparth5/palisade-waf/compare/v3.3.4...v3.4.0
