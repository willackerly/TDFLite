# Quick Context

**Last Updated:** 2026-02-21
**Branch:** main
**Phase:** 0 — Scaffolding

## What is TDFLite?

A lightweight, single-binary reimplementation of the [OpenTDF platform](https://github.com/opentdf/platform) in pure Go. No Docker, no Postgres, no Keycloak.

## Current State

- Project scaffolding complete: directory layout, Go module, interfaces
- All core interfaces defined: Store, AuthN, AuthZ, KAS, Policy, Crypto, Entity Resolution
- In-memory store implementation done
- Server skeleton with health endpoints done
- Config loading (YAML + env vars) done
- **Nothing is wired together yet** — the binary starts but doesn't serve real API endpoints

## What's Next (Phase 1)

Wire up the Policy service HTTP handlers to the in-memory store. First real CRUD endpoints.

## Key Design Decision

**Interface-first, swap-ready:** Every subsystem is a Go interface. Lightweight defaults ship in the binary. Heavier backends (Postgres, Keycloak, HSM) can be swapped in by implementing the same interface.
