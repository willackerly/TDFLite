// Package jsonfile provides a JSON file-backed store that wraps the in-memory
// store with periodic persistence to disk.
//
// State is kept in memory for fast access and flushed to JSON files in the
// configured data directory. On startup, existing JSON files are loaded.
package jsonfile

// Placeholder for JSON file persistence implementation.
// This will wrap the memory store and add:
// - Load from JSON files on startup
// - Periodic flush to JSON files
// - Flush on shutdown
//
// File layout in data_dir:
//   namespaces.json
//   attribute_definitions.json
//   attribute_values.json
//   subject_mappings.json
//   subject_condition_sets.json
//   resource_mappings.json
//   kas_registrations.json
//   keys.json
//   key_access_grants.json
//   identities.json
