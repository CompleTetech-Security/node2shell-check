#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
// Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
'use strict';
// Explicit optional collector: builtins only, no app imports, arguments, environment,
// hostnames, filesystem reads, sockets, DNS queries, shell, TLS connections or decoding.
const versions = process.versions || {};
if (!versions.node || versions.bun || versions.deno || versions.electron) {
  process.stderr.write('A standalone Node.js runtime is required.\n');
  process.exitCode = 2;
} else {
  const builtin = name => { try { return require(name); } catch (_) { return null; } };
  const h2 = builtin('node:http2');
  const tls = builtin('node:tls');
  const dns = builtin('node:dns');
  const v8 = builtin('node:v8');
  const sea = builtin('node:sea');
  const zlib = builtin('node:zlib');
  const available = (object, names) => object ? names.every(name => typeof object[name] === 'function') : null;
  const features = process.features || {};
  const bool = value => typeof value === 'boolean' ? value : null;
  let isSea = null;
  try { if (sea && typeof sea.isSea === 'function') isSea = bool(sea.isSea()); } catch (_) { /* unknown */ }
  const report = {
    schema_version: 'node-capabilities/1',
    runtime: 'node',
    node_version: versions.node,
    build_source: 'unknown',
    platform: process.platform,
    architecture: process.arch,
    library_versions: Object.fromEntries(['openssl', 'cares', 'brotli', 'v8'].map(name => [name, typeof versions[name] === 'string' ? versions[name] : ''])),
    build_features: {tls: bool(features.tls), tls_alpn: bool(features.tls_alpn), tls_sni: bool(features.tls_sni), tls_ocsp: bool(features.tls_ocsp)},
    capabilities: {
      http2_api_available: available(h2, ['connect', 'createServer']),
      tls_api_available: available(tls, ['connect', 'createServer']),
      dns_api_available: available(dns, ['lookup', 'resolve']),
      permission_api_available: process.permission ? typeof process.permission.has === 'function' : null,
      startup_snapshot_api_available: v8 && v8.startupSnapshot ? available(v8.startupSnapshot, ['isBuildingSnapshot']) : null,
      sea_api_available: available(sea, ['isSea']),
      sea_is_sea: isSea,
      brotli_decoder_api_available: available(zlib, ['brotliDecompress', 'brotliDecompressSync', 'createBrotliDecompress']),
    },
    application_use: 'unknown',
    reachability: 'unknown',
    exploitability: 'not_tested',
  };
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}
