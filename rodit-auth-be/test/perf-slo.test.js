#!/usr/bin/env node
/**
 * Performance SLO helper unit tests (no live API).
 * Run: node sdk/test/perf-slo.test.js
 */

"use strict";

const assert = require("assert");
const path = require("path");

const {
  computeP95,
  discardWarmup,
  evaluateP95Gate,
  findMetricValue,
  PERF_SPECS,
} = require(path.join(__dirname, "../../src/test-modules/perf-slo-utils"));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`ok ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`not-passed ${name}: ${err.message}`);
  }
}

test("computeP95 on sorted samples", () => {
  const p95 = computeP95([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
  assert.strictEqual(p95, 100);
});

test("discardWarmup removes first sample", () => {
  assert.deepStrictEqual(discardWarmup([99, 10, 20]), [10, 20]);
});

test("evaluateP95Gate passes within threshold", () => {
  const samples = Array.from({ length: 31 }, () => 50);
  const gate = evaluateP95Gate("SPEC_PERF_LOGIN_TIMESTAMP_P95_MS", samples);
  assert.strictEqual(gate.passed, true);
  assert.strictEqual(gate.p95, 50);
});

test("evaluateP95Gate fails above threshold", () => {
  const samples = Array.from({ length: 31 }, () => 500);
  const gate = evaluateP95Gate("SPEC_PERF_LOGIN_TIMESTAMP_P95_MS", samples);
  assert.strictEqual(gate.passed, false);
});

test("findMetricValue reads nested counters", () => {
  const value = findMetricValue(
    { metrics: { near_identity_get_token: 42 } },
    "near_identity_get_token"
  );
  assert.strictEqual(value, 42);
});

test("PERF_SPECS defines all latency gates", () => {
  const required = [
    "SPEC_PERF_LOGIN_TIMESTAMP_P95_MS",
    "SPEC_PERF_LOGIN_POST_P95_MS",
    "SPEC_PERF_HOLANONCE_P95_MS",
    "SPEC_PERF_JWT_PROTECTED_NOP_P95_MS",
    "SPEC_PERF_ME_IDENTITY_P95_MS",
    "SPEC_PERF_VERIFY_HOLA_P95_MS",
    "SPEC_PERF_AGENTS_LIST_P95_MS",
    "SPEC_PERF_HEALTH_P95_MS",
  ];
  for (const id of required) {
    assert.ok(PERF_SPECS[id], `missing ${id}`);
    assert.ok(PERF_SPECS[id].p95MaxMs > 0);
    assert.ok(PERF_SPECS[id].minSamples > 0);
  }
  assert.strictEqual(PERF_SPECS.SPEC_PERF_CHAIN_READ_RATIO_MAX, 0.1);
});

console.log(`\nperf-slo.test.js: ${passed} passed, ${failed} not-passed`);
process.exit(failed > 0 ? 1 : 0);
