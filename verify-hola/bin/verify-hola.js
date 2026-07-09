#!/usr/bin/env node
"use strict";

const { buildHolaReport, verifyHola } = require("../lib/report");
const { buildHolaReportViaRpc, verifyHolaViaRpc } = require("../lib/verify-rpc");

function usage() {
  process.stderr.write(`Usage:
  verify-hola verify <hola-string> [--rpc] [--expected-recipient <tokenId>]
  verify-hola report <hola-string> [--rpc] [--expected-recipient <tokenId>] [--canonical-peer <tokenId>]
  echo "HOLA/..." | verify-hola report - --rpc

Verify paths:
  --rpc     Direct NEAR RPC via @rodit/rodit-auth-be (recommended — no IdentyClaw API)
  default   POST /api/identity/verify on IDENTYCLAW_BASE_URL

RPC env (required with --rpc):
  NEAR_RPC_URL          e.g. https://rpc.mainnet.fastnear.com
  NEAR_CONTRACT_ID      e.g. genaaaa-identyclaw-com.near
  NEAR_RPC_TIMEOUT      optional milliseconds (default from rodit-auth-be)

API env (default path):
  IDENTYCLAW_BASE_URL   default https://api.identyclaw.com
  IDENTYCLAW_JWT        optional
  IDENTYCLAW_CANONICAL_PEER_ID
  IDENTYCLAW_EXPECTED_RECIPIENT
`);
}

function parseArgs(argv) {
  const args = [...argv];
  const command = args.shift();
  let hola = args[0];
  const options = {
    useRpc: false,
    expectedRecipient: process.env.IDENTYCLAW_EXPECTED_RECIPIENT,
    canonicalPeerId: process.env.IDENTYCLAW_CANONICAL_PEER_ID,
    baseUrl: process.env.IDENTYCLAW_BASE_URL,
    jwt: process.env.IDENTYCLAW_JWT,
    nearRpcUrl: process.env.NEAR_RPC_URL,
    nearContractId: process.env.NEAR_CONTRACT_ID
  };

  if (hola === "-") hola = null;

  for (let i = 1; i < args.length; i += 1) {
    const flag = args[i];
    if (flag === "--rpc") {
      options.useRpc = true;
    } else if (flag === "--expected-recipient") {
      options.expectedRecipient = args[++i];
    } else if (flag === "--canonical-peer") {
      options.canonicalPeerId = args[++i];
    } else if (flag === "--base-url") {
      options.baseUrl = args[++i];
    } else if (flag === "--near-rpc-url") {
      options.nearRpcUrl = args[++i];
    } else if (flag === "--near-contract-id") {
      options.nearContractId = args[++i];
    }
  }

  return { command, hola, options };
}

async function readHolaFromStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const hola = Buffer.concat(chunks).toString("utf8").trim();
  if (!hola) throw new Error("empty HOLA on stdin");
  return hola;
}

async function main() {
  const { command, hola: holaArg, options } = parseArgs(process.argv.slice(2));
  if (!command || !["verify", "report"].includes(command)) {
    usage();
    process.exit(1);
  }

  const hola = holaArg ? holaArg : await readHolaFromStdin();

  if (command === "verify") {
    const result = options.useRpc
      ? await verifyHolaViaRpc(hola, options)
      : await verifyHola(hola, options);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    process.exit(result.verified ? 0 : 1);
    return;
  }

  const report = options.useRpc
    ? await buildHolaReportViaRpc(hola, options)
    : await buildHolaReport(hola, { ...options, includeProfile: true });

  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exit(report.verified ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(JSON.stringify({ verified: false, error: err.message }) + "\n");
  process.exit(1);
});
