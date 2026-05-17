/**
 * Runtime environment helpers (development / main / test).
 * Copyright (c) 2025 Discernible IO. All rights reserved.
 */

function getNodeEnv() {
  const value = process.env.NODE_ENV;
  return value && String(value).trim() ? String(value).trim().toLowerCase() : 'development';
}

function isMainEnvironment() {
  return getNodeEnv() === 'main';
}

function isDevelopmentEnvironment() {
  return getNodeEnv() === 'development';
}

function isTestEnvironment() {
  return getNodeEnv() === 'test';
}

/** Main deploy: strict security (hidden error details, required peer keys). */
function isStrictEnvironment() {
  return isMainEnvironment();
}

module.exports = {
  getNodeEnv,
  isMainEnvironment,
  isDevelopmentEnvironment,
  isTestEnvironment,
  isStrictEnvironment,
};
