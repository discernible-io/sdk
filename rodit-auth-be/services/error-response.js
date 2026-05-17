const DEFAULT_ERROR_STATUS = 500;

function buildErrorResponse({ requestId, code, message, details }) {
  const payload = {
    error: {
      code,
      message
    },
    requestId,
    timestamp: new Date().toISOString()
  };

  if (details && Object.keys(details).length > 0) {
    payload.error.details = details;
  }

  return payload;
}

function sendError(res, { statusCode = DEFAULT_ERROR_STATUS, requestId, code, message, details }) {
  return res
    .status(statusCode)
    .json(buildErrorResponse({ requestId, code, message, details }));
}

module.exports = {
  buildErrorResponse,
  sendError
};
