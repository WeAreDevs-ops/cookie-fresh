
const { generateAuthTicket, redeemAuthTicket } = require('../refresh');

module.exports = async (req, res) => {
  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const roblosecurityCookie = req.query.cookie;

  if (!roblosecurityCookie) {
    return res.status(400).json({ error: "Cookie parameter is required" });
  }

  if (typeof roblosecurityCookie !== 'string' || roblosecurityCookie.trim().length === 0) {
    return res.status(400).json({ error: "Invalid cookie format" });
  }

  if (!roblosecurityCookie.includes('_|WARNING:-DO-NOT-SHARE-THIS')) {
    return res.status(400).json({ error: "Invalid Roblox cookie format" });
  }

  try {
    const authTicket = await generateAuthTicket(roblosecurityCookie.trim());

    if (authTicket === "Failed to fetch auth ticket") {
      return res.status(400).json({ error: "Invalid cookie or failed to generate auth ticket" });
    }

    const redemptionResult = await redeemAuthTicket(authTicket);

    if (!redemptionResult.success) {
      if (redemptionResult.robloxDebugResponse && redemptionResult.robloxDebugResponse.status === 401) {
        return res.status(401).json({ error: "Unauthorized: The provided cookie is invalid." });
      } else {
        return res.status(400).json({ error: "Failed to refresh cookie. Please check if your cookie is valid." });
      }
    }

    const refreshedCookie = redemptionResult.refreshedCookie || '';

    if (!refreshedCookie) {
      return res.status(500).json({ error: "Cookie refresh completed but no refreshed cookie received" });
    }

    return res.status(200).json({
      authTicket,
      redemptionResult: {
        success: true,
        refreshedCookie: refreshedCookie
      }
    });

  } catch (error) {
    console.error('Error in /api/refresh:', error.message);
    return res.status(500).json({ error: "Internal server error occurred while refreshing cookie" });
  }
};
