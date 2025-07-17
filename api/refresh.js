
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

  let roblosecurityCookie = req.query.cookie;

  if (!roblosecurityCookie) {
    return res.status(400).json({ error: "Cookie parameter is required" });
  }

  if (typeof roblosecurityCookie !== 'string' || roblosecurityCookie.trim().length === 0) {
    return res.status(400).json({ error: "Invalid cookie format" });
  }

  // Normalize cookie - remove .ROBLOSECURITY= prefix if present
  roblosecurityCookie = roblosecurityCookie.trim();
  if (roblosecurityCookie.startsWith('.ROBLOSECURITY=')) {
    roblosecurityCookie = roblosecurityCookie.substring(15);
  }

  // Check if it's a full cookie with warning or just the token part
  let isFullCookie = roblosecurityCookie.includes('_|WARNING:-DO-NOT-SHARE-THIS');
  let isTokenOnly = /^[A-Za-z0-9._-]+$/.test(roblosecurityCookie) && roblosecurityCookie.length > 100;

  if (!isFullCookie && !isTokenOnly) {
    return res.status(400).json({ error: "Invalid Roblox cookie format" });
  }

  // If it's token only, we need to add the warning prefix for internal processing
  if (isTokenOnly) {
    roblosecurityCookie = `_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_${roblosecurityCookie}`;
  }

  try {
    const authTicket = await generateAuthTicket(roblosecurityCookie.trim());

    if (authTicket === "Failed to fetch auth ticket") {
      return res.status(400).json({ error: "Invalid cookie or failed to generate auth ticket" });
    }

    const redemptionResult = await redeemAuthTicket(authTicket);

    if (!redemptionResult.success) {
      if (redemptionResult.robloxDebugResponse) {
        const status = redemptionResult.robloxDebugResponse.status;
        if (status === 401) {
          return res.status(401).json({ error: "Unauthorized: The provided cookie is invalid." });
        } else if (status === 429) {
          return res.status(429).json({ 
            error: "Rate limited: Your cookie is likely already fresh or you're refreshing too frequently. Please wait a few minutes before trying again." 
          });
        }
      }
      return res.status(400).json({ error: "Failed to refresh cookie. Please check if your cookie is valid." });
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
