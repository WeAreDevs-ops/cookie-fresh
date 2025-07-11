const { generateAuthTicket, redeemAuthTicket } = require('../../refresh');

module.exports = async (req, res) => {
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
    const authTicket = await generateAuthTicket(roblosecurityCookie);

    if (authTicket === "Failed to fetch auth ticket") {
      return res.status(400).json({ error: "Invalid cookie or failed to generate auth ticket" });
    }

    const redemptionResult = await redeemAuthTicket(authTicket);

    if (!redemptionResult.success) {
      return res.status(400).json({ error: "Failed to refresh cookie", debug: redemptionResult });
    }

    const refreshedCookie = redemptionResult.refreshedCookie || '';

    return res.status(200).json({
      success: true,
      authTicket,
      refreshedCookie
    });

  } catch (error) {
    console.error('Error in /api/refresh.js:', error);
    return res.status(500).json({ error: "Internal server error" });
  }
};
