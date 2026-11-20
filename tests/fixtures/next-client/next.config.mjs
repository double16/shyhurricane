export default {
  basePath: process.env.FIXTURE_BASE_PATH || "",
  assetPrefix: process.env.FIXTURE_ASSET_PREFIX || "",
  productionBrowserSourceMaps: process.env.FIXTURE_BROWSER_MAPS === "1",
};
