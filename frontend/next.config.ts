import type { NextConfig } from "next";

const enableApiProxy = process.env.ENABLE_NEXT_API_PROXY !== "false";
const backendOrigin = (
  process.env.BACKEND_INTERNAL_URL?.trim() || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  images: {
    unoptimized: true,
  },
  async rewrites() {
    if (!enableApiProxy) {
      return [];
    }
    return [
      {
        source: "/api/:path*",
        destination: `${backendOrigin}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
