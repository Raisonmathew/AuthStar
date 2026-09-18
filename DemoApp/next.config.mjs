/** @type {import('next').NextConfig} */
const nextConfig = {
  // Proxy all /api/* calls to the AuthStar backend so the demo app
  // can use relative URLs without CORS or credential issues.
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000'}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
