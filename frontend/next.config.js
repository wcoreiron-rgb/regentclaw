/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    // INTERNAL_API_URL is server-side only (no NEXT_PUBLIC_ prefix).
    // It resolves to http://backend:8000 inside Docker, or http://localhost:8000
    // when running locally outside Docker.
    // The browser never sees this URL — it only ever calls /api/v1/... which
    // Next.js intercepts here and proxies to the backend.
    const target = process.env.INTERNAL_API_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${target}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
