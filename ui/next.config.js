/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Proxy backend API calls in dev to avoid CORS. In prod, set the env vars
  // to point directly at the deployed services.
  async rewrites() {
    return [
      { source: '/api/audit/:path*',    destination: `${process.env.NEXT_PUBLIC_AUDIT_URL    || 'http://localhost:8001'}/:path*` },
      { source: '/api/identity/:path*', destination: `${process.env.NEXT_PUBLIC_IDENTITY_URL || 'http://localhost:8002'}/:path*` },
      { source: '/api/anomaly/:path*',  destination: `${process.env.NEXT_PUBLIC_ANOMALY_URL  || 'http://localhost:8000'}/:path*` },
      { source: '/api/approval/:path*', destination: `${process.env.NEXT_PUBLIC_APPROVAL_URL || 'http://localhost:8003'}/:path*` },
    ];
  },
};
module.exports = nextConfig;
