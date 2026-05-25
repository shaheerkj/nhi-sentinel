import './globals.css';
import type { Metadata } from 'next';
import { Nav } from '@/components/nav';

export const metadata: Metadata = {
  title: 'NHI-Sentinel Console',
  description: 'Non-human identity governance — operator console',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <Nav />
        <main className="mx-auto max-w-7xl px-6 py-6">{children}</main>
        <footer className="mx-auto max-w-7xl px-6 py-6 text-xs text-ink-faint">
          NHI-Sentinel · operator console · all actions audited
        </footer>
      </body>
    </html>
  );
}
