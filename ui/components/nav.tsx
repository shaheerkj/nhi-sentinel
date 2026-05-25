'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const links = [
  { href: '/',           label: 'Overview' },
  { href: '/identities', label: 'Identities' },
  { href: '/audit',      label: 'Audit' },
  { href: '/anomaly',    label: 'Anomaly' },
  { href: '/approvals',  label: 'Approvals' },
];

export function Nav() {
  const path = usePathname();
  return (
    <header className="border-b border-line bg-bg-soft">
      <div className="mx-auto flex max-w-7xl items-center gap-8 px-6 py-3">
        <Link href="/" className="font-mono text-sm tracking-wider text-ink">
          <span className="text-accent">NHI</span>-SENTINEL
          <span className="ml-2 text-ink-faint">console</span>
        </Link>
        <nav className="flex gap-1 text-sm">
          {links.map(l => {
            const active = l.href === '/' ? path === '/' : path.startsWith(l.href);
            return (
              <Link
                key={l.href}
                href={l.href}
                className={`rounded px-3 py-1.5 transition ${
                  active
                    ? 'bg-accent-soft text-ink'
                    : 'text-ink-dim hover:bg-bg-card hover:text-ink'
                }`}
              >
                {l.label}
              </Link>
            );
          })}
        </nav>
        <div className="ml-auto text-xs text-ink-faint">
          live · proxied via /api
        </div>
      </div>
    </header>
  );
}
