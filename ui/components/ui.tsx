// Tiny presentation primitives shared across pages. Keeping them all in one
// file because the surface is small and each is < 20 lines.

import type { ReactNode } from 'react';

export function Card({ title, subtitle, right, children }: {
  title?: string; subtitle?: string; right?: ReactNode; children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-line bg-bg-card">
      {(title || right) && (
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold tracking-wide text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-faint">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'accent' }) {
  const toneClass = tone === 'ok'      ? 'text-ok'
                  : tone === 'warn'    ? 'text-warn'
                  : tone === 'danger'  ? 'text-danger'
                  : tone === 'accent'  ? 'text-accent'
                  : 'text-ink';
  return (
    <div className="rounded-md border border-line bg-bg-soft px-4 py-3">
      <div className="text-xs uppercase tracking-wider text-ink-faint">{label}</div>
      <div className={`mt-1 font-mono text-2xl ${toneClass}`}>{value}</div>
    </div>
  );
}

export function Badge({ tone = 'accent', children }: { tone?: 'ok' | 'warn' | 'danger' | 'accent' | 'neutral'; children: ReactNode }) {
  const t = tone === 'ok'      ? 'bg-ok-soft text-ok'
          : tone === 'warn'    ? 'bg-warn-soft text-warn'
          : tone === 'danger'  ? 'bg-danger-soft text-danger'
          : tone === 'neutral' ? 'bg-bg-soft text-ink-dim'
          :                      'bg-accent-soft text-accent';
  return <span className={`inline-flex items-center rounded px-2 py-0.5 font-mono text-xs ${t}`}>{children}</span>;
}

export function DecisionBadge({ decision }: { decision: string }) {
  const tone: 'ok' | 'warn' | 'danger' | 'neutral' =
    decision === 'ALLOW' || decision === 'EXECUTED' ? 'ok'
    : decision === 'REQUIRE_APPROVAL' ? 'warn'
    : decision === 'DENY' || decision === 'EXECUTION_FAILED' ? 'danger'
    : 'neutral';
  return <Badge tone={tone}>{decision}</Badge>;
}

export function Empty({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center rounded border border-dashed border-line bg-bg-soft py-10 text-sm text-ink-faint">
      {message}
    </div>
  );
}

export function ErrorBlock({ error }: { error: Error }) {
  return (
    <div className="rounded border border-danger/40 bg-danger-soft px-4 py-3 text-sm text-danger">
      <div className="font-semibold">Request failed</div>
      <div className="mt-1 font-mono text-xs">{error.message}</div>
      <div className="mt-2 text-xs text-ink-faint">
        Is the backend service running? Start it with{' '}
        <code className="rounded bg-bg-soft px-1 py-0.5">uvicorn …</code>
      </div>
    </div>
  );
}

export function Button({ tone = 'accent', children, ...rest }: { tone?: 'accent' | 'danger' | 'ok' | 'neutral'; children: ReactNode } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const t = tone === 'danger'  ? 'border-danger/40 bg-danger-soft text-danger hover:bg-danger/20'
          : tone === 'ok'      ? 'border-ok/40 bg-ok-soft text-ok hover:bg-ok/20'
          : tone === 'neutral' ? 'border-line bg-bg-soft text-ink-dim hover:bg-bg-card'
          :                      'border-accent/40 bg-accent-soft text-accent hover:bg-accent/20';
  return (
    <button
      {...rest}
      className={`rounded border px-3 py-1.5 font-mono text-xs transition disabled:cursor-not-allowed disabled:opacity-40 ${t} ${rest.className ?? ''}`}
    >
      {children}
    </button>
  );
}
