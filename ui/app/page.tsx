'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card, Stat, Empty, ErrorBlock, DecisionBadge, Badge } from '@/components/ui';
import type { AnomalyScores, AuditEvent, SuspendedList } from '@/lib/types';
import Link from 'next/link';

export default function Overview() {
  const [scores, setScores] = useState<AnomalyScores | null>(null);
  const [suspended, setSuspended] = useState<SuspendedList | null>(null);
  const [recent, setRecent] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [s, sus, ev] = await Promise.all([
          api.anomalyScores().catch(() => null),
          api.listSuspended().catch(() => null),
          api.listEvents({ limit: 8 }).catch(() => null),
        ]);
        if (!alive) return;
        setScores(s);
        setSuspended(sus);
        setRecent(ev);
        setError(null);
      } catch (e) {
        if (alive) setError(e as Error);
      }
    };
    load();
    const id = setInterval(load, 5000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const denyCount = recent?.filter(e => e.decision === 'DENY').length ?? 0;
  const criticalAnomalies = scores
    ? Object.values(scores.scores).filter(v => v > 0.95).length
    : 0;

  return (
    <div className="space-y-6">
      {error && <ErrorBlock error={error} />}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Stat
          label="Suspended NHIs"
          value={suspended?.count ?? '—'}
          tone={suspended && suspended.count > 0 ? 'danger' : 'ok'}
        />
        <Stat
          label="Critical Anomalies (>0.95)"
          value={criticalAnomalies}
          tone={criticalAnomalies > 0 ? 'danger' : 'ok'}
        />
        <Stat
          label="Events Scored"
          value={scores?.events_scored ?? '—'}
          tone="accent"
        />
        <Stat
          label="Recent DENYs"
          value={denyCount}
          tone={denyCount > 0 ? 'warn' : 'ok'}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="Anomaly Scores" subtitle="Per-agent IsolationForest output (0=normal, 1=anomalous)">
          {!scores || Object.keys(scores.scores).length === 0 ? (
            <Empty message="No agents scored yet — start sending events to the anomaly service" />
          ) : (
            <ul className="space-y-2 font-mono text-sm">
              {Object.entries(scores.scores)
                .sort(([, a], [, b]) => b - a)
                .map(([agent, score]) => (
                  <li key={agent} className="flex items-center justify-between rounded border border-line bg-bg-soft px-3 py-2">
                    <Link href={`/audit?agent_id=${encodeURIComponent(agent)}`} className="hover:text-accent">
                      {agent}
                    </Link>
                    <div className="flex items-center gap-3">
                      <ScoreBar value={score} />
                      <span className="w-12 text-right tabular-nums">{score.toFixed(3)}</span>
                    </div>
                  </li>
                ))}
            </ul>
          )}
        </Card>

        <Card title="Recent Audit Events" subtitle="Latest 8 events across all agents">
          {!recent || recent.length === 0 ? (
            <Empty message="No audit events yet" />
          ) : (
            <ul className="space-y-2">
              {recent.map(e => (
                <li key={e.event_id} className="rounded border border-line bg-bg-soft px-3 py-2 text-xs">
                  <div className="flex items-center justify-between">
                    <div className="font-mono text-ink">{e.action}</div>
                    <DecisionBadge decision={e.decision} />
                  </div>
                  <div className="mt-1 flex items-center justify-between text-ink-faint">
                    <span className="font-mono">{e.agent_id}</span>
                    <span>{new Date(e.timestamp).toLocaleTimeString()}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {suspended && suspended.count > 0 && (
        <Card title="Currently Suspended" subtitle="These identities cannot perform any action — PEP blocks them before OPA">
          <div className="flex flex-wrap gap-2">
            {suspended.agents.map(a => (
              <Link key={a} href={`/identities`}>
                <Badge tone="danger">{a}</Badge>
              </Link>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const color = value > 0.95 ? 'bg-danger' : value > 0.85 ? 'bg-warn' : 'bg-ok';
  return (
    <div className="h-1.5 w-32 overflow-hidden rounded bg-bg-card">
      <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}
