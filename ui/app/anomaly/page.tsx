'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card, Empty, ErrorBlock, Badge, Button } from '@/components/ui';
import type { AnomalyScores } from '@/lib/types';

export default function AnomalyPage() {
  const [scores, setScores] = useState<AnomalyScores | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = async () => {
    try {
      setScores(await api.anomalyScores());
      setError(null);
    } catch (e) { setError(e as Error); }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  const suspend = async (agent: string, score: number) => {
    setBusy(agent);
    try {
      await api.suspendIdentity(agent, `Manual: anomaly score ${score.toFixed(3)}`);
      await load();
    } catch (e) { setError(e as Error); }
    finally { setBusy(null); }
  };

  const entries = scores
    ? Object.entries(scores.scores).sort(([, a], [, b]) => b - a)
    : [];

  return (
    <div className="space-y-6">
      {error && <ErrorBlock error={error} />}

      <Card
        title="Live Anomaly Scores"
        subtitle="IsolationForest output, refreshed every 3 seconds"
        right={
          scores && (
            <div className="font-mono text-xs text-ink-faint">
              {scores.events_scored} events scored
            </div>
          )
        }
      >
        {entries.length === 0 ? (
          <Empty message="No scores yet — the anomaly service hasn't received any events" />
        ) : (
          <ul className="space-y-2">
            {entries.map(([agent, score]) => {
              const isSuspended = scores!.suspended.includes(agent);
              const tier = score > 0.95 ? 'critical' : score > 0.85 ? 'high' : score > 0.70 ? 'elevated' : 'normal';
              return (
                <li key={agent} className="rounded border border-line bg-bg-soft p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm text-ink">{agent}</span>
                      {isSuspended && <Badge tone="danger">SUSPENDED</Badge>}
                      <TierBadge tier={tier} />
                    </div>
                    <div className="flex items-center gap-3">
                      <ScoreBar value={score} />
                      <span className="w-14 text-right font-mono text-sm tabular-nums">{score.toFixed(4)}</span>
                      {!isSuspended && score > 0.7 && (
                        <Button
                          tone="danger"
                          onClick={() => suspend(agent, score)}
                          disabled={busy === agent}
                        >
                          {busy === agent ? '…' : 'Suspend'}
                        </Button>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card title="Score Tiers">
        <div className="grid grid-cols-1 gap-2 text-xs md:grid-cols-4">
          <Legend tier="normal"   range="0.00 – 0.70"   action="log only" />
          <Legend tier="elevated" range="0.70 – 0.85"   action="Grafana alert" />
          <Legend tier="high"     range="0.85 – 0.95"   action="critical alert + Slack/ntfy" />
          <Legend tier="critical" range="0.95 – 1.00"   action="auto-suspend identity" />
        </div>
      </Card>
    </div>
  );
}

function TierBadge({ tier }: { tier: string }) {
  const tone = tier === 'critical' ? 'danger' : tier === 'high' ? 'warn' : tier === 'elevated' ? 'accent' : 'neutral';
  return <Badge tone={tone as 'danger' | 'warn' | 'accent' | 'neutral'}>{tier}</Badge>;
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const color = value > 0.95 ? 'bg-danger' : value > 0.85 ? 'bg-warn' : value > 0.7 ? 'bg-accent' : 'bg-ok';
  return (
    <div className="h-2 w-48 overflow-hidden rounded bg-bg-card">
      <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function Legend({ tier, range, action }: { tier: string; range: string; action: string }) {
  return (
    <div className="rounded border border-line bg-bg-soft px-3 py-2">
      <TierBadge tier={tier} />
      <div className="mt-1 font-mono text-ink">{range}</div>
      <div className="text-ink-faint">{action}</div>
    </div>
  );
}
