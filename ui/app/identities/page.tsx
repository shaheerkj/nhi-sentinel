'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card, Empty, ErrorBlock, Badge, Button } from '@/components/ui';
import type { SuspendedList } from '@/lib/types';

export default function IdentitiesPage() {
  const [suspended, setSuspended] = useState<SuspendedList | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [newAgent, setNewAgent] = useState('');
  const [newReason, setNewReason] = useState('');

  const refresh = async () => {
    try {
      setSuspended(await api.listSuspended());
      setError(null);
    } catch (e) { setError(e as Error); }
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);

  const reinstate = async (agent: string) => {
    setBusy(agent);
    try {
      await api.unsuspendIdentity(agent);
      await refresh();
    } catch (e) { setError(e as Error); }
    finally { setBusy(null); }
  };

  const suspend = async () => {
    if (!newAgent || !newReason) return;
    setBusy('__new');
    try {
      await api.suspendIdentity(newAgent, newReason);
      setNewAgent('');
      setNewReason('');
      await refresh();
    } catch (e) { setError(e as Error); }
    finally { setBusy(null); }
  };

  return (
    <div className="space-y-6">
      {error && <ErrorBlock error={error} />}

      <Card
        title="Manual Suspension"
        subtitle="Used for incident response — the anomaly service does this automatically on score >0.95 or burst detection"
      >
        <div className="flex gap-2">
          <input
            value={newAgent}
            onChange={e => setNewAgent(e.target.value)}
            placeholder="agent-data-001"
            className="flex-1 rounded border border-line bg-bg-soft px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
          />
          <input
            value={newReason}
            onChange={e => setNewReason(e.target.value)}
            placeholder="Reason (free text)"
            className="flex-[2] rounded border border-line bg-bg-soft px-3 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
          />
          <Button
            tone="danger"
            onClick={suspend}
            disabled={!newAgent || !newReason || busy === '__new'}
          >
            {busy === '__new' ? 'suspending…' : 'Suspend'}
          </Button>
        </div>
      </Card>

      <Card
        title="Suspended Identities"
        subtitle={
          suspended
            ? `${suspended.count} suspended — PEP will DENY before consulting OPA`
            : 'loading…'
        }
      >
        {!suspended || suspended.count === 0 ? (
          <Empty message="No identities are suspended" />
        ) : (
          <ul className="space-y-2">
            {suspended.agents.map(a => (
              <li key={a} className="flex items-center justify-between rounded border border-line bg-bg-soft px-3 py-2">
                <div className="flex items-center gap-3">
                  <Badge tone="danger">SUSPENDED</Badge>
                  <span className="font-mono text-sm">{a}</span>
                </div>
                <Button tone="ok" onClick={() => reinstate(a)} disabled={busy === a}>
                  {busy === a ? 'reinstating…' : 'Reinstate'}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
