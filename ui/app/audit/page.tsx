'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { api } from '@/lib/api';
import { Card, Empty, ErrorBlock, DecisionBadge, Button, Badge } from '@/components/ui';
import type { AuditEvent, ChainVerifyResult } from '@/lib/types';

function AuditInner() {
  const sp = useSearchParams();
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [agentId, setAgentId] = useState(sp.get('agent_id') ?? '');
  const [decision, setDecision] = useState(sp.get('decision') ?? '');
  const [verify, setVerify] = useState<ChainVerifyResult | null>(null);

  const load = async () => {
    try {
      setEvents(await api.listEvents({ agent_id: agentId, decision, limit: 50 }));
      setError(null);
    } catch (e) { setError(e as Error); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const runVerify = async () => {
    if (!agentId) return;
    try {
      setVerify(await api.verifyChain(agentId));
    } catch (e) { setError(e as Error); }
  };

  return (
    <div className="space-y-6">
      {error && <ErrorBlock error={error} />}

      <Card title="Filters">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={agentId}
            onChange={e => setAgentId(e.target.value)}
            placeholder="agent_id (optional)"
            className="rounded border border-line bg-bg-soft px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
          />
          <select
            value={decision}
            onChange={e => setDecision(e.target.value)}
            className="rounded border border-line bg-bg-soft px-3 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none"
          >
            <option value="">any decision</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="EXECUTED">EXECUTED</option>
            <option value="EXECUTION_FAILED">EXECUTION_FAILED</option>
          </select>
          <Button onClick={load}>Search</Button>
          <Button tone="neutral" onClick={runVerify} disabled={!agentId}>
            Verify chain
          </Button>
          {verify && (
            <Badge tone={verify.valid ? 'ok' : 'danger'}>
              chain: {verify.valid ? 'intact' : 'BROKEN'} ({verify.event_count} events)
            </Badge>
          )}
        </div>
      </Card>

      <Card title={`Audit Events (${events?.length ?? 0})`}>
        {!events || events.length === 0 ? (
          <Empty message="No events match the filter" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="border-b border-line text-left text-ink-faint">
                <tr>
                  <th className="px-2 py-2 font-normal">Time</th>
                  <th className="px-2 py-2 font-normal">Agent</th>
                  <th className="px-2 py-2 font-normal">Action</th>
                  <th className="px-2 py-2 font-normal">Resource</th>
                  <th className="px-2 py-2 font-normal">Decision</th>
                  <th className="px-2 py-2 font-normal">Hash</th>
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <tr key={e.event_id} className="border-b border-line/40 hover:bg-bg-soft">
                    <td className="px-2 py-2 font-mono text-ink-dim">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="px-2 py-2 font-mono">{e.agent_id}</td>
                    <td className="px-2 py-2 font-mono">{e.action}</td>
                    <td className="px-2 py-2 font-mono text-ink-dim" title={e.resource_arn}>
                      {e.resource_arn.length > 40 ? `…${e.resource_arn.slice(-40)}` : e.resource_arn}
                    </td>
                    <td className="px-2 py-2"><DecisionBadge decision={e.decision} /></td>
                    <td className="px-2 py-2 font-mono text-ink-faint" title={e.event_hash}>
                      {e.event_hash.slice(0, 12)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

export default function AuditPage() {
  return (
    <Suspense fallback={<div className="text-ink-faint">Loading…</div>}>
      <AuditInner />
    </Suspense>
  );
}
