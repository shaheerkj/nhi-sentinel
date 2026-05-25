'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card, Empty, ErrorBlock, Button, Badge } from '@/components/ui';
import type { ApprovalRequest } from '@/lib/types';

export default function ApprovalsPage() {
  const [items, setItems] = useState<ApprovalRequest[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [approver, setApprover] = useState('operator');

  const load = async () => {
    try {
      setItems(await api.listApprovals());
      setError(null);
    } catch (e) { setError(e as Error); }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const resolve = async (id: string, action: 'approve' | 'deny', agentId: string) => {
    if (approver === agentId) {
      setError(new Error('Self-approval is blocked at the policy layer — pick a different approver'));
      return;
    }
    setBusy(id);
    try {
      await api.resolveApproval(id, action, approver);
      await load();
    } catch (e) { setError(e as Error); }
    finally { setBusy(null); }
  };

  return (
    <div className="space-y-6">
      {error && <ErrorBlock error={error} />}

      <Card title="Approver Identity" subtitle="Set the identity you are approving as. Self-approval is rejected.">
        <input
          value={approver}
          onChange={e => setApprover(e.target.value)}
          className="w-full max-w-sm rounded border border-line bg-bg-soft px-3 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none"
        />
      </Card>

      <Card
        title={`Pending Approvals (${items?.length ?? 0})`}
        subtitle="Actions that triggered REQUIRE_APPROVAL — typically destructive ops and IAM writes"
      >
        {!items || items.length === 0 ? (
          <Empty message="Queue is empty" />
        ) : (
          <ul className="space-y-3">
            {items.map(req => (
              <li key={req.request_id} className="rounded border border-line bg-bg-soft p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1 space-y-1.5 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="warn">{req.status}</Badge>
                      <span className="font-mono text-ink">{req.action}</span>
                      {req.risk_level && <Badge tone="danger">{req.risk_level}</Badge>}
                    </div>
                    <div className="font-mono text-xs text-ink-dim">
                      <div><span className="text-ink-faint">agent:</span> {req.agent_id}</div>
                      <div><span className="text-ink-faint">resource:</span> {req.resource_arn}</div>
                      <div><span className="text-ink-faint">task:</span> {req.task_id}</div>
                      <div><span className="text-ink-faint">policy:</span> {req.policy_ref}</div>
                    </div>
                    <div className="text-xs text-ink-faint">
                      requested {new Date(req.requested_at).toLocaleString()} ·
                      expires {new Date(req.expires_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex flex-col gap-2">
                    <Button
                      tone="ok"
                      disabled={busy === req.request_id}
                      onClick={() => resolve(req.request_id, 'approve', req.agent_id)}
                    >
                      Approve
                    </Button>
                    <Button
                      tone="danger"
                      disabled={busy === req.request_id}
                      onClick={() => resolve(req.request_id, 'deny', req.agent_id)}
                    >
                      Deny
                    </Button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
