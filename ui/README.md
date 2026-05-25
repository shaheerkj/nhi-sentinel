# NHI-Sentinel Console

Operator UI for the NHI-Sentinel governance platform. Lives alongside Grafana — Grafana shows metric timeseries; this console is for *acting* on the system (approving requests, suspending identities, verifying audit chains).

## Stack

- Next.js 15 (App Router) + React 19
- TypeScript, strict mode
- Tailwind CSS (dark theme, single config file)
- Pure `fetch` — no client-state library, no axios

## Pages

| Route          | What it does                                                            |
|----------------|-------------------------------------------------------------------------|
| `/`            | Overview: suspended count, critical anomalies, recent events            |
| `/identities`  | Suspended NHI inventory; manual suspend + reinstate                     |
| `/audit`       | Filterable audit log; on-demand `verify_chain` per agent                |
| `/anomaly`     | Live per-agent anomaly scores, refreshed every 3s; one-click suspend   |
| `/approvals`   | Pending approval queue; approve/deny with self-approval guard           |

## Running

```bash
cd ui
npm install
cp .env.example .env.local       # adjust ports if needed
npm run dev                       # http://localhost:3001
```

The four backend services must be running for the UI to have anything to show:

```bash
# in separate terminals from the repo root
uvicorn anomaly.service:app   --port 8000
uvicorn audit.api:app         --port 8001
uvicorn identity.api:app      --port 8002
uvicorn approval.api:app      --port 8003
```

All browser calls go through `/api/{audit,identity,anomaly,approval}/*`, which the Next dev server rewrites to the corresponding service. This sidesteps CORS in development and lets the production deployment sit behind a single reverse proxy.

## Why a custom UI when Grafana exists

Grafana is good at *timeseries* — anomaly score trends, action rates over time, deny percentages. It is not good at:

- **Acting** on the system. You cannot click a Grafana panel to suspend an identity.
- **Reading audit detail.** Audit records have a per-record hash chain; verifying integrity needs a button, not a graph.
- **Approval workflows.** Approvers need a queue with approve/deny controls, not a histogram of queue depth.

This console fills those gaps. Use both — they are complementary, not redundant.
