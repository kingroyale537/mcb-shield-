import http from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { PolicyEngine } from '../policy/engine.js';
import { SandboxManager } from '../sandbox/manager.js';
import { ApprovalManager } from '../audit/approvalManager.js';
import { AuditLogger } from '../audit/logger.js';
import { SecurityPolicy } from '../policy/types.js';

export interface WebServerOptions {
  port?: number;
  policyEngine: PolicyEngine;
  sandboxManager: SandboxManager;
  approvalManager: ApprovalManager;
  auditLogger: AuditLogger;
}

export class McpShieldWebServer {
  private server: http.Server;
  private wss: WebSocketServer;
  private port: number;
  private policyEngine: PolicyEngine;
  private sandboxManager: SandboxManager;
  private approvalManager: ApprovalManager;
  private auditLogger: AuditLogger;

  constructor(options: WebServerOptions) {
    this.port = options.port || 4200;
    this.policyEngine = options.policyEngine;
    this.sandboxManager = options.sandboxManager;
    this.approvalManager = options.approvalManager;
    this.auditLogger = options.auditLogger;

    this.server = http.createServer((req, res) => this.handleHttpRequest(req, res));
    this.wss = new WebSocketServer({ server: this.server, path: '/ws' });

    this.setupWebSockets();
    this.setupEventListeners();
  }

  public start(): Promise<number> {
    return new Promise((resolve) => {
      this.server.listen(this.port, () => {
        resolve(this.port);
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      this.wss.close(() => {
        this.server.close(() => resolve());
      });
    });
  }

  private setupWebSockets(): void {
    this.wss.on('connection', (ws: WebSocket) => {
      // Send initial snapshot
      const snapshot = {
        type: 'snapshot',
        policy: this.policyEngine.getPolicy(),
        metrics: this.auditLogger.getMetrics(),
        recentLogs: this.auditLogger.getRecentLogs(30),
        pendingApprovals: this.approvalManager.getPendingList(),
        sandboxStats: this.sandboxManager.getStats(),
      };
      ws.send(JSON.stringify(snapshot));

      ws.on('message', (message: string) => {
        try {
          const data = JSON.parse(message.toString());
          if (data.type === 'resolve_approval' && data.id) {
            this.approvalManager.resolveApproval(data.id, !!data.approved, data.note);
          }
        } catch {
          // Ignore malformed message
        }
      });
    });
  }

  private broadcast(data: Record<string, unknown>): void {
    const payload = JSON.stringify(data);
    for (const client of this.wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }

  private setupEventListeners(): void {
    this.auditLogger.on('log_entry', (entry) => {
      this.broadcast({
        type: 'log_entry',
        entry,
        metrics: this.auditLogger.getMetrics(),
      });
    });

    this.approvalManager.on('approval_requested', (item) => {
      this.broadcast({
        type: 'approval_requested',
        item,
      });
    });

    this.approvalManager.on('approval_resolved', (data) => {
      this.broadcast({
        type: 'approval_resolved',
        data,
        metrics: this.auditLogger.getMetrics(),
      });
    });
  }

  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // CORS headers for local dev
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // API Routes
    if (pathname === '/api/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'online',
          version: '1.0.0',
          sandboxDriver: this.sandboxManager.getActiveDriverName(),
          metrics: this.auditLogger.getMetrics(),
        })
      );
      return;
    }

    if (pathname === '/api/policy' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.policyEngine.getPolicy(), null, 2));
      return;
    }

    if (pathname === '/api/policy' && req.method === 'PUT') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body) as SecurityPolicy;
          this.policyEngine.updatePolicy(parsed);
          this.broadcast({ type: 'policy_updated', policy: parsed });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, policy: parsed }));
        } catch (err: unknown) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'Invalid JSON' }));
        }
      });
      return;
    }

    if (pathname === '/api/logs') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.auditLogger.getRecentLogs(100)));
      return;
    }

    if (pathname.startsWith('/api/approvals/') && pathname.endsWith('/decide') && req.method === 'POST') {
      const parts = pathname.split('/');
      const id = parts[3];
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          const { approved, note } = JSON.parse(body);
          const resolved = this.approvalManager.resolveApproval(id, !!approved, note);
          res.writeHead(resolved ? 200 : 404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: resolved }));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid payload' }));
        }
      });
      return;
    }

    // Serve Embedded Real-time Dashboard HTML
    if (pathname === '/' || pathname === '/dashboard') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(this.getDashboardHtml());
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }

  private getDashboardHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP-Shield // Real-time Observability & Security Gateway</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap');
    body { font-family: 'Inter', sans-serif; background-color: #0b0f17; }
    code, pre { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="text-slate-100 min-h-screen">
  <!-- Top Bar -->
  <header class="border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
    <div class="flex items-center gap-3">
      <div class="h-8 w-8 rounded-lg bg-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">
        🛡
      </div>
      <div>
        <div class="flex items-center gap-2">
          <h1 class="font-bold text-lg tracking-tight">MCP-Shield</h1>
          <span class="text-xs px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">Anthropic MCP Gateway</span>
        </div>
        <p class="text-xs text-slate-400">Hardened Sandboxing & Human-in-the-Loop Gateway</p>
      </div>
    </div>
    <div class="flex items-center gap-4">
      <div class="flex items-center gap-2 text-xs">
        <span class="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
        <span id="conn-status" class="text-emerald-400 font-medium">Connected (Live)</span>
      </div>
      <div class="text-xs px-3 py-1.5 rounded-md bg-slate-800 border border-slate-700 text-slate-300">
        Sandbox: <span id="sandbox-badge" class="font-mono text-cyan-400">detecting...</span>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
    <!-- Stat Cards -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400 font-medium">Total Intercepts</div>
        <div id="stat-total" class="text-2xl font-bold mt-1 text-slate-100">0</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-emerald-400 font-medium">Allowed</div>
        <div id="stat-allowed" class="text-2xl font-bold mt-1 text-emerald-400">0</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-cyan-400 font-medium">Sandboxed</div>
        <div id="stat-sandboxed" class="text-2xl font-bold mt-1 text-cyan-400">0</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-rose-400 font-medium">Blocked Attacks</div>
        <div id="stat-blocked" class="text-2xl font-bold mt-1 text-rose-400">0</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-indigo-400 font-medium">Avg Latency</div>
        <div id="stat-latency" class="text-2xl font-bold mt-1 text-indigo-300">0 ms</div>
      </div>
    </div>

    <!-- Approvals Banner (Hidden if no pending approvals) -->
    <div id="approvals-section" class="hidden bg-amber-500/10 border border-amber-500/30 rounded-xl p-5 space-y-3">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <span class="text-lg">⚠️</span>
          <h2 class="font-semibold text-amber-300">Human-in-the-Loop Approval Required</h2>
        </div>
        <span id="pending-count" class="text-xs bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded-full font-bold">1 Pending</span>
      </div>
      <div id="approvals-list" class="space-y-2"></div>
    </div>

    <!-- Main Grid: Live Feed + Active Policy -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Live Interception Stream (2 cols) -->
      <div class="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col h-[600px]">
        <div class="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
          <div class="flex items-center gap-2">
            <span class="h-2 w-2 rounded-full bg-cyan-400"></span>
            <h2 class="font-semibold text-sm">Live Tool Interception Stream</h2>
          </div>
          <span class="text-xs text-slate-500 font-mono">Real-time WebSocket feed</span>
        </div>
        <div id="logs-container" class="flex-1 overflow-y-auto space-y-2.5 pr-2 font-mono text-xs">
          <div class="text-slate-500 text-center py-10">Listening for MCP agent calls...</div>
        </div>
      </div>

      <!-- Policy Guardrails Inspector (1 col) -->
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col h-[600px]">
        <div class="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
          <h2 class="font-semibold text-sm">Active Guardrail Policy</h2>
          <span id="policy-name" class="text-xs font-mono text-indigo-400">Standard</span>
        </div>
        <div id="policy-container" class="flex-1 overflow-y-auto space-y-3 pr-2 text-xs">
          <div class="text-slate-500">Loading active security rules...</div>
        </div>
      </div>
    </div>
  </main>

  <script>
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
    const logsContainer = document.getElementById('logs-container');
    const approvalsSection = document.getElementById('approvals-section');
    const approvalsList = document.getElementById('approvals-list');
    let pendingApprovalsMap = new Map();

    ws.onopen = () => {
      document.getElementById('conn-status').textContent = 'Connected (Live)';
    };

    ws.onclose = () => {
      document.getElementById('conn-status').textContent = 'Disconnected';
      document.getElementById('conn-status').className = 'text-rose-400 font-medium';
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === 'snapshot') {
        updateMetrics(data.metrics);
        document.getElementById('sandbox-badge').textContent = data.sandboxStats.activeDriver || 'process';
        document.getElementById('policy-name').textContent = data.policy.name;
        renderPolicy(data.policy);
        
        logsContainer.innerHTML = '';
        data.recentLogs.forEach(entry => appendLog(entry));

        data.pendingApprovals.forEach(app => pendingApprovalsMap.set(app.id, app));
        renderApprovals();
      }

      if (data.type === 'log_entry') {
        appendLog(data.entry);
        updateMetrics(data.metrics);
      }

      if (data.type === 'approval_requested') {
        pendingApprovalsMap.set(data.item.id, data.item);
        renderApprovals();
      }

      if (data.type === 'approval_resolved') {
        pendingApprovalsMap.delete(data.data.id);
        renderApprovals();
        if (data.metrics) updateMetrics(data.metrics);
      }
    };

    function updateMetrics(m) {
      if (!m) return;
      document.getElementById('stat-total').textContent = m.totalRequests;
      document.getElementById('stat-allowed').textContent = m.allowedCount;
      document.getElementById('stat-sandboxed').textContent = m.sandboxedCount;
      document.getElementById('stat-blocked').textContent = m.blockedCount;
      document.getElementById('stat-latency').textContent = m.avgLatencyMs + ' ms';
    }

    function appendLog(log) {
      const emptyState = logsContainer.querySelector('.text-slate-500.text-center');
      if (emptyState) emptyState.remove();

      const item = document.createElement('div');
      item.className = 'p-3 rounded-lg border bg-slate-950/60 ' + getBorderColor(log.status);

      const time = new Date(log.timestamp).toLocaleTimeString();
      const statusBadge = getStatusBadgeHtml(log.status);
      const riskBadge = getRiskBadgeHtml(log.riskLevel, log.riskScore);

      item.innerHTML = \`
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="text-slate-400">\${time}</span>
            \${statusBadge}
            <span class="font-bold text-slate-100">\${escapeHtml(log.toolName)}</span>
          </div>
          <div class="flex items-center gap-2">
            \${riskBadge}
            <span class="text-slate-400 text-[11px]">\${log.latencyMs.toFixed(1)}ms</span>
          </div>
        </div>
        <div class="mt-2 text-slate-300 text-[11px] overflow-x-auto bg-slate-900/80 p-2 rounded border border-slate-800">
          \${escapeHtml(JSON.stringify(log.args))}
        </div>
        \${log.error ? \`<div class="mt-1.5 text-rose-400 text-[11px]">⚠️ \${escapeHtml(log.error)}</div>\` : ''}
        \${log.sandboxed ? \`<div class="mt-1 text-cyan-400 text-[11px]">🛡 Isolated in \${log.sandboxDriver || 'sandbox'}</div>\` : ''}
      \`;

      logsContainer.insertBefore(item, logsContainer.firstChild);
    }

    function renderApprovals() {
      if (pendingApprovalsMap.size === 0) {
        approvalsSection.classList.add('hidden');
        return;
      }
      approvalsSection.classList.remove('hidden');
      document.getElementById('pending-count').textContent = \`\${pendingApprovalsMap.size} Pending\`;
      approvalsList.innerHTML = '';

      pendingApprovalsMap.forEach(app => {
        const row = document.createElement('div');
        row.className = 'bg-slate-900/90 border border-amber-500/40 rounded-lg p-3 flex items-center justify-between gap-4';
        row.innerHTML = \`
          <div>
            <div class="flex items-center gap-2 font-mono text-xs">
              <span class="text-amber-400 font-bold">\${escapeHtml(app.toolName)}</span>
              <span class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">Risk: \${app.riskScore}</span>
            </div>
            <div class="text-xs text-slate-300 mt-1 font-mono">\${escapeHtml(JSON.stringify(app.args))}</div>
            <div class="text-[11px] text-slate-400 mt-0.5">\${app.reasons.join(', ')}</div>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="resolveApproval('\${app.id}', true)" class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded text-xs transition">Approve</button>
            <button onclick="resolveApproval('\${app.id}', false)" class="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-medium rounded text-xs transition">Reject</button>
          </div>
        \`;
        approvalsList.appendChild(row);
      });
    }

    function resolveApproval(id, approved) {
      ws.send(JSON.stringify({ type: 'resolve_approval', id, approved }));
    }

    function renderPolicy(policy) {
      const container = document.getElementById('policy-container');
      container.innerHTML = '';
      (policy.rules || []).forEach(rule => {
        const card = document.createElement('div');
        card.className = 'p-3 rounded-lg bg-slate-950/40 border border-slate-800 space-y-1.5';
        card.innerHTML = \`
          <div class="flex items-center justify-between">
            <span class="font-semibold text-slate-200">\${escapeHtml(rule.name)}</span>
            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase \${getActionClass(rule.action)}">\${rule.action}</span>
          </div>
          <div class="text-[11px] text-slate-400 font-mono">Pattern: \${escapeHtml(rule.toolPattern)}</div>
          <div class="text-[11px] text-slate-500">\${escapeHtml(rule.description || '')}</div>
        \`;
        container.appendChild(card);
      });
    }

    function getActionClass(action) {
      switch (action) {
        case 'allow': return 'bg-emerald-500/20 text-emerald-400';
        case 'block': return 'bg-rose-500/20 text-rose-400';
        case 'sandbox': return 'bg-cyan-500/20 text-cyan-400';
        case 'require_approval': return 'bg-amber-500/20 text-amber-300';
        default: return 'bg-slate-700 text-slate-300';
      }
    }

    function getBorderColor(status) {
      switch (status) {
        case 'allowed': return 'border-emerald-500/30';
        case 'sandboxed': return 'border-cyan-500/30';
        case 'blocked': return 'border-rose-500/40';
        case 'approved': return 'border-emerald-400/50';
        case 'rejected': return 'border-rose-600/50';
        default: return 'border-slate-800';
      }
    }

    function getStatusBadgeHtml(status) {
      switch (status) {
        case 'allowed': return '<span class="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">ALLOWED</span>';
        case 'sandboxed': return '<span class="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold">SANDBOXED</span>';
        case 'blocked': return '<span class="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold">BLOCKED</span>';
        case 'approved': return '<span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">APPROVED</span>';
        case 'rejected': return '<span class="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">REJECTED</span>';
        default: return '<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-bold">' + status.toUpperCase() + '</span>';
      }
    }

    function getRiskBadgeHtml(level, score) {
      if (level === 'critical') return \`<span class="px-1.5 py-0.5 rounded bg-rose-600 text-white font-bold text-[10px]">CRITICAL \${score}</span>\`;
      if (level === 'high') return \`<span class="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 text-[10px]">High \${score}</span>\`;
      if (level === 'medium') return \`<span class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">Med \${score}</span>\`;
      return \`<span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px]">Low \${score}</span>\`;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/[&<>"']/g, m => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[m]);
    }
  </script>
</body>
</html>`;
  }
}
