import chalk from 'chalk';
import { DEFAULT_SECURITY_POLICY } from '../src/policy/defaultPolicy.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { SandboxManager } from '../src/sandbox/manager.js';
import { ApprovalManager } from '../src/audit/approvalManager.js';
import { AuditLogger } from '../src/audit/logger.js';
import { McpGateway } from '../src/protocol/gateway.js';
import { McpShieldWebServer } from '../src/server/webServer.js';

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runDemo() {
  console.log(chalk.bold.cyan('\n============================================================='));
  console.log(chalk.bold.cyan('       🛡️  MCP-SHIELD: LIVE SECURITY GATEWAY DEMO            '));
  console.log(chalk.bold.cyan('   Hardened Sandboxing & Guardrails for Anthropic MCP        '));
  console.log(chalk.bold.cyan('=============================================================\n'));

  // 1. Initialize Core
  const policyEngine = new PolicyEngine(DEFAULT_SECURITY_POLICY);
  const sandboxManager = new SandboxManager('process');
  await sandboxManager.initialize();
  const approvalManager = new ApprovalManager(15000);
  const auditLogger = new AuditLogger(100, true);

  // 2. Start Dashboard
  const webServer = new McpShieldWebServer({
    port: 4200,
    policyEngine,
    sandboxManager,
    approvalManager,
    auditLogger,
  });

  const port = await webServer.start();
  console.log(chalk.green(`✓ Real-time Observability Dashboard running at: ${chalk.underline.bold(`http://localhost:${port}`)}\n`));

  // 3. Create Mock Upstream MCP Client for demo
  const mockUpstreamClient: any = {
    listTools: async () => ({
      tools: [
        { name: 'read_file', description: 'Read a file from workspace', inputSchema: {} },
        { name: 'write_file', description: 'Write a file to workspace', inputSchema: {} },
        { name: 'http_fetch', description: 'Fetch external URL', inputSchema: {} },
      ],
    }),
    callTool: async ({ name, arguments: args }: any) => {
      if (name === 'read_file') {
        return {
          content: [{ type: 'text', text: '# MCP-Shield Documentation\nWelcome to secure agent tooling.' }],
        };
      }
      if (name === 'http_fetch') {
        return {
          content: [{ type: 'text', text: '{"status": 200, "message": "Successfully fetched external payload"}' }],
        };
      }
      return { content: [{ type: 'text', text: 'OK' }] };
    },
  };

  // 4. Create Gateway
  const gateway = new McpGateway({
    policyEngine,
    sandboxManager,
    approvalManager,
    auditLogger,
    upstreamClient: mockUpstreamClient,
  });

  const server = gateway.getServer();

  console.log(chalk.yellow('🤖 Simulating Autonomous Agent Tool Invocations...\n'));
  await sleep(1000);

  async function callTool(name: string, args: Record<string, unknown>) {
    console.log(chalk.dim(`--- Invocating tool: ${name} ---`));
    const requestHandler = (server as any)._requestHandlers.get('tools/call');
    if (!requestHandler) throw new Error('No tools/call handler registered');

    const result = await requestHandler({
      method: 'tools/call',
      params: { name, arguments: args },
    });

    return result;
  }

  // --- Scenario 1: Harmless Read Operation ---
  console.log(chalk.white.bold('\n[Test 1] Agent requests safe file read'));
  const res1 = await callTool('read_file', { path: 'README.md' });
  console.log(chalk.gray(`Result: ${res1.content[0].text.slice(0, 50)}...\n`));
  await sleep(1000);

  // --- Scenario 2: Catastrophic Command Injection ---
  console.log(chalk.white.bold('[Test 2] Adversarial Prompt Injection attempts destructive system command'));
  const res2 = await callTool('execute_command', { command: 'rm -rf /' });
  console.log(chalk.gray(`Result: ${res2.content[0].text}\n`));
  await sleep(1000);

  // --- Scenario 3: Secret & SSH Key Exfiltration ---
  console.log(chalk.white.bold('[Test 3] Jailbroken Agent attempts reading private SSH credentials'));
  const res3 = await callTool('read_file', { path: '~/.ssh/id_rsa' });
  console.log(chalk.gray(`Result: ${res3.content[0].text}\n`));
  await sleep(1000);

  // --- Scenario 4: Path Traversal Attack on Sensitive Files ---
  console.log(chalk.white.bold('[Test 4] Directory traversal attack targeting /etc/shadow'));
  const res4 = await callTool('write_file', { path: '../../etc/shadow', content: 'hacked::0:0:::' });
  console.log(chalk.gray(`Result: ${res4.content[0].text}\n`));
  await sleep(1000);

  // --- Scenario 5: Sandboxed Shell Execution ---
  console.log(chalk.white.bold('[Test 5] Agent runs arbitrary shell command (isolated in sandbox with scrubbed env)'));
  const res5 = await callTool('run_terminal_command', {
    command: "echo 'Isolated Sandbox Active!' && uname -sm && whoami && date",
  });
  console.log(chalk.cyan(`Result: \n${res5.content[0].text}\n`));
  await sleep(1000);

  // --- Scenario 6: Human-in-the-Loop Approval Workflow ---
  console.log(chalk.white.bold('[Test 6] Agent triggers external network fetch (Escalated to Human-in-the-Loop)'));

  setTimeout(() => {
    const pending = approvalManager.getPendingList();
    if (pending.length > 0) {
      console.log(chalk.green(`\n[Operator Action] Human operator approves pending request #${pending[0].id} via Dashboard!\n`));
      approvalManager.resolveApproval(pending[0].id, true, 'Approved by security auditor');
    }
  }, 1200);

  const res6 = await callTool('http_fetch', { url: 'https://api.github.com/repos/anthropics/anthropic-sdk-python' });
  console.log(chalk.gray(`Result: ${res6.content[0].text}\n`));
  await sleep(1000);

  // --- Final Metrics Summary ---
  const metrics = auditLogger.getMetrics();
  console.log(chalk.bold.green('============================================================='));
  console.log(chalk.bold.green('              SECURITY TELEMETRY SUMMARY                     '));
  console.log(chalk.bold.green('============================================================='));
  console.log(`  Total Tool Interceptions : ${chalk.bold(metrics.totalRequests)}`);
  console.log(`  Allowed Operations       : ${chalk.green.bold(metrics.allowedCount)}`);
  console.log(`  Sandboxed Executions     : ${chalk.cyan.bold(metrics.sandboxedCount)}`);
  console.log(`  Blocked Attacks          : ${chalk.red.bold(metrics.blockedCount)}`);
  console.log(`  Approved by Human        : ${chalk.greenBright.bold(metrics.approvedCount)}`);
  console.log(`  Average Gateway Latency  : ${metrics.avgLatencyMs}ms`);
  console.log(chalk.bold.green('=============================================================\n'));

  console.log(chalk.gray('Demo completed successfully. Clean shutdown.'));
  await webServer.stop();
}

runDemo().catch((err) => {
  console.error(chalk.red('Demo encountered an error:'), err);
  process.exit(1);
});
