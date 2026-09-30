import { describe, it, expect } from 'vitest';
import { McpGateway } from '../src/protocol/gateway.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { SandboxManager } from '../src/sandbox/manager.js';
import { ApprovalManager } from '../src/audit/approvalManager.js';
import { AuditLogger } from '../src/audit/logger.js';
import { DEFAULT_SECURITY_POLICY } from '../src/policy/defaultPolicy.js';

describe('McpGateway Protocol Interception', () => {
  const policyEngine = new PolicyEngine(DEFAULT_SECURITY_POLICY);
  const sandboxManager = new SandboxManager('process');
  const approvalManager = new ApprovalManager(5000);
  const auditLogger = new AuditLogger(50, false);

  const gateway = new McpGateway({
    policyEngine,
    sandboxManager,
    approvalManager,
    auditLogger,
  });

  const server = gateway.getServer();

  it('exposes built-in management tools in listTools', async () => {
    const listHandler = (server as any)._requestHandlers.get('tools/list');
    expect(listHandler).toBeDefined();

    const result = await listHandler({ method: 'tools/list', params: {} });
    expect(result.tools).toBeDefined();
    const toolNames = result.tools.map((t: any) => t.name);
    expect(toolNames).toContain('mcp_shield_get_status');
    expect(toolNames).toContain('mcp_shield_get_metrics');
  });

  it('intercepts and blocks prohibited tool call with an informative security message', async () => {
    const callHandler = (server as any)._requestHandlers.get('tools/call');

    const result = await callHandler({
      method: 'tools/call',
      params: {
        name: 'execute_command',
        arguments: { command: 'rm -rf /' },
      },
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('MCP-SHIELD SECURITY VIOLATION');
    expect(result.content[0].text).toContain('destructive system command');
  });

  it('routes shell tools to sandbox and returns isolated output', async () => {
    const callHandler = (server as any)._requestHandlers.get('tools/call');

    const result = await callHandler({
      method: 'tools/call',
      params: {
        name: 'run_terminal_command',
        arguments: { command: 'echo "gateway-sandboxed-ok"' },
      },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBe('gateway-sandboxed-ok');
  });

  it('handles built-in mcp_shield_get_status tool execution', async () => {
    const callHandler = (server as any)._requestHandlers.get('tools/call');

    const result = await callHandler({
      method: 'tools/call',
      params: {
        name: 'mcp_shield_get_status',
        arguments: {},
      },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.gateway).toBe('mcp-shield');
    expect(parsed.version).toBe('1.0.0');
    expect(parsed.activePolicy).toBe(DEFAULT_SECURITY_POLICY.name);
  });
});
