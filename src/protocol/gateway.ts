import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import { v4 as uuidv4 } from 'uuid';
import { PolicyEngine } from '../policy/engine.js';
import { SandboxManager } from '../sandbox/manager.js';
import { ApprovalManager } from '../audit/approvalManager.js';
import { AuditLogger } from '../audit/logger.js';
import { AuditLogEntry, ToolExecutionStatus } from '../audit/types.js';

export interface McpGatewayOptions {
  policyEngine: PolicyEngine;
  sandboxManager: SandboxManager;
  approvalManager: ApprovalManager;
  auditLogger: AuditLogger;
  upstreamClient?: Client;
  workspaceDir?: string;
}

export class McpGateway {
  private server: Server;
  private policyEngine: PolicyEngine;
  private sandboxManager: SandboxManager;
  private approvalManager: ApprovalManager;
  private auditLogger: AuditLogger;
  private upstreamClient?: Client;
  private workspaceDir: string;

  constructor(options: McpGatewayOptions) {
    this.policyEngine = options.policyEngine;
    this.sandboxManager = options.sandboxManager;
    this.approvalManager = options.approvalManager;
    this.auditLogger = options.auditLogger;
    this.upstreamClient = options.upstreamClient;
    this.workspaceDir = options.workspaceDir || process.cwd();

    this.server = new Server(
      {
        name: 'mcp-shield-gateway',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
  }

  public getServer(): Server {
    return this.server;
  }

  public setUpstreamClient(client: Client): void {
    this.upstreamClient = client;
  }

  private setupHandlers(): void {
    // 1. Handle tools/list
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      let tools: Array<{ name: string; description?: string; inputSchema: Record<string, unknown> }> = [];

      if (this.upstreamClient) {
        try {
          const upstreamRes = await this.upstreamClient.listTools();
          tools = (upstreamRes.tools || []).map((t) => {
            const evalResult = this.policyEngine.evaluate(t.name, {});
            let badge = '';
            if (evalResult.action === 'block') badge = ' [BLOCKED BY POLICY]';
            else if (evalResult.action === 'sandbox') badge = ' [SHIELD-SANDBOXED]';
            else if (evalResult.action === 'require_approval') badge = ' [REQUIRES APPROVAL]';

            return {
              name: t.name,
              description: `${t.description || ''}${badge}`,
              inputSchema: t.inputSchema as Record<string, unknown>,
            };
          });
        } catch (err) {
          console.error('Failed to query upstream tools:', err);
        }
      }

      // Add built-in shield management tools
      tools.push(
        {
          name: 'mcp_shield_get_status',
          description: 'Get current MCP-Shield security gateway status, active policy, and execution telemetry.',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'mcp_shield_get_metrics',
          description: 'Get aggregated security metrics: blocked attacks, sandboxed executions, and latency.',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        }
      );

      return { tools };
    });

    // 2. Handle tools/call
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const args = (request.params.arguments || {}) as Record<string, unknown>;
      const startTime = performance.now();
      const callId = uuidv4().slice(0, 8);

      // Check if it's a built-in shield tool
      if (toolName === 'mcp_shield_get_status') {
        const metrics = this.auditLogger.getMetrics();
        const policy = this.policyEngine.getPolicy();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  gateway: 'mcp-shield',
                  version: '1.0.0',
                  activePolicy: policy.name,
                  sandboxDriver: this.sandboxManager.getActiveDriverName(),
                  totalCallsIntercepted: metrics.totalRequests,
                  blockedAttacks: metrics.blockedCount,
                  sandboxedCalls: metrics.sandboxedCount,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      if (toolName === 'mcp_shield_get_metrics') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(this.auditLogger.getMetrics(), null, 2),
            },
          ],
        };
      }

      // Step 1: Policy Evaluation
      const evaluation = this.policyEngine.evaluate(toolName, args);

      // Step 2: Handle BLOCK action
      if (evaluation.action === 'block') {
        const latencyMs = performance.now() - startTime;
        const entry: AuditLogEntry = {
          id: callId,
          timestamp: new Date().toISOString(),
          toolName,
          args,
          action: 'block',
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          ruleId: evaluation.matchedRule?.id,
          reasons: evaluation.reasons,
          status: 'blocked',
          latencyMs,
          sandboxed: false,
          error: evaluation.reasons.join('; '),
        };
        this.auditLogger.record(entry);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `🚨 MCP-SHIELD SECURITY VIOLATION: Execution of '${toolName}' was BLOCKED.\nRule: ${evaluation.matchedRule?.name || 'DefaultGuard'}\nReasons:\n${evaluation.reasons.map((r) => `  - ${r}`).join('\n')}`,
            },
          ],
        };
      }

      // Step 3: Handle REQUIRE_APPROVAL action
      let approvedStatus: ToolExecutionStatus = 'allowed';
      if (evaluation.action === 'require_approval') {
        const approvalRes = await this.approvalManager.requestApproval(toolName, args, evaluation);

        if (!approvalRes.approved) {
          const latencyMs = performance.now() - startTime;
          const status: ToolExecutionStatus =
            approvalRes.note?.includes('timed out') ? 'timeout' : 'rejected';

          const entry: AuditLogEntry = {
            id: callId,
            timestamp: new Date().toISOString(),
            toolName,
            args,
            action: 'require_approval',
            riskLevel: evaluation.riskLevel,
            riskScore: evaluation.riskScore,
            ruleId: evaluation.matchedRule?.id,
            reasons: evaluation.reasons,
            status,
            latencyMs,
            sandboxed: false,
            error: approvalRes.note || 'Operator rejected execution.',
          };
          this.auditLogger.record(entry);

          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `🛑 MCP-SHIELD PERMISSION DENIED: Human operator rejected tool execution '${toolName}'.\nNote: ${approvalRes.note || 'No reason provided.'}`,
              },
            ],
          };
        }

        approvedStatus = 'approved';
      }

      // Step 4: Handle SANDBOX action
      if (evaluation.action === 'sandbox') {
        const policy = this.policyEngine.getPolicy();
        const sandboxRes = await this.sandboxManager.execute({
          toolName,
          args,
          workspaceDir: this.workspaceDir,
          timeoutMs: policy.sandbox.maxExecutionTimeMs,
          envWhitelist: policy.sandbox.envWhitelist,
          allowNetwork: policy.sandbox.allowNetwork,
          maxMemoryMb: policy.sandbox.maxMemoryMb,
        });

        const latencyMs = performance.now() - startTime;
        const entry: AuditLogEntry = {
          id: callId,
          timestamp: new Date().toISOString(),
          toolName,
          args,
          action: 'sandbox',
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          ruleId: evaluation.matchedRule?.id,
          reasons: evaluation.reasons,
          status: 'sandboxed',
          latencyMs,
          sandboxed: true,
          sandboxDriver: sandboxRes.driver,
          outputPreview: sandboxRes.stdout?.slice(0, 200),
          error: sandboxRes.error,
        };
        this.auditLogger.record(entry);

        if (!sandboxRes.success) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `[MCP-Shield Sandboxed Execution Failed in ${sandboxRes.driver}]\n${sandboxRes.error || sandboxRes.stderr || 'Non-zero exit code'}`,
              },
            ],
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: sandboxRes.stdout || '(Execution completed with no standard output)',
            },
          ],
        };
      }

      // Step 5: Handle ALLOW (pass through to upstream server)
      if (!this.upstreamClient) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `No upstream MCP server configured for tool '${toolName}'.`,
            },
          ],
        };
      }

      try {
        const upstreamResult = (await this.upstreamClient.callTool({
          name: toolName,
          arguments: args,
        })) as CallToolResult;

        const latencyMs = performance.now() - startTime;
        const entry: AuditLogEntry = {
          id: callId,
          timestamp: new Date().toISOString(),
          toolName,
          args,
          action: 'allow',
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          ruleId: evaluation.matchedRule?.id,
          reasons: evaluation.reasons,
          status: approvedStatus,
          latencyMs,
          sandboxed: false,
          outputPreview: typeof upstreamResult.content?.[0] === 'object' ? JSON.stringify(upstreamResult.content[0]).slice(0, 150) : '',
        };
        this.auditLogger.record(entry);

        return upstreamResult;
      } catch (err: unknown) {
        const latencyMs = performance.now() - startTime;
        const errorMsg = err instanceof Error ? err.message : String(err);
        const entry: AuditLogEntry = {
          id: callId,
          timestamp: new Date().toISOString(),
          toolName,
          args,
          action: 'allow',
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          ruleId: evaluation.matchedRule?.id,
          reasons: evaluation.reasons,
          status: 'error',
          latencyMs,
          sandboxed: false,
          error: errorMsg,
        };
        this.auditLogger.record(entry);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Upstream tool execution failed: ${errorMsg}`,
            },
          ],
        };
      }
    });
  }
}
