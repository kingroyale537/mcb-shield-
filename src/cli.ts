#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'node:fs/promises';
import path from 'node:path';
import chalk from 'chalk';
import yaml from 'yaml';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

import { DEFAULT_SECURITY_POLICY } from './policy/defaultPolicy.js';
import { PolicyEngine } from './policy/engine.js';
import { SandboxManager } from './sandbox/manager.js';
import { ApprovalManager } from './audit/approvalManager.js';
import { AuditLogger } from './audit/logger.js';
import { McpGateway } from './protocol/gateway.js';
import { McpShieldWebServer } from './server/webServer.js';
import { SecurityPolicySchema } from './policy/schema.js';

const program = new Command();

program
  .name('mcp-shield')
  .description('🛡️ Hardened security gateway & real-time observability proxy for Anthropic Model Context Protocol (MCP)')
  .version('1.0.0');

// Command: run
program
  .command('run')
  .description('Start the MCP-Shield proxy gateway')
  .option('-u, --upstream <cmd...>', 'Command to run upstream MCP server (e.g. --upstream npx -y @modelcontextprotocol/server-filesystem /tmp)')
  .option('-p, --policy <path>', 'Path to custom security policy file (.yaml or .json)')
  .option('--port <number>', 'Port for real-time web dashboard', '4200')
  .option('--sandbox <mode>', 'Sandbox driver: auto, docker, or process', 'auto')
  .option('--no-dashboard', 'Disable real-time web dashboard')
  .action(async (options) => {
    console.error(chalk.cyan.bold('\n🛡️  Starting MCP-Shield Security Gateway...\n'));

    // 1. Load Policy
    let policy = DEFAULT_SECURITY_POLICY;
    if (options.policy) {
      try {
        const fileContent = await fs.readFile(options.policy, 'utf-8');
        const parsed = options.policy.endsWith('.json') ? JSON.parse(fileContent) : yaml.parse(fileContent);
        policy = SecurityPolicySchema.parse(parsed);
        console.error(chalk.green(`✓ Loaded custom policy: ${policy.name} (${policy.rules.length} rules)`));
      } catch (err: unknown) {
        console.error(chalk.red(`Failed to load policy file: ${err instanceof Error ? err.message : String(err)}`));
        process.exit(1);
      }
    } else {
      console.error(chalk.gray(`✓ Using built-in Anthropic Guardrail Policy (${policy.rules.length} rules)`));
    }

    // 2. Initialize Subsystems
    const policyEngine = new PolicyEngine(policy);
    const sandboxManager = new SandboxManager(options.sandbox);
    const activeDriver = await sandboxManager.initialize();
    console.error(chalk.cyan(`✓ Sandbox isolation initialized: driver = ${activeDriver}`));

    const approvalManager = new ApprovalManager();
    const auditLogger = new AuditLogger(500, true);

    // 3. Connect to Upstream MCP Server if provided
    let upstreamClient: Client | undefined;
    if (options.upstream && options.upstream.length > 0) {
      const [cmd, ...args] = options.upstream;
      console.error(chalk.gray(`⏳ Connecting to upstream MCP server: ${cmd} ${args.join(' ')}`));

      try {
        const transport = new StdioClientTransport({
          command: cmd,
          args,
        });

        upstreamClient = new Client(
          {
            name: 'mcp-shield-client',
            version: '1.0.0',
          },
          {
            capabilities: {},
          }
        );

        await upstreamClient.connect(transport);
        console.error(chalk.green('✓ Upstream MCP server connected!'));
      } catch (err) {
        console.error(chalk.red(`Failed to connect to upstream server: ${err}`));
        process.exit(1);
      }
    }

    // 4. Start Real-time Dashboard Web Server
    if (options.dashboard) {
      const webPort = parseInt(options.port, 10);
      const webServer = new McpShieldWebServer({
        port: webPort,
        policyEngine,
        sandboxManager,
        approvalManager,
        auditLogger,
      });

      await webServer.start();
      console.error(chalk.green.bold(`✓ Real-time Observability Dashboard: http://localhost:${webPort}\n`));
    }

    // 5. Connect Gateway to Client via STDIO
    const gateway = new McpGateway({
      policyEngine,
      sandboxManager,
      approvalManager,
      auditLogger,
      upstreamClient,
    });

    const stdioTransport = new StdioServerTransport();
    await gateway.getServer().connect(stdioTransport);
    console.error(chalk.magenta('🚀 MCP-Shield Gateway is actively intercepting and securing tool calls!\n'));
  });

// Command: init
program
  .command('init')
  .description('Generate sample configuration files and Claude Desktop integration snippet')
  .action(async () => {
    const yamlContent = yaml.stringify(DEFAULT_SECURITY_POLICY);
    const policyPath = path.join(process.cwd(), 'mcp-shield.yaml');
    await fs.writeFile(policyPath, yamlContent, 'utf-8');

    console.log(chalk.green(`\n✓ Generated default policy at ${policyPath}`));

    const claudeDesktopConfig = {
      mcpServers: {
        'shielded-filesystem': {
          command: 'npx',
          args: [
            '-y',
            'mcp-shield',
            'run',
            '--policy',
            policyPath,
            '--upstream',
            'npx',
            '-y',
            '@modelcontextprotocol/server-filesystem',
            process.cwd(),
          ],
        },
      },
    };

    console.log(chalk.bold('\nAdd this to your Claude Desktop config (~/Library/Application Support/Claude/claude_desktop_config.json):'));
    console.log(chalk.cyan(JSON.stringify(claudeDesktopConfig, null, 2)));
    console.log();
  });

program.parse(process.argv);
