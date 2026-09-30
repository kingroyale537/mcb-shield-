import { describe, it, expect } from 'vitest';
import { ProcessSandboxDriver } from '../src/sandbox/processDriver.js';
import { SandboxManager } from '../src/sandbox/manager.js';

describe('Sandbox Isolation Execution', () => {
  const driver = new ProcessSandboxDriver();

  it('successfully executes a basic command in process isolation', async () => {
    const result = await driver.execute({
      toolName: 'execute_command',
      args: { command: 'echo "hello mcp-shield"' },
      workspaceDir: process.cwd(),
      timeoutMs: 5000,
    });

    expect(result.success).toBe(true);
    expect(result.stdout).toBe('hello mcp-shield');
    expect(result.sandboxed).toBe(true);
    expect(result.driver).toBe('process-isolated');
  });

  it('enforces execution timeout and terminates running child', async () => {
    const result = await driver.execute({
      toolName: 'execute_command',
      args: { command: 'sleep 5' },
      workspaceDir: process.cwd(),
      timeoutMs: 500, // 500ms timeout
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('timed out');
  });

  it('scrubs sensitive environment secrets from execution context', async () => {
    // Set a dummy sensitive environment variable
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test-secret-value-12345';
    process.env.MY_SECRET_TOKEN = 'secret_token_abcdef';

    const result = await driver.execute({
      toolName: 'execute_command',
      args: { command: 'echo KEY=$ANTHROPIC_API_KEY && echo TOKEN=$MY_SECRET_TOKEN' },
      workspaceDir: process.cwd(),
      timeoutMs: 5000,
      envWhitelist: ['PATH', 'LANG'],
    });

    expect(result.success).toBe(true);
    // Neither key should appear in the output
    expect(result.stdout).not.toContain('sk-ant-test-secret-value-12345');
    expect(result.stdout).not.toContain('secret_token_abcdef');
    expect(result.stdout).toContain('KEY=');
    expect(result.stdout).toContain('TOKEN=');

    // Clean up
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.MY_SECRET_TOKEN;
  });

  it('SandboxManager tracks execution statistics properly', async () => {
    const manager = new SandboxManager('process');
    await manager.initialize();

    await manager.execute({
      toolName: 'execute_command',
      args: { command: 'echo "stat test"' },
      workspaceDir: process.cwd(),
      timeoutMs: 5000,
    });

    const stats = manager.getStats();
    expect(stats.totalExecutions).toBe(1);
    expect(stats.successfulExecutions).toBe(1);
    expect(stats.activeDriver).toBe('process-isolated');
  });
});
