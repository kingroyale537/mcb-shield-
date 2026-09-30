import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { SandboxDriver, SandboxExecutionRequest, SandboxExecutionResult } from './types.js';

export class ProcessSandboxDriver implements SandboxDriver {
  readonly name = 'process-isolated';

  async isAvailable(): Promise<boolean> {
    return true; // Always available on any Node environment
  }

  async execute(request: SandboxExecutionRequest): Promise<SandboxExecutionResult> {
    const startTime = performance.now();
    const command = this.extractCommand(request.args);

    if (!command) {
      return {
        success: false,
        output: null,
        executionTimeMs: performance.now() - startTime,
        sandboxed: true,
        driver: this.name,
        error: `Could not extract executable command from tool arguments for '${request.toolName}'.`,
      };
    }

    // 1. Create an isolated ephemeral workspace if needed
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-shield-proc-'));
    const workDir = request.workspaceDir || tempDir;

    // 2. Build sanitized environment: scrub all API keys and secrets!
    const sanitizedEnv = this.sanitizeEnvironment(request.envWhitelist || ['PATH', 'LANG', 'LC_ALL', 'TERM', 'NODE_ENV']);

    // 3. Execute with strict timeout handling
    try {
      const execResult = await this.runProcess(command, workDir, sanitizedEnv, request.timeoutMs);
      const executionTimeMs = performance.now() - startTime;

      return {
        success: execResult.exitCode === 0,
        output: {
          stdout: execResult.stdout,
          stderr: execResult.stderr,
          exitCode: execResult.exitCode,
        },
        stdout: execResult.stdout,
        stderr: execResult.stderr,
        exitCode: execResult.exitCode,
        executionTimeMs,
        sandboxed: true,
        driver: this.name,
      };
    } catch (err: unknown) {
      const executionTimeMs = performance.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        output: null,
        executionTimeMs,
        sandboxed: true,
        driver: this.name,
        error: errorMsg,
      };
    } finally {
      // Clean up temp dir if we created one
      try {
        await fs.rm(tempDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup error
      }
    }
  }

  private sanitizeEnvironment(whitelist: string[]): NodeJS.ProcessEnv {
    const cleanEnv: NodeJS.ProcessEnv = {};

    for (const key of whitelist) {
      if (process.env[key] !== undefined) {
        cleanEnv[key] = process.env[key];
      }
    }

    // Explicitly guarantee no secrets leak
    const blacklistSubstrings = ['KEY', 'SECRET', 'TOKEN', 'AUTH', 'PASSWORD', 'CREDENTIAL'];
    for (const [key] of Object.entries(process.env)) {
      const upperKey = key.toUpperCase();
      if (blacklistSubstrings.some((sub) => upperKey.includes(sub))) {
        delete cleanEnv[key];
      }
    }

    // Provide safe defaults
    cleanEnv.SANDBOX = 'true';
    cleanEnv.MCP_SHIELD = '1.0';

    return cleanEnv;
  }

  private runProcess(
    command: string,
    cwd: string,
    env: NodeJS.ProcessEnv,
    timeoutMs: number
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      // Spawn in shell for multi-command pipes, but with sanitized env
      const child = spawn('/bin/sh', ['-c', command], {
        cwd,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        // If still alive after 1000ms, force kill
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 1000);
      }, timeoutMs);

      child.stdout.on('data', (data) => {
        stdout += data.toString();
        // Prevent buffer explosion
        if (stdout.length > 5 * 1024 * 1024) {
          child.kill('SIGTERM');
        }
      });

      child.stderr.on('data', (data) => {
        stderr += data.toString();
        if (stderr.length > 5 * 1024 * 1024) {
          child.kill('SIGTERM');
        }
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        if (timedOut) {
          reject(new Error(`Execution timed out after ${timeoutMs}ms (SIGKILL enforced).`));
        } else {
          resolve({
            stdout: stdout.trim(),
            stderr: stderr.trim(),
            exitCode: code ?? 0,
          });
        }
      });
    });
  }

  private extractCommand(args: Record<string, unknown>): string | null {
    const keys = ['command', 'cmd', 'CommandLine', 'commandLine', 'script'];
    for (const key of keys) {
      if (typeof args[key] === 'string') {
        return args[key] as string;
      }
    }
    return null;
  }
}
