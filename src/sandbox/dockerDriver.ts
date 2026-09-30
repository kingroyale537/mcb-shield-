import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { SandboxDriver, SandboxExecutionRequest, SandboxExecutionResult } from './types.js';

const execFileAsync = promisify(execFile);

export class DockerSandboxDriver implements SandboxDriver {
  readonly name = 'docker-container';
  private image: string;

  constructor(image = 'alpine:3.20') {
    this.image = image;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { stdout } = await execFileAsync('docker', ['info', '--format', '{{.ServerVersion}}'], {
        timeout: 2000,
      });
      return stdout.trim().length > 0;
    } catch {
      return false;
    }
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
        error: `Could not extract command from tool arguments for '${request.toolName}'.`,
      };
    }

    const networkFlag = request.allowNetwork ? 'bridge' : 'none';
    const memoryLimit = `${request.maxMemoryMb || 512}m`;

    const dockerArgs = [
      'run',
      '--rm',
      `--network=${networkFlag}`,
      `--memory=${memoryLimit}`,
      '--cpus=1.0',
      '--pids-limit=100',
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      '-v',
      `${request.workspaceDir}:/workspace:rw`,
      '-w',
      '/workspace',
      this.image,
      '/bin/sh',
      '-c',
      command,
    ];

    try {
      const execResult = await this.runDockerProcess(dockerArgs, request.timeoutMs);
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
    }
  }

  private runDockerProcess(
    args: string[],
    timeoutMs: number
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      const child = spawn('docker', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (d) => {
        stdout += d.toString();
      });

      child.stderr.on('data', (d) => {
        stderr += d.toString();
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        if (timedOut) {
          reject(new Error(`Container execution timed out after ${timeoutMs}ms.`));
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
