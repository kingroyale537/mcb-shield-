import {
  SandboxDriver,
  SandboxExecutionRequest,
  SandboxExecutionResult,
} from './types.js';
import { ProcessSandboxDriver } from './processDriver.js';
import { DockerSandboxDriver } from './dockerDriver.js';

export interface SandboxStats {
  activeDriver: string;
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  avgExecutionTimeMs: number;
}

export class SandboxManager {
  private driver: SandboxDriver;
  private processDriver: ProcessSandboxDriver;
  private dockerDriver: DockerSandboxDriver;
  private preferredMode: 'auto' | 'docker' | 'process';
  private totalExecutions = 0;
  private successfulExecutions = 0;
  private failedExecutions = 0;
  private totalTimeMs = 0;

  constructor(preferredMode: 'auto' | 'docker' | 'process' = 'auto') {
    this.preferredMode = preferredMode;
    this.processDriver = new ProcessSandboxDriver();
    this.dockerDriver = new DockerSandboxDriver();
    // Default to process driver initially
    this.driver = this.processDriver;
  }

  public async initialize(): Promise<string> {
    if (this.preferredMode === 'docker') {
      const dockerOk = await this.dockerDriver.isAvailable();
      if (!dockerOk) {
        throw new Error('Docker was explicitly selected for sandboxing, but the Docker daemon is unreachable.');
      }
      this.driver = this.dockerDriver;
      return this.driver.name;
    }

    if (this.preferredMode === 'auto') {
      const dockerOk = await this.dockerDriver.isAvailable();
      if (dockerOk) {
        this.driver = this.dockerDriver;
      } else {
        this.driver = this.processDriver;
      }
      return this.driver.name;
    }

    this.driver = this.processDriver;
    return this.driver.name;
  }

  public getActiveDriverName(): string {
    return this.driver.name;
  }

  public async execute(request: SandboxExecutionRequest): Promise<SandboxExecutionResult> {
    this.totalExecutions++;
    const result = await this.driver.execute(request);

    if (result.success) {
      this.successfulExecutions++;
    } else {
      this.failedExecutions++;
    }
    this.totalTimeMs += result.executionTimeMs;

    return result;
  }

  public getStats(): SandboxStats {
    return {
      activeDriver: this.driver.name,
      totalExecutions: this.totalExecutions,
      successfulExecutions: this.successfulExecutions,
      failedExecutions: this.failedExecutions,
      avgExecutionTimeMs:
        this.totalExecutions > 0 ? Math.round(this.totalTimeMs / this.totalExecutions) : 0,
    };
  }
}
