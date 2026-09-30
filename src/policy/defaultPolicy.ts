import { SecurityPolicy } from './types.js';

export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
  name: 'Standard-Anthropic-Guardrails',
  version: '1.0.0',
  description: 'Enterprise-grade security policy for Model Context Protocol agents, preventing data exfiltration, system destruction, and unauthorized privilege escalation.',
  defaultAction: 'require_approval',
  sandbox: {
    driver: 'auto',
    maxExecutionTimeMs: 30000,
    maxMemoryMb: 512,
    allowNetwork: false,
    envWhitelist: ['PATH', 'NODE_ENV', 'LANG', 'LC_ALL', 'TERM'],
  },
  rules: [
    // 1. Critical Disallowed System Attacks
    {
      id: 'block-destructive-system-commands',
      name: 'Block Destructive System Commands',
      description: 'Prevents catastrophic destruction of host filesystems, formatting, and fork bombs.',
      toolPattern: '*(bash|sh|zsh|terminal|command|exec)*',
      action: 'block',
      riskLevel: 'critical',
      conditions: {
        commands: {
          denyPatterns: [
            // Destructive removal
            'rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|--force|-[a-zA-Z]*f[a-zA-Z]*r)\\s+[/~]',
            // Disk formatting and block device overwrite
            'mkfs(\\.[a-z0-9]+)?\\s+',
            'dd\\s+.*of=/dev/(sd[a-z]|nvme[0-9]|disk[0-9])',
            // Fork bombs
            ':\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\};\\s*:',
            // Permissions escalation / hijacking
            'chmod\\s+(-R\\s+)?777\\s+[/~]',
            'chown\\s+(-R\\s+)?root',
            // Reverse shells
            'nc\\s+.*-e\\s+/(bin/)?(ba)?sh',
            '/dev/tcp/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+',
            'python([0-9])?\\s+-c\\s+.*socket.*connect'
          ]
        }
      },
      reason: 'Detected signature of destructive system command or unauthorized reverse shell.'
    },

    // 2. Critical Credential and Secret Exfiltration Prevention
    {
      id: 'block-credential-exfiltration',
      name: 'Block Credential & Secret Exfiltration',
      description: 'Stops attempts to read or exfiltrate private SSH keys, cloud credentials, or environment secrets.',
      toolPattern: '*',
      action: 'block',
      riskLevel: 'critical',
      conditions: {
        paths: {
          denied: [
            '~/.ssh',
            '~/.aws',
            '~/.config/gcloud',
            '~/.kube',
            '~/.docker/config.json',
            '~/.gnupg',
            '/etc/shadow',
            '/etc/passwd',
            '/etc/sudoers',
            '**/etc/**',
            '**/.env*',
            '**/*_rsa*',
            '**/*id_ed25519*'
          ]
        },
        commands: {
          denyPatterns: [
            'printenv\\b',
            '\\benv\\b(\\s*\\|\\s*(grep|curl|wget))?',
            'cat\\s+.*(\\.(env|ssh|aws|kube)|id_rsa|id_ed25519)',
            'export\\s*$'
          ]
        }
      },
      reason: 'Attempted access or exfiltration of sensitive credentials or private keys.'
    },

    // 3. System Directory Write Protection
    {
      id: 'block-system-dir-writes',
      name: 'Block System Directory Mutations',
      description: 'Disallows file modifications to OS binaries, libraries, or system-wide configuration.',
      toolPattern: '*(write|edit|modify|append|create|delete|patch)*',
      action: 'block',
      riskLevel: 'critical',
      conditions: {
        paths: {
          denied: [
            '/bin',
            '/sbin',
            '/usr',
            '/System',
            '/Library',
            '/etc',
            '**/etc/**',
            '/var/root',
            '/private',
            '~/.bashrc',
            '~/.zshrc',
            '~/.profile',
            '~/.bash_profile',
            '**/.git/hooks/**'
          ]
        }
      },
      reason: 'Write access to protected system directories or shell initialization files is prohibited.'
    },

    // 4. Safe Read-Only Inspection Tools
    {
      id: 'allow-safe-reads',
      name: 'Allow Safe Read-Only Inspection',
      description: 'Permits uninhibited read-only inspections, queries, directory listings, and documentation fetching.',
      toolPattern: '*(read_file|view_file|list_directory|search_code|list_files|get_weather|fetch_docs)*',
      action: 'allow',
      riskLevel: 'low',
      reason: 'Safe read-only operation without side effects.'
    },

    // 5. Sandboxed Shell & Code Execution
    {
      id: 'sandbox-shell-execution',
      name: 'Sandbox Shell & Code Execution',
      description: 'Routes general command line and scripting tools into isolated containers or memory-constrained child sandboxes.',
      toolPattern: '*(bash|sh|zsh|terminal|exec|run_command|eval_python|run_script)*',
      action: 'sandbox',
      riskLevel: 'medium',
      conditions: {
        rateLimit: {
          maxCalls: 30,
          windowSeconds: 60
        }
      },
      reason: 'Code and shell execution routed to isolated sandbox environment.'
    },

    // 6. Project Filesystem Writes
    {
      id: 'allow-workspace-writes',
      name: 'Allow Workspace File Writes',
      description: 'Allows modifications within the active working directory, excluding hidden sensitive files.',
      toolPattern: '*(write_file|edit_file|create_file|replace_file_content)*',
      action: 'allow',
      riskLevel: 'medium',
      reason: 'Standard workspace file modifications within authorized bounds.'
    },

    // 7. Network Access Control
    {
      id: 'require-approval-for-network',
      name: 'Require Approval for Outbound Network',
      description: 'Escalates external web calls and API fetches for human operator confirmation to prevent SSRF and exfiltration.',
      toolPattern: '*(fetch|curl|wget|http_request|download)*',
      action: 'require_approval',
      riskLevel: 'high',
      reason: 'Outbound network requests require explicit operator confirmation.'
    }
  ]
};
