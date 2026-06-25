import { useEffect, useMemo, useState, type ReactNode } from 'react';
import type {
  DatasetAssessmentReport,
  HardeningSummary,
  NetworkFinding,
  RankedRisk,
  SecretFinding,
  SecretRotationEntry,
} from './types';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

type Tab = 'overview' | 'hardening' | 'secrets' | 'network' | 'analyse';

// ---------------------------------------------------------------------------
// Client-side vulnerability analyser
// ---------------------------------------------------------------------------
interface AnalysisFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  line?: number;
  match?: string;
  recommendation: string;
}

interface AnalysisResult {
  findings: AnalysisFinding[];
  score: number;
  tier: 1 | 2 | 3;
  summary: string;
}

const SECRET_PATTERNS: { pattern: RegExp; type: string; severity: 'critical' | 'high' }[] = [
  { pattern: /AKIA[0-9A-Z]{16}/g,                                severity: 'critical', type: 'AWS Access Key ID' },
  { pattern: /(?:aws.?secret|AWS_SECRET)[^\n]*[=:]\s*['"]?[A-Za-z0-9/+]{40}/gi, severity: 'critical', type: 'AWS Secret Key' },
  { pattern: /ghp_[A-Za-z0-9]{36}/g,                             severity: 'critical', type: 'GitHub PAT' },
  { pattern: /github_pat_[A-Za-z0-9_]{82}/g,                    severity: 'critical', type: 'GitHub Fine-grained PAT' },
  { pattern: /npm_[A-Za-z0-9]{36}/g,                             severity: 'high',     type: 'NPM Token' },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}/gi, severity: 'high',     type: 'Hardcoded Password' },
  { pattern: /(?:secret|api.?key|apikey)\s*[:=]\s*['"][^'"]{8,}/gi, severity: 'high', type: 'Hardcoded Secret/API Key' },
  { pattern: /BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY/g,     severity: 'critical', type: 'Private Key' },
  { pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,                   severity: 'high',     type: 'Slack Token' },
  { pattern: /sq[pg]_[A-Za-z0-9]{48}/g,                          severity: 'high',     type: 'SonarQube Token' },
];

const MUTABLE_REF = /uses:\s+([A-Za-z0-9_.\-\/]+)@(main|master|latest|HEAD|develop|v?\d+)/g;
const THIRD_PARTY  = /uses:\s+([A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+)@/g;
const WRITE_PERMS  = /(?:permissions|permission)[\s\S]{0,120}write-all|contents:\s*write|actions:\s*write|packages:\s*write|id-token:\s*write/gi;
const PR_TARGET    = /on:\s*[\s\S]*pull_request_target/g;
const SCRIPT_INJ   = /run:[\s\S]*?\$\{\{\s*github\.event\.(issue\.body|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body)/g;
const SELF_HOSTED  = /runs-on:\s*(?:\[)?self-hosted/gi;
const ALLOW_UNSECURE = /allow-no-pinned-digest|disable-security/gi;
const CURL_PIPE    = /curl\s+[^\n]*\|\s*(?:sh|bash|zsh|fish)/gi;
const EVAL_UNTRUST = /eval\s*\(\s*\$\{\{/gi;
const SUDO_USE     = /sudo\s+/g;

function getLineNumber(text: string, index: number): number {
  return text.substring(0, index).split('\n').length;
}

function analyseInput(input: string): AnalysisResult {
  const findings: AnalysisFinding[] = [];
  let fid = 0;
  const id = () => `F-${String(++fid).padStart(3, '0')}`;

  // 1. Secret detection
  for (const { pattern, type, severity } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(input)) !== null) {
      findings.push({
        id: id(), severity, title: `Hardcoded ${type} detected`,
        description: `A ${type} appears to be hardcoded directly in the input. This will be exposed in logs, forks, and version history.`,
        line: getLineNumber(input, m.index),
        match: m[0].substring(0, 24) + '…',
        recommendation: `Remove immediately. Rotate the credential. Store in GitHub Secrets and reference via \${{ secrets.SECRET_NAME }}.`,
      });
    }
  }

  // 2. Mutable action refs
  MUTABLE_REF.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MUTABLE_REF.exec(input)) !== null) {
    findings.push({
      id: id(), severity: 'high', title: 'Mutable action reference',
      description: `"${m[1]}@${m[2]}" uses a mutable ref. A compromised maintainer can silently alter what code runs in your pipeline.`,
      line: getLineNumber(input, m.index),
      match: m[0].trim(),
      recommendation: `Pin to an immutable commit SHA: uses: ${m[1]}@<full-sha>  # ${m[2]}`,
    });
  }

  // 3. Third-party actions
  const internalPrefixes = ['actions/', 'tr/', 'github/'];
  THIRD_PARTY.lastIndex = 0;
  const seenActions = new Set<string>();
  while ((m = THIRD_PARTY.exec(input)) !== null) {
    const action = m[1];
    if (!internalPrefixes.some((p) => action.startsWith(p)) && !seenActions.has(action)) {
      seenActions.add(action);
      findings.push({
        id: id(), severity: 'medium', title: 'Unapproved third-party action',
        description: `"${action}" is a third-party action not on the TR approved list. It has full access to your runner environment, secrets, and GITHUB_TOKEN.`,
        line: getLineNumber(input, m.index),
        match: m[0].trim(),
        recommendation: `Submit for security review. Pin to SHA once approved. Consider replacing with an internal TR equivalent.`,
      });
    }
  }

  // 4. Over-permissive token
  WRITE_PERMS.lastIndex = 0;
  if (WRITE_PERMS.test(input)) {
    findings.push({
      id: id(), severity: 'high', title: 'Over-permissive GITHUB_TOKEN',
      description: 'Broad write permissions on GITHUB_TOKEN increase the blast radius of a supply-chain attack.',
      recommendation: 'Set top-level permissions to read-only and grant write only to the specific job that needs it.',
    });
  }

  // 5. pull_request_target
  PR_TARGET.lastIndex = 0;
  if (PR_TARGET.test(input)) {
    findings.push({
      id: id(), severity: 'critical', title: 'Dangerous pull_request_target trigger',
      description: 'pull_request_target runs with write permissions and access to secrets even for PRs from forks. This is the most common attack vector for secret theft.',
      recommendation: 'Use pull_request instead. If pull_request_target is required, never check out untrusted code, and never expose secrets to that context.',
    });
  }

  // 6. Script injection
  SCRIPT_INJ.lastIndex = 0;
  if (SCRIPT_INJ.test(input)) {
    findings.push({
      id: id(), severity: 'critical', title: 'Script injection from untrusted input',
      description: 'Interpolating github.event values directly into a run: step allows attackers to inject arbitrary shell commands via PR titles, issue bodies, or comments.',
      recommendation: 'Store the value in an env var and reference $VAR in the script. Never interpolate ${{ github.event.* }} directly into shell commands.',
    });
  }

  // 7. Self-hosted runner
  SELF_HOSTED.lastIndex = 0;
  if (SELF_HOSTED.test(input)) {
    findings.push({
      id: id(), severity: 'medium', title: 'Self-hosted runner detected',
      description: 'Self-hosted runners persist state between jobs and can access internal network resources. Untrusted code on self-hosted runners can pivot into corporate infrastructure.',
      recommendation: 'Never run self-hosted runners for jobs triggered by external PRs. Ensure runners are ephemeral and network-isolated.',
    });
  }

  // 8. curl | sh pattern
  CURL_PIPE.lastIndex = 0;
  if (CURL_PIPE.test(input)) {
    findings.push({
      id: id(), severity: 'high', title: 'curl pipe to shell (curl | sh)',
      description: 'Piping curl output directly to a shell executes arbitrary remote code. If the endpoint is compromised or the request is intercepted, attackers can run anything on the runner.',
      recommendation: 'Download to a file, verify the checksum, then execute. Use package managers or pinned actions where possible.',
    });
  }

  // 9. eval with untrusted context
  EVAL_UNTRUST.lastIndex = 0;
  if (EVAL_UNTRUST.test(input)) {
    findings.push({
      id: id(), severity: 'critical', title: 'eval() with untrusted GitHub context',
      description: 'Using eval() with ${{ }} expressions allows untrusted user-controlled data to execute as code.',
      recommendation: 'Never eval GitHub context values. Use environment variables and validate inputs before use.',
    });
  }

  // 10. Sudo
  const sudoMatches = input.match(SUDO_USE);
  if (sudoMatches && sudoMatches.length > 2) {
    findings.push({
      id: id(), severity: 'low', title: 'Excessive sudo usage',
      description: `${sudoMatches.length} sudo invocations detected. Excessive privilege escalation increases risk if the runner is compromised.`,
      recommendation: 'Minimise sudo usage. Run processes as a non-root user where possible.',
    });
  }

  // Score
  const severityScore: Record<string, number> = { critical: 40, high: 20, medium: 10, low: 4 };
  const raw = findings.reduce((acc, f) => acc + (severityScore[f.severity] ?? 0), 0);
  const score = Math.min(100, raw);
  const tier: 1 | 2 | 3 = score >= 65 ? 1 : score >= 30 ? 2 : 3;

  const summary = findings.length === 0
    ? 'No vulnerabilities detected. Input looks clean.'
    : `${findings.length} issue${findings.length > 1 ? 's' : ''} found — ${findings.filter(f => f.severity === 'critical').length} critical, ${findings.filter(f => f.severity === 'high').length} high, ${findings.filter(f => f.severity === 'medium').length} medium, ${findings.filter(f => f.severity === 'low').length} low.`;

  return { findings, score, tier, summary };
}

// ---------------------------------------------------------------------------
// ANALYSE tab component
// ---------------------------------------------------------------------------
const EXAMPLE_YAML = `name: Deploy
on:
  pull_request_target:
    types: [opened]

permissions:
  contents: write
  actions: write

jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@main
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: AKIAIOSFODNN7EXAMPLE
          aws-secret-access-key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      - name: Run script
        run: |
          curl https://install.example.com/setup.sh | sh
          echo "PR title: \${{ github.event.pull_request.title }}"
`;

function AnalyseTab() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analysed, setAnalysed] = useState(false);

  function runAnalysis() {
    if (!input.trim()) return;
    setResult(analyseInput(input));
    setAnalysed(true);
  }

  function loadExample() {
    setInput(EXAMPLE_YAML);
    setResult(null);
    setAnalysed(false);
  }

  const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const sorted = result ? [...result.findings].sort((a, b) => (sevOrder[b.severity] ?? 0) - (sevOrder[a.severity] ?? 0)) : [];

  return (
    <div className="analyse-layout">
      <div className="analyse-input-panel">
        <div className="panel">
          <div className="panel-header">
            <h3>Paste workflow YAML or code snippet</h3>
            <button className="btn-ghost" onClick={loadExample}>Load example</button>
          </div>
          <textarea
            className="analyse-textarea"
            value={input}
            onChange={(e) => { setInput(e.target.value); setAnalysed(false); }}
            placeholder={`Paste a GitHub Actions workflow (.yml), shell script, or any code snippet here.\n\nThe scanner checks for:\n• Hardcoded secrets & credentials\n• Mutable / unpinned action refs\n• Third-party actions not on TR approved list\n• Over-permissive GITHUB_TOKEN\n• Dangerous triggers (pull_request_target)\n• Script injection vulnerabilities\n• Self-hosted runner risks\n• curl pipe-to-shell patterns\n• And more…`}
            spellCheck={false}
          />
          <div className="analyse-actions">
            <button className="btn-primary" onClick={runAnalysis} disabled={!input.trim()}>
              Analyse for vulnerabilities
            </button>
            {analysed && (
              <button className="btn-ghost" onClick={() => { setInput(''); setResult(null); setAnalysed(false); }}>
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="analyse-results-panel">
        {!analysed && (
          <div className="panel analyse-placeholder">
            <div className="analyse-placeholder__icon">⚿</div>
            <div className="analyse-placeholder__title">Vulnerability Scanner</div>
            <p className="muted">Paste a workflow or script on the left and click <strong>Analyse</strong> to get instant security feedback.</p>
            <div className="analyse-checks-list">
              {['Hardcoded secrets & API keys', 'Mutable action refs (@main, @latest)', 'Unapproved third-party actions', 'Script injection (pull_request_target)', 'Over-permissive GITHUB_TOKEN', 'Self-hosted runner exposure', 'curl | sh execution patterns', 'Dangerous eval() usage'].map((c) => (
                <div key={c} className="analyse-check-item">
                  <span className="analyse-check-dot" />
                  {c}
                </div>
              ))}
            </div>
          </div>
        )}

        {analysed && result && (
          <>
            <div className={`panel analyse-score-panel analyse-score--tier${result.tier}`}>
              <div className="analyse-score-row">
                <div>
                  <div className="analyse-score-number">{result.score}<span>/100</span></div>
                  <div className="analyse-score-label">Risk score</div>
                </div>
                <div className={`analyse-tier-badge analyse-tier--${result.tier}`}>
                  Tier {result.tier} — {result.tier === 1 ? 'Block' : result.tier === 2 ? 'Review' : 'Approve'}
                </div>
              </div>
              <div className="analyse-summary">{result.summary}</div>
              {result.findings.length > 0 && (
                <div className="analyse-sev-pills">
                  {(['critical','high','medium','low'] as const).map((s) => {
                    const n = result.findings.filter(f => f.severity === s).length;
                    return n > 0 ? <span key={s} className={`badge sev-${s}`}>{n} {s}</span> : null;
                  })}
                </div>
              )}
            </div>

            {sorted.length === 0 ? (
              <div className="panel analyse-clean">
                <div className="analyse-clean__icon">✓</div>
                <div>No vulnerabilities found. Input looks clean.</div>
              </div>
            ) : (
              <div className="findings-list">
                {sorted.map((f) => (
                  <div key={f.id} className={`finding-card finding-card--${f.severity}`}>
                    <div className="finding-card__header">
                      <div className="finding-card__left">
                        <span className={`badge sev-${f.severity}`}>{f.severity}</span>
                        <span className="finding-card__id">{f.id}</span>
                        {f.line && <span className="finding-card__line">Line {f.line}</span>}
                      </div>
                      <div className="finding-card__title">{f.title}</div>
                    </div>
                    {f.match && <div className="finding-card__match"><code>{f.match}</code></div>}
                    <p className="finding-card__desc">{f.description}</p>
                    <div className="finding-card__rec">
                      <span className="finding-card__rec-label">Recommendation</span>
                      {f.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Built-in demo report — uses real TR summary.json numbers
// Shown whenever the backend API is unavailable
// ---------------------------------------------------------------------------
const DEMO_REPORT: DatasetAssessmentReport = {
  generatedAt: new Date().toISOString(),
  datasetPath: 'C:/TR/github-actions-dataset',
  riskModel: { formula: 'RiskScore = min(100, Pinning + SourceType + BlastRadius + RefGovernance)' },
  summary: {
    totalActionUses: 236760,
    distinctActions: 3178,
    reposUsingActions: 16734,
    workflowFilesWithActions: 63966,
    highOrCriticalActions: 47,
    highOrCriticalRepos: 312,
    estimatedApiCalls: 188,
    estimatedLlmTokens: 282000,
    estimatedRuntimeMs: 14200,
    estimatedAnalystMinutes: 847,
  },
  topRiskyActions: [
    { entityId: 'azure/login', entityType: 'action', score: 72, level: 'critical', tier: 1, businessImpact: 'high', quickChecks: 4, deepChecks: 2, findings: ['Very low pinning rate (1.5%)', 'Third-party action', 'Mutable refs observed', 'High blast radius (413 repos)'], recommendations: ['Pin to immutable SHA', 'Open security review'], evidence: [], estimatedApiCalls: 4 },
    { entityId: 'microsoft/setup-msbuild', entityType: 'action', score: 67, level: 'critical', tier: 1, businessImpact: 'high', quickChecks: 4, deepChecks: 1, findings: ['Zero pinning rate (0%)', 'Third-party action', '517 repos affected'], recommendations: ['Pin to immutable SHA', 'Enforce policy gate'], evidence: [], estimatedApiCalls: 2 },
    { entityId: 'aws-actions/configure-aws-credentials', entityType: 'action', score: 62, level: 'high', tier: 1, businessImpact: 'high', quickChecks: 3, deepChecks: 2, findings: ['Low pinning rate (12.9%)', 'Third-party action', 'AWS credential scope risk'], recommendations: ['Pin to SHA', 'Enforce OIDC federation'], evidence: [], estimatedApiCalls: 4 },
    { entityId: 'wei/curl', entityType: 'action', score: 58, level: 'high', tier: 1, businessImpact: 'medium', quickChecks: 3, deepChecks: 1, findings: ['Zero pinning rate (0%)', 'Third-party action', 'Network egress risk'], recommendations: ['Replace with internal equivalent', 'Block pending review'], evidence: [], estimatedApiCalls: 2 },
    { entityId: 'docker/login-action', entityType: 'action', score: 54, level: 'high', tier: 1, businessImpact: 'high', quickChecks: 3, deepChecks: 2, findings: ['Very low pinning rate (2%)', 'Third-party action', 'Credential exposure risk'], recommendations: ['Pin to SHA', 'Use OIDC registry auth'], evidence: [], estimatedApiCalls: 4 },
    { entityId: 'hashicorp/setup-terraform', entityType: 'action', score: 48, level: 'high', tier: 2, businessImpact: 'high', quickChecks: 3, deepChecks: 1, findings: ['Low pinning rate (8.1%)', 'Third-party action', '387 repos affected'], recommendations: ['Pin to SHA', 'Security review required'], evidence: [], estimatedApiCalls: 2 },
    { entityId: 'emibcn/badge-action', entityType: 'action', score: 42, level: 'medium', tier: 2, businessImpact: 'medium', quickChecks: 3, deepChecks: 0, findings: ['Low pinning rate (20.6%)', 'Third-party action', '1105 repos affected'], recommendations: ['Pin to SHA or replace'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'release-drafter/release-drafter', entityType: 'action', score: 38, level: 'medium', tier: 2, businessImpact: 'medium', quickChecks: 2, deepChecks: 0, findings: ['Moderate pinning (39.8%)', 'Third-party action'], recommendations: ['Improve pinning rate'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'ncipollo/release-action', entityType: 'action', score: 35, level: 'medium', tier: 2, businessImpact: 'high', quickChecks: 2, deepChecks: 0, findings: ['Low pinning rate (29.3%)', 'Third-party action', '2088 repos'], recommendations: ['Pin to SHA'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'gradle/gradle-build-action', entityType: 'action', score: 32, level: 'medium', tier: 2, businessImpact: 'medium', quickChecks: 2, deepChecks: 0, findings: ['Very low pinning (1.7%)', 'Third-party action'], recommendations: ['Pin to SHA'], evidence: [], estimatedApiCalls: 0 },
  ],
  topSafeActions: [
    { entityId: 'actions/checkout', entityType: 'action', score: 18, level: 'low', tier: 3, businessImpact: 'high', quickChecks: 2, deepChecks: 0, findings: ['GitHub official action', 'Low pinning rate (8.4%)'], recommendations: ['Improve pinning'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'actions/upload-artifact', entityType: 'action', score: 12, level: 'low', tier: 3, businessImpact: 'medium', quickChecks: 1, deepChecks: 0, findings: ['GitHub official action'], recommendations: [], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'actions/setup-java', entityType: 'action', score: 14, level: 'low', tier: 3, businessImpact: 'medium', quickChecks: 2, deepChecks: 0, findings: ['GitHub official action', 'Very low pinning (4.1%)'], recommendations: ['Improve pinning'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'actions/setup-node', entityType: 'action', score: 16, level: 'low', tier: 3, businessImpact: 'medium', quickChecks: 2, deepChecks: 0, findings: ['GitHub official action', 'Very low pinning (2.3%)'], recommendations: ['Improve pinning'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'tr/prodsec_github_actions', entityType: 'action', score: 8, level: 'low', tier: 3, businessImpact: 'medium', quickChecks: 1, deepChecks: 0, findings: ['Internal TR action', 'Good pinning (28.6%)'], recommendations: [], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'tr/devops_lead-time-action', entityType: 'action', score: 6, level: 'low', tier: 3, businessImpact: 'low', quickChecks: 1, deepChecks: 0, findings: ['Internal TR action', 'Good pinning (48.6%)'], recommendations: [], evidence: [], estimatedApiCalls: 0 },
  ],
  topRiskyRepositories: [
    { entityId: 'tr/legal-research-api', entityType: 'repository', score: 68, level: 'critical', tier: 1, businessImpact: 'high', quickChecks: 3, deepChecks: 0, findings: ['Very low pinning', 'High third-party dependency'], recommendations: ['Reduce token scope', 'Increase SHA pinning'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'tr/westlaw-search-service', entityType: 'repository', score: 61, level: 'high', tier: 1, businessImpact: 'high', quickChecks: 3, deepChecks: 0, findings: ['Low pinning', 'High third-party dependency', 'Customer-facing'], recommendations: ['Increase SHA pinning'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'tr/tax-compliance-platform', entityType: 'repository', score: 54, level: 'high', tier: 1, businessImpact: 'high', quickChecks: 2, deepChecks: 0, findings: ['Low pinning', 'Customer-facing software class'], recommendations: ['Reduce third-party exposure'], evidence: [], estimatedApiCalls: 0 },
  ],
  topRiskyBusinessUnits: [
    { entityId: 'Legal Professionals', entityType: 'business_unit', score: 48, level: 'high', tier: 2, businessImpact: 'high', quickChecks: 2, deepChecks: 0, findings: ['High BU third-party share', 'Low BU pinning baseline'], recommendations: ['Run BU remediation program'], evidence: [], estimatedApiCalls: 0 },
    { entityId: 'Tax & Accounting', entityType: 'business_unit', score: 42, level: 'medium', tier: 2, businessImpact: 'high', quickChecks: 2, deepChecks: 0, findings: ['High third-party share'], recommendations: ['Run BU remediation program'], evidence: [], estimatedApiCalls: 0 },
  ],
  prioritizedRecommendations: [
    'Enforce SHA pinning for all third-party actions — only 10.7% of 236,760 uses are currently pinned.',
    'Block mutable refs (main/master/latest) for third-party actions via branch protection policy.',
    'Require security review for azure/login, microsoft/setup-msbuild, and aws-actions/configure-aws-credentials before any new use.',
    'Reduce GITHUB_TOKEN permissions to read-only at org level; grant write only to specific jobs.',
    'Enable Zscaler proxy enforcement for all GitHub Actions network egress.',
    'Auto-rotate secrets older than 90 days; prioritise AWS and Azure credentials.',
  ],
  operationalProcess: [
    { decision: 'approve', criteria: ['Internal TR action', 'SHA pinned', 'Low risk score'], nextSteps: ['Allow reuse'], reassessment: 'weekly' },
    { decision: 'conditional_approve', criteria: ['Medium risk', 'Owner assigned'], nextSteps: ['Remediate within 14 days'], reassessment: 'bi-weekly' },
    { decision: 'reject_or_block', criteria: ['Tier 1 action', 'Unpinned third-party in sensitive context'], nextSteps: ['Block merge/deploy', 'Security review'], reassessment: 'after remediation' },
    { decision: 'exception', criteria: ['Business justification documented', 'Expiry set'], nextSteps: ['Time-boxed approval'], reassessment: 'before expiry' },
  ],
  costAndScalabilityNotes: [
    'Baseline checks are CSV-local and scale linearly.',
    'Deep checks are capped to top risk tier to control API/LLM usage.',
  ],
  hardeningSummary: {
    thirdPartyBlocked: 5,
    thirdPartyAllowed: 5,
    thirdPartyTotal: 683,
    secretLeaksFound: 5,
    maliciousPatterns: 2,
    networkViolations: 5,
    secretsOverdue: 4,
    secretsDue: 2,
    secretsOk: 4,
    tier1Count: 5,
    tier2Count: 5,
    tier3Count: 6,
  },
};

// ---------------------------------------------------------------------------
// Demo / fallback data (used when backend hasn't generated hardening fields)
// ---------------------------------------------------------------------------
const DEMO_SECRETS: SecretFinding[] = [
  { id: 'SEC-0001', repository: 'tr/legal-research-api', workflowPath: '.github/workflows/ci.yml', secretType: 'AWS_SECRET_ACCESS_KEY', severity: 'critical', location: 'Line 42', masked: 'AKIA***************Qz9', confirmed: true, remediation: 'Remove secret, rotate AWS credentials, use OIDC federation' },
  { id: 'SEC-0002', repository: 'tr/westlaw-search-service', workflowPath: '.github/workflows/deploy.yml', secretType: 'GITHUB_PAT', severity: 'high', location: 'Line 87', masked: 'ghp_***************abc', confirmed: true, remediation: 'Replace with GITHUB_TOKEN (minimal scopes); remove hardcoded PAT' },
  { id: 'SEC-0003', repository: 'tr/tax-compliance-platform', workflowPath: '.github/workflows/release.yml', secretType: 'AZURE_CLIENT_SECRET', severity: 'high', location: 'Line 23', masked: '***************def', confirmed: true, remediation: 'Rotate secret, migrate to managed identity or OIDC' },
  { id: 'SEC-0004', repository: 'tr/practical-law-gateway', workflowPath: '.github/workflows/build.yml', secretType: 'NPM_TOKEN', severity: 'high', location: 'Line 61', masked: 'npm_***************xyz', confirmed: true, remediation: 'Rotate NPM token, store in GitHub Secrets' },
  { id: 'SEC-0005', repository: 'tr/checkpoint-api', workflowPath: '.github/workflows/test.yml', secretType: 'DOCKER_PASSWORD', severity: 'medium', location: 'Line 18', masked: '***************pass', confirmed: false, remediation: 'Use registry OIDC or ephemeral tokens; remove hardcoded password' },
  { id: 'SEC-0006', repository: 'tr/cobalt-data-pipeline', workflowPath: '.github/workflows/ci.yml', secretType: 'SONAR_TOKEN', severity: 'medium', location: 'Line 55', masked: 'squ_***************ijk', confirmed: false, remediation: 'Rotate SonarQube token, store in GitHub Secrets' },
  { id: 'SEC-0007', repository: 'tr/reuters-connect-api', workflowPath: '.github/workflows/deploy.yml', secretType: 'DATADOG_API_KEY', severity: 'medium', location: 'Line 33', masked: 'DD_***************api', confirmed: false, remediation: 'Rotate Datadog API key, use environment-specific secrets' },
  { id: 'SEC-0008', repository: 'tr/findlaw-indexer', workflowPath: '.github/workflows/release.yml', secretType: 'VAULT_TOKEN', severity: 'critical', location: 'Line 77', masked: 'hvs.***************tok', confirmed: true, remediation: 'Use dynamic Vault secrets with short TTL; remove static token' },
];

const DEMO_NETWORK: NetworkFinding[] = [
  { id: 'NET-0001', repository: 'tr/legal-research-api', workflowPath: '.github/workflows/ci.yml', endpoint: 'registry.npmjs.org', protocol: 'HTTPS', viaZscaler: false, companyOwned: false, action: 'actions/setup-node@v3', severity: 'high', blocked: true },
  { id: 'NET-0002', repository: 'tr/westlaw-search-service', workflowPath: '.github/workflows/deploy.yml', endpoint: 'hub.docker.com', protocol: 'HTTPS', viaZscaler: false, companyOwned: false, action: 'docker/build-push-action@v4', severity: 'high', blocked: true },
  { id: 'NET-0003', repository: 'tr/tax-compliance-platform', workflowPath: '.github/workflows/build.yml', endpoint: 'pypi.org', protocol: 'HTTPS', viaZscaler: true, companyOwned: false, action: 'actions/setup-python@v4', severity: 'medium', blocked: false },
  { id: 'NET-0004', repository: 'tr/practical-law-gateway', workflowPath: '.github/workflows/ci.yml', endpoint: 'api.github.com', protocol: 'HTTPS', viaZscaler: false, companyOwned: false, action: 'actions/checkout@v4', severity: 'medium', blocked: false },
  { id: 'NET-0005', repository: 'tr/checkpoint-api', workflowPath: '.github/workflows/release.yml', endpoint: 'artifactory.int.thomsonreuters.com', protocol: 'HTTPS', viaZscaler: true, companyOwned: true, action: 'tr/publish-action@v2', severity: 'low', blocked: false },
  { id: 'NET-0006', repository: 'tr/cobalt-data-pipeline', workflowPath: '.github/workflows/test.yml', endpoint: 'repo.maven.apache.org', protocol: 'HTTPS', viaZscaler: false, companyOwned: false, action: 'actions/setup-java@v3', severity: 'high', blocked: true },
  { id: 'NET-0007', repository: 'tr/reuters-connect-api', workflowPath: '.github/workflows/ci.yml', endpoint: 'sonarqube.int.thomsonreuters.com', protocol: 'HTTPS', viaZscaler: true, companyOwned: true, action: 'sonarsource/sonarcloud-github-action@v2', severity: 'low', blocked: false },
  { id: 'NET-0008', repository: 'tr/findlaw-indexer', workflowPath: '.github/workflows/deploy.yml', endpoint: 'ghcr.io', protocol: 'HTTPS', viaZscaler: false, companyOwned: false, action: 'docker/build-push-action@v4', severity: 'high', blocked: true },
];

const DEMO_ROTATION: SecretRotationEntry[] = [
  { secretName: 'AWS_SECRET_ACCESS_KEY', repository: 'tr/legal-research-api', lastRotatedDays: 125, status: 'overdue', nextRotationDays: 0, autoRotateEnabled: false },
  { secretName: 'GITHUB_PAT', repository: 'tr/westlaw-search-service', lastRotatedDays: 92, status: 'due', nextRotationDays: 14, autoRotateEnabled: false },
  { secretName: 'NPM_PUBLISH_TOKEN', repository: 'tr/tax-compliance-platform', lastRotatedDays: 30, status: 'ok', nextRotationDays: 60, autoRotateEnabled: true },
  { secretName: 'SONAR_TOKEN', repository: 'tr/practical-law-gateway', lastRotatedDays: 180, status: 'overdue', nextRotationDays: 0, autoRotateEnabled: false },
  { secretName: 'AZURE_CLIENT_SECRET', repository: 'tr/checkpoint-api', lastRotatedDays: 67, status: 'due', nextRotationDays: 23, autoRotateEnabled: true },
  { secretName: 'DOCKER_REGISTRY_PASSWORD', repository: 'tr/cobalt-data-pipeline', lastRotatedDays: 25, status: 'ok', nextRotationDays: 65, autoRotateEnabled: true },
  { secretName: 'ARTIFACTORY_API_KEY', repository: 'tr/reuters-connect-api', lastRotatedDays: 150, status: 'overdue', nextRotationDays: 0, autoRotateEnabled: false },
  { secretName: 'SLACK_WEBHOOK', repository: 'tr/findlaw-indexer', lastRotatedDays: 200, status: 'overdue', nextRotationDays: 0, autoRotateEnabled: false },
  { secretName: 'DATADOG_API_KEY', repository: 'tr/checkpoint-api', lastRotatedDays: 38, status: 'ok', nextRotationDays: 52, autoRotateEnabled: true },
  { secretName: 'VAULT_TOKEN', repository: 'tr/legal-research-api', lastRotatedDays: 15, status: 'ok', nextRotationDays: 75, autoRotateEnabled: true },
];

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
function tierClass(tier: number) {
  if (tier === 1) return 'tier-1';
  if (tier === 2) return 'tier-2';
  return 'tier-3';
}

function sevClass(sev: string) {
  return `sev-${sev.toLowerCase()}`;
}

function rotClass(status: string) {
  if (status === 'overdue') return 'rot-overdue';
  if (status === 'due') return 'rot-due';
  return 'rot-ok';
}

function scoreWidth(score: number) {
  return `${Math.max(4, Math.min(100, score))}%`;
}

// ---------------------------------------------------------------------------
// Small shared components
// ---------------------------------------------------------------------------
function Pill({ children }: { children: ReactNode }) {
  return <span className="pill">{children}</span>;
}

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className={`stat-card${accent ? ` stat-card--${accent}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub ? <div className="stat-hint">{sub}</div> : null}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge ${sevClass(severity)}`}>{severity}</span>;
}

function TierBadge({ tier }: { tier: number }) {
  return <span className={`badge ${tierClass(tier)}`}>T{tier}</span>;
}

// ---------------------------------------------------------------------------
// Tier distribution bar
// ---------------------------------------------------------------------------
function TierDistributionBar({ t1, t2, t3 }: { t1: number; t2: number; t3: number }) {
  const total = t1 + t2 + t3 || 1;
  return (
    <div className="tier-bar-wrap">
      <div className="tier-bar">
        <div className="tier-bar__seg tier-bar__seg--1" style={{ width: `${(t1 / total) * 100}%` }} title={`Tier 1: ${t1}`} />
        <div className="tier-bar__seg tier-bar__seg--2" style={{ width: `${(t2 / total) * 100}%` }} title={`Tier 2: ${t2}`} />
        <div className="tier-bar__seg tier-bar__seg--3" style={{ width: `${(t3 / total) * 100}%` }} title={`Tier 3: ${t3}`} />
      </div>
      <div className="tier-bar__legend">
        <span className="tier-bar__dot tier-bar__dot--1" /> T1 Block ({t1})
        <span className="tier-bar__dot tier-bar__dot--2" /> T2 Review ({t2})
        <span className="tier-bar__dot tier-bar__dot--3" /> T3 Approve ({t3})
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Risk card (compact)
// ---------------------------------------------------------------------------
function RiskCard({ item, compact }: { item: RankedRisk; compact?: boolean }) {
  const tier = item.tier ?? (item.score >= 65 ? 1 : item.score >= 30 ? 2 : 3);
  return (
    <article className={`risk-card${compact ? ' risk-card--compact' : ''}`}>
      <div className="risk-card__top">
        <div>
          <div className="risk-card__entity">{item.entityType.replace('_', ' ')}</div>
          <h3 className="risk-card__id">{item.entityId}</h3>
        </div>
        <div className="risk-card__badges">
          <TierBadge tier={tier} />
          <span className={`badge badge-${item.level}`}>{item.level}</span>
        </div>
      </div>
      <div className="progress-row">
        <div className="progress-meta">
          <span>Risk score</span>
          <strong>{item.score}/100</strong>
        </div>
        <div className="progress-track">
          <div className={`progress-bar progress-${item.level}`} style={{ width: scoreWidth(item.score) }} />
        </div>
      </div>
      {!compact && (
        <>
          <div className="chips">
            <Pill>{item.businessImpact} impact</Pill>
            <Pill>{item.quickChecks} quick checks</Pill>
            {item.deepChecks > 0 && <Pill>{item.deepChecks} deep checks</Pill>}
          </div>
          <div className="risk-section">
            <div className="section-title">Findings</div>
            <ul>{item.findings.length ? item.findings.map((f) => <li key={f}>{f}</li>) : <li>No notable findings</li>}</ul>
          </div>
        </>
      )}
    </article>
  );
}

// ---------------------------------------------------------------------------
// OVERVIEW tab
// ---------------------------------------------------------------------------
function OverviewTab({ report, hs }: { report: DatasetAssessmentReport; hs: HardeningSummary }) {
  const top = report.topRiskyActions.slice(0, 6);
  return (
    <>
      <section className="hero">
        <div>
          <div className="eyebrow">ActionTrust · GitHub Actions Security</div>
          <h2>Actions hardening &amp; vulnerability dashboard</h2>
          <p className="muted">
            Scanning {report.summary.totalActionUses.toLocaleString()} action uses across{' '}
            {report.summary.reposUsingActions.toLocaleString()} repositories. Actions are classified into security tiers,
            secret leaks are flagged, and network policy violations are surfaced.
          </p>
        </div>
        <div className="hero-card">
          <div className="hero-score">{report.summary.totalActionUses.toLocaleString()}</div>
          <div className="muted">Total action uses scanned</div>
        </div>
      </section>

      <section className="stats-grid">
        <StatCard label="Distinct actions" value={report.summary.distinctActions.toLocaleString()} />
        <StatCard label="Repos scanned" value={report.summary.reposUsingActions.toLocaleString()} />
        <StatCard label="Workflow files" value={report.summary.workflowFilesWithActions.toLocaleString()} />
        <StatCard label="High/Critical actions" value={report.summary.highOrCriticalActions.toLocaleString()} accent="warn" />
        <StatCard label="High/Critical repos" value={report.summary.highOrCriticalRepos.toLocaleString()} accent="warn" />
        <StatCard label="Analyst minutes saved" value={report.summary.estimatedAnalystMinutes.toLocaleString()} accent="ok" />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Security tier distribution</h3>
          <span className="muted">All scanned actions</span>
        </div>
        <div className="tier-summary-grid">
          <div className="tier-summary-card tier-summary-card--1">
            <div className="tier-summary-number">{hs.tier1Count}</div>
            <div className="tier-summary-label">Tier 1 — Block</div>
            <div className="tier-summary-sub">Critical &amp; High risk · Immediate action required</div>
          </div>
          <div className="tier-summary-card tier-summary-card--2">
            <div className="tier-summary-number">{hs.tier2Count}</div>
            <div className="tier-summary-label">Tier 2 — Review</div>
            <div className="tier-summary-sub">Medium risk · Security review within 14 days</div>
          </div>
          <div className="tier-summary-card tier-summary-card--3">
            <div className="tier-summary-number">{hs.tier3Count}</div>
            <div className="tier-summary-label">Tier 3 — Approve</div>
            <div className="tier-summary-sub">Low risk · Approved with monitoring</div>
          </div>
        </div>
        <TierDistributionBar t1={hs.tier1Count} t2={hs.tier2Count} t3={hs.tier3Count} />
      </section>

      <section className="panel two-col">
        <div>
          <div className="panel-header"><h3>Top risky actions</h3><span className="muted">Sorted by score</span></div>
          <div className="risk-list">{top.map((r) => <RiskCard key={r.entityId} item={r} />)}</div>
        </div>
        <div className="stack">
          <div className="panel-inner">
            <h3>Prioritised recommendations</h3>
            <ol>{report.prioritizedRecommendations.map((r) => <li key={r}>{r}</li>)}</ol>
          </div>
          <div className="panel-inner">
            <h3>Hardening overview</h3>
            <div className="kv-list">
              <div className="kv-row"><span>Third-party blocked</span><strong className="kv-bad">{hs.thirdPartyBlocked}</strong></div>
              <div className="kv-row"><span>Third-party allowed</span><strong className="kv-ok">{hs.thirdPartyAllowed}</strong></div>
              <div className="kv-row"><span>Secret leaks found</span><strong className="kv-bad">{hs.secretLeaksFound}</strong></div>
              <div className="kv-row"><span>Network violations</span><strong className="kv-bad">{hs.networkViolations}</strong></div>
              <div className="kv-row"><span>Secrets overdue rotation</span><strong className="kv-bad">{hs.secretsOverdue}</strong></div>
              <div className="kv-row"><span>Secrets OK</span><strong className="kv-ok">{hs.secretsOk}</strong></div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

// ---------------------------------------------------------------------------
// HARDENING tab
// ---------------------------------------------------------------------------
function HardeningTab({ report, hs }: { report: DatasetAssessmentReport; hs: HardeningSummary }) {
  const actions = useMemo(() => {
    const all = [...(report.topRiskyActions ?? []), ...(report.topSafeActions ?? [])];
    return all.filter((x, i, a) => a.findIndex((y) => y.entityId === x.entityId) === i);
  }, [report]);

  const t1 = useMemo(() => actions.filter((a) => (a.tier ?? 1) === 1), [actions]);
  const t2 = useMemo(() => actions.filter((a) => (a.tier ?? 2) === 2), [actions]);
  const t3 = useMemo(() => actions.filter((a) => (a.tier ?? 3) === 3), [actions]);

  return (
    <>
      <section className="stats-grid">
        <StatCard label="Total actions" value={hs.thirdPartyTotal} />
        <StatCard label="Tier 1 — Blocked" value={hs.tier1Count} accent="bad" />
        <StatCard label="Tier 2 — Review" value={hs.tier2Count} accent="warn" />
        <StatCard label="Tier 3 — Approved" value={hs.tier3Count} accent="ok" />
        <StatCard label="Third-party blocked" value={hs.thirdPartyBlocked} accent="bad" />
        <StatCard label="Third-party allowed" value={hs.thirdPartyAllowed} accent="ok" />
      </section>

      <section className="panel">
        <div className="panel-header"><h3>Tier classification</h3><span className="muted">Based on security score and risk factors</span></div>
        <div className="tier-board">

          <div className="tier-col tier-col--1">
            <div className="tier-col__header">
              <span className="tier-col__badge">T1</span>
              <div>
                <div className="tier-col__title">Block</div>
                <div className="tier-col__sub">Score ≥ 65 · {t1.length} actions</div>
              </div>
            </div>
            <div className="tier-col__body">
              {t1.length === 0 && <div className="tier-empty">No Tier 1 actions</div>}
              {t1.map((a) => (
                <div key={a.entityId} className="tier-item">
                  <div className="tier-item__name">{a.entityId}</div>
                  <div className="tier-item__meta">
                    <span className={`badge badge-${a.level}`}>{a.level}</span>
                    <span>{a.score}/100</span>
                  </div>
                  {a.findings.slice(0, 2).map((f) => <div key={f} className="tier-item__finding">• {f}</div>)}
                </div>
              ))}
            </div>
          </div>

          <div className="tier-col tier-col--2">
            <div className="tier-col__header">
              <span className="tier-col__badge">T2</span>
              <div>
                <div className="tier-col__title">Review</div>
                <div className="tier-col__sub">Score 30–64 · {t2.length} actions</div>
              </div>
            </div>
            <div className="tier-col__body">
              {t2.length === 0 && <div className="tier-empty">No Tier 2 actions</div>}
              {t2.map((a) => (
                <div key={a.entityId} className="tier-item">
                  <div className="tier-item__name">{a.entityId}</div>
                  <div className="tier-item__meta">
                    <span className={`badge badge-${a.level}`}>{a.level}</span>
                    <span>{a.score}/100</span>
                  </div>
                  {a.findings.slice(0, 2).map((f) => <div key={f} className="tier-item__finding">• {f}</div>)}
                </div>
              ))}
            </div>
          </div>

          <div className="tier-col tier-col--3">
            <div className="tier-col__header">
              <span className="tier-col__badge">T3</span>
              <div>
                <div className="tier-col__title">Approve</div>
                <div className="tier-col__sub">Score &lt; 30 · {t3.length} actions</div>
              </div>
            </div>
            <div className="tier-col__body">
              {t3.length === 0 && <div className="tier-empty">No Tier 3 actions</div>}
              {t3.map((a) => (
                <div key={a.entityId} className="tier-item tier-item--safe">
                  <div className="tier-item__name">{a.entityId}</div>
                  <div className="tier-item__meta">
                    <span className={`badge badge-${a.level}`}>{a.level}</span>
                    <span>{a.score}/100</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </section>

      <section className="panel">
        <div className="panel-header"><h3>Operational policy</h3></div>
        <div className="policy-grid">
          {report.operationalProcess.map((p) => (
            <div key={p.decision} className={`policy-card policy-card--${p.decision.replace('_', '-')}`}>
              <div className="policy-card__decision">{p.decision.replace(/_/g, ' ')}</div>
              <ul>{p.criteria.map((c) => <li key={c}>{c}</li>)}</ul>
              <div className="policy-card__reassess">Reassess: {p.reassessment}</div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

// ---------------------------------------------------------------------------
// SECRETS tab
// ---------------------------------------------------------------------------
function SecretsTab({ secrets, hs }: { secrets: SecretFinding[]; hs: HardeningSummary }) {
  const [filter, setFilter] = useState<string>('all');
  const filtered = filter === 'all' ? secrets : secrets.filter((s) => s.severity === filter);

  return (
    <>
      <section className="stats-grid">
        <StatCard label="Total findings" value={secrets.length} />
        <StatCard label="Confirmed leaks" value={hs.secretLeaksFound} accent="bad" />
        <StatCard label="Critical severity" value={hs.maliciousPatterns} accent="bad" />
        <StatCard label="High severity" value={secrets.filter((s) => s.severity === 'high').length} accent="warn" />
        <StatCard label="Medium severity" value={secrets.filter((s) => s.severity === 'medium').length} />
        <StatCard label="Unconfirmed" value={secrets.filter((s) => !s.confirmed).length} />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Secret scan findings</h3>
          <div className="segmented">
            {['all', 'critical', 'high', 'medium'].map((f) => (
              <button key={f} className={filter === f ? 'segment active' : 'segment'} onClick={() => setFilter(f)}>{f}</button>
            ))}
          </div>
        </div>
        <div className="secret-table">
          <div className="secret-table__head">
            <span>ID</span><span>Repository</span><span>Secret type</span><span>Location</span><span>Masked value</span><span>Severity</span><span>Status</span>
          </div>
          {filtered.map((s) => (
            <div key={s.id} className="secret-table__row">
              <span className="mono">{s.id}</span>
              <span className="mono small">{s.repository}</span>
              <span><code>{s.secretType}</code></span>
              <span className="muted">{s.workflowPath} · {s.location}</span>
              <span className="mono masked">{s.masked}</span>
              <SeverityBadge severity={s.severity} />
              <span className={s.confirmed ? 'status-confirmed' : 'status-unconfirmed'}>{s.confirmed ? 'Confirmed' : 'Potential'}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header"><h3>Remediation guide</h3><span className="muted">Top priority actions</span></div>
        <div className="remediation-list">
          {filtered.filter((s) => s.confirmed).map((s) => (
            <div key={s.id} className="remediation-item">
              <div className="remediation-item__top">
                <code>{s.secretType}</code>
                <SeverityBadge severity={s.severity} />
              </div>
              <div className="muted small">{s.repository} — {s.location}</div>
              <div className="remediation-item__action">{s.remediation}</div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

// ---------------------------------------------------------------------------
// NETWORK & ROTATION tab
// ---------------------------------------------------------------------------
function NetworkRotationTab({ network, rotation, hs }: { network: NetworkFinding[]; rotation: SecretRotationEntry[]; hs: HardeningSummary }) {
  return (
    <>
      <section className="stats-grid">
        <StatCard label="Network violations" value={hs.networkViolations} accent="bad" />
        <StatCard label="Non-Zscaler access" value={network.filter((n) => !n.viaZscaler).length} accent="warn" />
        <StatCard label="External endpoints" value={network.filter((n) => !n.companyOwned).length} />
        <StatCard label="Secrets overdue" value={hs.secretsOverdue} accent="bad" />
        <StatCard label="Secrets due" value={hs.secretsDue} accent="warn" />
        <StatCard label="Secrets OK" value={hs.secretsOk} accent="ok" />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Network access policy</h3>
          <span className="muted">Non-Zscaler / non-company endpoints flagged</span>
        </div>
        <div className="net-table">
          <div className="net-table__head">
            <span>Repository</span><span>Endpoint</span><span>Via Zscaler</span><span>Company-owned</span><span>Action</span><span>Severity</span><span>Status</span>
          </div>
          {network.map((n) => (
            <div key={n.id} className="net-table__row">
              <span className="mono small">{n.repository}</span>
              <span className="mono">{n.endpoint}</span>
              <span className={n.viaZscaler ? 'status-ok' : 'status-bad'}>{n.viaZscaler ? 'Yes' : 'No'}</span>
              <span className={n.companyOwned ? 'status-ok' : 'status-warn'}>{n.companyOwned ? 'Yes' : 'No'}</span>
              <span className="mono small">{n.action}</span>
              <SeverityBadge severity={n.severity} />
              <span className={n.blocked ? 'status-bad' : 'status-ok'}>{n.blocked ? 'Blocked' : 'Allowed'}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Auto-rotation status</h3>
          <span className="muted">Secret credential lifecycle</span>
        </div>
        <div className="rot-table">
          <div className="rot-table__head">
            <span>Secret</span><span>Repository</span><span>Last rotated</span><span>Status</span><span>Next rotation</span><span>Auto-rotate</span>
          </div>
          {rotation.map((r) => (
            <div key={`${r.secretName}-${r.repository}`} className="rot-table__row">
              <span><code>{r.secretName}</code></span>
              <span className="mono small">{r.repository}</span>
              <span>{r.lastRotatedDays}d ago</span>
              <span className={rotClass(r.status)}>{r.status}</span>
              <span>{r.nextRotationDays > 0 ? `in ${r.nextRotationDays}d` : <span className="status-bad">Overdue</span>}</span>
              <span className={r.autoRotateEnabled ? 'status-ok' : 'status-warn'}>{r.autoRotateEnabled ? 'Enabled' : 'Manual'}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

// ---------------------------------------------------------------------------
// TR Logo (inline SVG — no file dependency)
// ---------------------------------------------------------------------------
function TRLogo() {
  // TR sphere: 5 columns × 4 rows of dots, left-heavy circular arrangement
  const dots: [number, number, number][] = [
                        [17,4,2.8], [23,3,2.5],
        [8,9,2.8],  [14,7,3.0],  [20,6,3.0],  [26,6,2.8],
    [4,14,2.8], [10,13,3.2], [16,11,3.2], [22,11,3.0], [28,12,2.6],
    [4,20,2.8], [10,19,3.2], [16,18,3.2], [22,18,3.0], [28,19,2.5],
    [5,26,2.5], [11,25,3.0], [17,24,3.0], [23,24,2.8],
        [7,31,2.2],  [13,31,2.6],  [19,30,2.5],
  ];
  return (
    <svg width="156" height="42" viewBox="0 0 156 42" xmlns="http://www.w3.org/2000/svg" aria-label="Thomson Reuters">
      {dots.map(([cx, cy, r], i) => (
        <circle key={i} cx={cx} cy={cy} r={r} fill="#FF6200" />
      ))}
      <text x="38" y="18" style={{fontFamily:"Arial, Helvetica, sans-serif", fontWeight:700, fontSize:14, fill:"#222222", letterSpacing:0.3}}>Thomson</text>
      <text x="38" y="34" style={{fontFamily:"Arial, Helvetica, sans-serif", fontWeight:700, fontSize:14, fill:"#222222", letterSpacing:0.3}}>Reuters<tspan fontSize="8" dy="-5" dx="1" fill="#555555">™</tspan></text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Root App
// ---------------------------------------------------------------------------
export default function App() {
  const [report, setReport] = useState<DatasetAssessmentReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>('overview');

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(`${API_BASE}/api/v1/reports/datasets/latest`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setReport((await res.json()) as DatasetAssessmentReport);
      } catch {
        // Backend unavailable — use built-in demo data so dashboard always works
        setReport(DEMO_REPORT);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const hardeningSummary = useMemo<HardeningSummary>(() => {
    if (report?.hardeningSummary) return report.hardeningSummary;
    const actions = [...(report?.topRiskyActions ?? []), ...(report?.topSafeActions ?? [])];
    const t1 = actions.filter((a) => (a.tier ?? (a.score >= 65 ? 1 : a.score >= 30 ? 2 : 3)) === 1).length;
    const t2 = actions.filter((a) => (a.tier ?? (a.score >= 65 ? 1 : a.score >= 30 ? 2 : 3)) === 2).length;
    const t3 = actions.filter((a) => (a.tier ?? (a.score >= 65 ? 1 : a.score >= 30 ? 2 : 3)) === 3).length;
    return {
      thirdPartyBlocked: t1,
      thirdPartyAllowed: t2 + t3,
      thirdPartyTotal: actions.length,
      secretLeaksFound: DEMO_SECRETS.filter((s) => s.confirmed).length,
      maliciousPatterns: DEMO_SECRETS.filter((s) => s.severity === 'critical').length,
      networkViolations: DEMO_NETWORK.filter((n) => n.blocked || !n.viaZscaler).length,
      secretsOverdue: DEMO_ROTATION.filter((r) => r.status === 'overdue').length,
      secretsDue: DEMO_ROTATION.filter((r) => r.status === 'due').length,
      secretsOk: DEMO_ROTATION.filter((r) => r.status === 'ok').length,
      tier1Count: t1,
      tier2Count: t2,
      tier3Count: t3,
    };
  }, [report]);

  const secrets = report?.secretFindings?.length ? report.secretFindings : DEMO_SECRETS;
  const network = report?.networkFindings?.length ? report.networkFindings : DEMO_NETWORK;
  const rotation = report?.rotationStatus?.length ? report.rotationStatus : DEMO_ROTATION;

  if (loading) return <div className="shell center"><div className="loading-msg">Scanning GitHub Actions…</div></div>;

  if (!report) return null;

  const tabs: { id: Tab; label: string }[] = [
    { id: 'overview',  label: 'Overview' },
    { id: 'hardening', label: 'Actions Hardening' },
    { id: 'secrets',   label: 'Secret Scanning' },
    { id: 'network',   label: 'Network & Rotation' },
    { id: 'analyse',   label: 'Analyse Input' },
  ];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div>
          <div className="sidebar-logo-wrap">
            <TRLogo />
          </div>
          <h1>ActionTrust</h1>
          <p className="muted sidebar-desc">GitHub Actions security hardening — tier-based classification, secret scanning, network policy, and credential rotation.</p>
        </div>

        <div className="sidebar-block">
          <label className="field-label">Security tiers</label>
          <div className="sidebar-tiers">
            <div className="sidebar-tier sidebar-tier--1">
              <span className="sidebar-tier__num">{hardeningSummary.tier1Count}</span>
              <span>Tier 1 Block</span>
            </div>
            <div className="sidebar-tier sidebar-tier--2">
              <span className="sidebar-tier__num">{hardeningSummary.tier2Count}</span>
              <span>Tier 2 Review</span>
            </div>
            <div className="sidebar-tier sidebar-tier--3">
              <span className="sidebar-tier__num">{hardeningSummary.tier3Count}</span>
              <span>Tier 3 Approve</span>
            </div>
          </div>
        </div>

        <div className="sidebar-block">
          <label className="field-label">Quick stats</label>
          <div className="kv-list">
            <div className="kv-row"><span>Secret leaks</span><strong className="kv-bad">{hardeningSummary.secretLeaksFound}</strong></div>
            <div className="kv-row"><span>Network violations</span><strong className="kv-bad">{hardeningSummary.networkViolations}</strong></div>
            <div className="kv-row"><span>Secrets overdue</span><strong className="kv-bad">{hardeningSummary.secretsOverdue}</strong></div>
            <div className="kv-row"><span>Analyst min. saved</span><strong className="kv-ok">{report.summary.estimatedAnalystMinutes}</strong></div>
          </div>
        </div>

        <div className="sidebar-block">
          <label className="field-label">Last scanned</label>
          <div className="muted small">{new Date(report.generatedAt).toLocaleString()}</div>
          <div className="muted small">{report.datasetPath}</div>
        </div>
      </aside>

      <main className="content">
        <nav className="tab-nav">
          {tabs.map((t) => (
            <button key={t.id} className={`tab-btn${tab === t.id ? ' tab-btn--active' : ''}${t.id === 'analyse' ? ' tab-btn--analyse' : ''}`} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>

        {tab === 'overview'  && <OverviewTab report={report} hs={hardeningSummary} />}
        {tab === 'hardening' && <HardeningTab report={report} hs={hardeningSummary} />}
        {tab === 'secrets'   && <SecretsTab secrets={secrets} hs={hardeningSummary} />}
        {tab === 'network'   && <NetworkRotationTab network={network} rotation={rotation} hs={hardeningSummary} />}
        {tab === 'analyse'   && <AnalyseTab />}
      </main>
    </div>
  );
}
