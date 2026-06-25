import { useEffect, useMemo, useState, type ReactNode } from 'react';
import type { DatasetAssessmentReport, RankedRisk, RiskLevel } from './types';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

const levelOrder: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const categoryLabels: Record<string, string> = {
  action: 'Action',
  repository: 'Repository',
  business_unit: 'Business unit',
  workflow_file: 'Workflow file',
  software_class: 'Software class',
};

function levelBadge(level: string) {
  return `badge badge-${level.toLowerCase()}`;
}

function formatScore(score: number) {
  return `${score}/100`;
}

function scoreWidth(score: number) {
  return `${Math.max(4, Math.min(100, score))}%`;
}

function normalizeText(value: string) {
  return value.trim().toLowerCase();
}

function matchesCategory(item: RankedRisk, category: string) {
  if (category === 'all') return true;
  if (category === 'safe') return item.score <= 20;
  if (category === 'risky') return item.score >= 50;
  if (category === 'critical') return item.level === 'critical';
  if (category === 'high') return item.level === 'high';
  return true;
}

function sortByRisk(a: RankedRisk, b: RankedRisk) {
  return (levelOrder[b.level] ?? 0) - (levelOrder[a.level] ?? 0) || b.score - a.score;
}

function riskSummary(items: RankedRisk[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  items.forEach((item) => {
    const key = item.level.toLowerCase() as RiskLevel;
    if (counts[key] !== undefined) counts[key] += 1;
  });
  return counts;
}

function Pill({ children }: { children: ReactNode }) {
  return <span className="pill">{children}</span>;
}

function StatCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint ? <div className="stat-hint">{hint}</div> : null}
    </div>
  );
}

function RiskCard({ item }: { item: RankedRisk }) {
  return (
    <article className="risk-card">
      <div className="risk-card__top">
        <div>
          <div className="risk-card__label">{categoryLabels[item.entityType] ?? item.entityType}</div>
          <h3>{item.entityId}</h3>
        </div>
        <div className={levelBadge(item.level)}>{item.level}</div>
      </div>

      <div className="progress-row">
        <div className="progress-meta">
          <span>Risk score</span>
          <strong>{formatScore(item.score)}</strong>
        </div>
        <div className="progress-track">
          <div className={`progress-bar progress-${item.level.toLowerCase()}`} style={{ width: scoreWidth(item.score) }} />
        </div>
      </div>

      <div className="chips">
        <Pill>{item.businessImpact} impact</Pill>
        <Pill>{item.quickChecks} quick checks</Pill>
        <Pill>{item.deepChecks} deep checks</Pill>
        <Pill>{item.estimatedApiCalls} est. API calls</Pill>
      </div>

      <div className="risk-section">
        <div className="section-title">Findings</div>
        <ul>
          {item.findings.length ? item.findings.map((finding) => <li key={finding}>{finding}</li>) : <li>No notable findings</li>}
        </ul>
      </div>

      <div className="risk-section">
        <div className="section-title">Recommendations</div>
        <ul>
          {item.recommendations.length ? item.recommendations.map((rec) => <li key={rec}>{rec}</li>) : <li>No recommendation</li>}
        </ul>
      </div>
    </article>
  );
}

export default function App() {
  const [report, setReport] = useState<DatasetAssessmentReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [selectedEntityType, setSelectedEntityType] = useState('all');

  useEffect(() => {
    async function load() {
      try {
        const response = await fetch(`${API_BASE}/api/v1/reports/datasets/latest`);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const data = (await response.json()) as DatasetAssessmentReport;
        setReport(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to load report');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const actions = useMemo(() => {
    if (!report) return [];
    const all = [...report.topRiskyActions, ...report.topSafeActions];
    return all
      .filter((item, idx, arr) => arr.findIndex((x) => x.entityId === item.entityId) === idx)
      .filter((item) => matchesCategory(item, category))
      .filter((item) => selectedEntityType === 'all' || item.entityType === selectedEntityType)
      .filter((item) => normalizeText(item.entityId).includes(normalizeText(query)) || item.findings.some((f) => normalizeText(f).includes(normalizeText(query))) || item.recommendations.some((r) => normalizeText(r).includes(normalizeText(query))))
      .sort(sortByRisk);
  }, [report, category, query, selectedEntityType]);

  const topActions = useMemo(() => report?.topRiskyActions ?? [], [report]);
  const summaries = useMemo(() => (report ? riskSummary(report.topRiskyActions) : null), [report]);

  if (loading) {
    return <div className="shell center">Loading dashboard…</div>;
  }

  if (error || !report) {
    return (
      <div className="shell center">
        <div className="empty-state">
          <h1>ActionTrust Dashboard</h1>
          <p>Could not load the latest dataset report.</p>
          <p className="muted">{error ?? 'No report available'}</p>
          <p>Run the backend batch assessment first, then refresh this page.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div>
          <div className="eyebrow">ActionTrust</div>
          <h1>Action categorization dashboard</h1>
          <p className="muted">A React dashboard for grouping actions by risk, source, usage, and business impact.</p>
        </div>

        <div className="sidebar-block">
          <label className="field-label">Search</label>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search actions, findings, or recommendations" />
        </div>

        <div className="sidebar-block">
          <label className="field-label">Category</label>
          <div className="segmented">
            {['all', 'risky', 'critical', 'high', 'safe'].map((item) => (
              <button key={item} className={category === item ? 'segment active' : 'segment'} onClick={() => setCategory(item)}>
                {item}
              </button>
            ))}
          </div>
        </div>

        <div className="sidebar-block">
          <label className="field-label">Entity type</label>
          <select value={selectedEntityType} onChange={(e) => setSelectedEntityType(e.target.value)}>
            <option value="all">All</option>
            <option value="action">Action</option>
            <option value="workflow_file">Workflow file</option>
            <option value="repository">Repository</option>
            <option value="business_unit">Business unit</option>
            <option value="software_class">Software class</option>
          </select>
        </div>

        <div className="sidebar-block">
          <label className="field-label">Top counts</label>
          <div className="mini-grid">
            <StatCard label="Critical" value={summaries?.critical ?? 0} />
            <StatCard label="High" value={summaries?.high ?? 0} />
            <StatCard label="Medium" value={summaries?.medium ?? 0} />
            <StatCard label="Low" value={summaries?.low ?? 0} />
          </div>
        </div>
      </aside>

      <main className="content">
        <section className="hero">
          <div>
            <div className="eyebrow">Latest dataset assessment</div>
            <h2>Prioritize GitHub Actions by risk category</h2>
            <p>
              Built from raw usage rows and aggregate datasets. This highlights top-risk actions, workflow files, repositories, business units, and software classes.
            </p>
          </div>
          <div className="hero-card">
            <div className="hero-score">{report.summary.totalActionUses.toLocaleString()}</div>
            <div className="muted">Total action uses analyzed</div>
          </div>
        </section>

        <section className="stats-grid">
          <StatCard label="Distinct actions" value={report.summary.distinctActions.toLocaleString()} />
          <StatCard label="Repos using actions" value={report.summary.reposUsingActions.toLocaleString()} />
          <StatCard label="Workflow files" value={report.summary.workflowFilesWithActions.toLocaleString()} />
          <StatCard label="High/Critical actions" value={report.summary.highOrCriticalActions.toLocaleString()} />
          <StatCard label="High/Critical repos" value={report.summary.highOrCriticalRepos.toLocaleString()} />
          <StatCard label="Analyst minutes saved" value={report.summary.estimatedAnalystMinutes.toLocaleString()} />
        </section>

        <section className="panel">
          <div className="panel-header">
            <h3>Top risky actions</h3>
            <span className="muted">Sorted by score</span>
          </div>
          <div className="risk-list">
            {topActions.slice(0, 5).map((item) => (
              <RiskCard key={item.entityId} item={item} />
            ))}
          </div>
        </section>

        <section className="panel two-col">
          <div>
            <div className="panel-header">
              <h3>Filtered action catalog</h3>
              <span className="muted">{actions.length} matches</span>
            </div>
            <div className="risk-list compact">
              {actions.slice(0, 8).map((item) => (
                <RiskCard key={item.entityId} item={item} />
              ))}
            </div>
          </div>

          <div className="stack">
            <div className="panel-inner">
              <h3>Top recommendations</h3>
              <ol>
                {report.prioritizedRecommendations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ol>
            </div>
            <div className="panel-inner">
              <h3>Operational policy</h3>
              {report.operationalProcess.map((policy) => (
                <div key={policy.decision} className="policy-card">
                  <strong>{policy.decision}</strong>
                  <div className="muted">Reassess: {policy.reassessment}</div>
                  <ul>
                    {policy.criteria.map((criterion) => (
                      <li key={criterion}>{criterion}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h3>Dataset coverage</h3>
            <span className="muted">{report.datasetPath}</span>
          </div>
          <div className="coverage-grid">
            <StatCard label="Risk model" value="Explainable" hint={report.riskModel.formula} />
            <StatCard label="API calls est." value={report.summary.estimatedApiCalls.toLocaleString()} />
            <StatCard label="LLM tokens est." value={report.summary.estimatedLlmTokens.toLocaleString()} />
            <StatCard label="Runtime est." value={`${report.summary.estimatedRuntimeMs.toLocaleString()} ms`} />
          </div>
        </section>
      </main>
    </div>
  );
}
