export function ChartCard({ title, subtitle, children, delay = 0, className = "" }) {
  return (
    <section className={`panel chart-panel reveal ${className}`.trim()} style={{ "--delay": `${delay}ms` }}>
      <div className="panel-header">
        <h2>{title}</h2>
        <p className="muted">{subtitle}</p>
      </div>
      {children}
    </section>
  );
}
