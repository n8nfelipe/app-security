export function ScoreCards({ scores }) {
  const cards = [
    { label: "Geral", value: scores?.overall ?? "--", accent: "sun" },
    { label: "Seguranca", value: scores?.security ?? "--", accent: "forest" },
    { label: "Performance", value: scores?.performance ?? "--", accent: "ocean" },
  ];

  return (
    <section className="cards-grid">
      {cards.map((card) => (
        <article key={card.label} className={`score-card ${card.accent}`}>
          <span>{card.label}</span>
          <strong>{card.value}</strong>
        </article>
      ))}
    </section>
  );
}
