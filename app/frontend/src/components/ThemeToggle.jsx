export function ThemeToggle({ theme, onToggle }) {
  return (
    <button className="theme-toggle" onClick={onToggle} type="button" aria-label="Alternar tema">
      <span className={`theme-toggle-track ${theme === "light" ? "light" : "dark"}`}>
        <span className="theme-toggle-thumb" />
      </span>
      <span>{theme === "dark" ? "Dark mode" : "Light mode"}</span>
    </button>
  );
}
