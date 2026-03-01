export function ExportPanel({ onExportJson, onExportPdf, disabled }) {
  return (
    <div className="export-panel">
      <p className="eyebrow">Relatorio</p>
      <button className="secondary-button" onClick={onExportJson} disabled={disabled}>
        Exportar JSON
      </button>
      <button className="secondary-button" onClick={onExportPdf} disabled={disabled}>
        Exportar PDF
      </button>
    </div>
  );
}
