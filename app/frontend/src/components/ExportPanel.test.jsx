import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { ExportPanel } from "./ExportPanel";

test("renders export buttons", () => {
  const onExportJson = vi.fn();
  const onExportPdf = vi.fn();
  render(<ExportPanel onExportJson={onExportJson} onExportPdf={onExportPdf} disabled={false} />);
  expect(screen.getByText(/exportar json/i)).toBeInTheDocument();
  expect(screen.getByText(/exportar pdf/i)).toBeInTheDocument();
});

test("buttons disabled when prop disabled", () => {
  const onExportJson = vi.fn();
  const onExportPdf = vi.fn();
  render(<ExportPanel onExportJson={onExportJson} onExportPdf={onExportPdf} disabled={true} />);
  expect(screen.getAllByRole("button")[0]).toBeDisabled();
});