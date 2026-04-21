import { render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import { PerformancePage } from "./PerformancePage";

test("renders performance page with audit", async () => {
  const mockAudit = {
    result: {
      scores: { performance: 75 },
      summary: {},
      findings: [],
    },
  };
  render(<PerformancePage audit={mockAudit} />);
  await waitFor(() => {
    expect(screen.getAllByText("75")).toHaveLength(3);
  });
});

test("renders score display", async () => {
  const mockAudit = {
    result: {
      scores: { performance: 90 },
      summary: { top_processes: [], disk_pressure_mounts: [] },
      findings: [],
    },
  };
  render(<PerformancePage audit={mockAudit} />);
  expect(screen.getByText("Score de performance")).toBeInTheDocument();
});