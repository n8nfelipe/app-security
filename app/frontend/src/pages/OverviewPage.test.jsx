import { vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";

import { OverviewPage } from "./OverviewPage";

vi.mock("../lib/api", () => ({
  api: {
    history: vi.fn().mockResolvedValue({ items: [] }),
    listNetworkDevices: vi.fn().mockResolvedValue({ devices: [], total: 5 }),
    listContainers: vi.fn().mockResolvedValue({ containers: [], total: 2 }),
  },
}));

test("renders overview page with data", async () => {
  const mockAudit = {
    result: {
      scores: { overall: 85, security: 90, performance: 80 },
      summary: {},
      history: [],
      findings: [],
      processes: [],
    },
  };
  render(<OverviewPage audit={mockAudit} />);
  await waitFor(() => {
    expect(screen.getByText("Painel operacional")).toBeInTheDocument();
  });
});

test("renders performance metric", async () => {
  const mockAudit = {
    result: {
      scores: { overall: 85, security: 90, performance: 80 },
      summary: {},
      history: [],
      findings: [],
      processes: [],
    },
  };
  render(<OverviewPage audit={mockAudit} />);
  await waitFor(() => {
    expect(screen.getAllByText("Performance")[0]).toBeInTheDocument();
  });
});

test("renders security section", async () => {
  const mockAudit = {
    result: {
      scores: { overall: 70, security: 85, performance: 65 },
      summary: {},
      history: [],
      findings: [],
      processes: [],
    },
  };
  render(<OverviewPage audit={mockAudit} />);
  await waitFor(() => {
    expect(screen.getAllByText("Seguranca")[0]).toBeInTheDocument();
  });
});

test("renders findings section", async () => {
  const mockAudit = {
    result: {
      scores: { overall: 80 },
      summary: {},
      history: [],
      findings: [{ id: "1", title: "Test", severity: "high" }],
      processes: [],
    },
  };
  render(<OverviewPage audit={mockAudit} />);
  await waitFor(() => {
    expect(screen.getByText("Investigation Board")).toBeInTheDocument();
  });
});