import { render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import { RecommendationsPage } from "./RecommendationsPage";

vi.mock("../lib/api", () => ({
  api: {
    history: vi.fn().mockResolvedValue({ items: [] }),
    listNetworkDevices: vi.fn().mockResolvedValue({ devices: [], total: 0 }),
    listContainers: vi.fn().mockResolvedValue({ containers: [], total: 0 }),
  },
}));

test("renders with recommendations", async () => {
  const mockAudit = {
    result: {
      recommendations: [{ id: "1", title: "Fix" }],
    },
  };
  render(<RecommendationsPage audit={mockAudit} />);
  await waitFor(() => {
    expect(screen.getByText("Fix")).toBeInTheDocument();
  });
});