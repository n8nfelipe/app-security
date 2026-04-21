import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { ChartCard } from "./ChartCard";

test("renders title", () => {
  render(<ChartCard title="Test Chart"><div>content</div></ChartCard>);
  expect(screen.getByText("Test Chart")).toBeInTheDocument();
});

test("renders children", () => {
  render(<ChartCard title="Chart"><span>chart data</span></ChartCard>);
  expect(screen.getByText("chart data")).toBeInTheDocument();
});