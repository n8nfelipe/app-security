import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { ScoreTrendChart } from "./ScoreTrendChart";

test("renders with scores object", () => {
  render(<ScoreTrendChart scores={{ overall: 85 }} />);
  expect(screen.getByText("85")).toBeInTheDocument();
});

test("renders with empty scores", () => {
  render(<ScoreTrendChart scores={{}} />);
  expect(screen.getAllByText("0")).toHaveLength(3);
});

test("renders with custom rows", () => {
  render(
    <ScoreTrendChart
      scores={{}}
      rows={[
        { label: "Custom", value: 75, color: "blue" },
      ]}
    />
  );
  expect(screen.getByText("Custom")).toBeInTheDocument();
  expect(screen.getByText("75")).toBeInTheDocument();
});