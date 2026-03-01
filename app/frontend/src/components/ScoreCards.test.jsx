import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { ScoreCards } from "./ScoreCards";

test("renders score values", () => {
  render(<ScoreCards scores={{ overall: 88, security: 92, performance: 81 }} />);
  expect(screen.getByText("88")).toBeInTheDocument();
  expect(screen.getByText("92")).toBeInTheDocument();
  expect(screen.getByText("81")).toBeInTheDocument();
});
