import { render } from "@testing-library/react";
import { expect, test } from "vitest";

import { ScoreCards } from "./ScoreCards";

test("renders scores object", () => {
  const scores = { overall: 85, security: 90, performance: 75 };
  expect(() => render(<ScoreCards scores={scores} />)).not.toThrow();
});

test("renders null scores", () => {
  expect(() => render(<ScoreCards scores={null} />)).not.toThrow();
});

test("renders undefined scores", () => {
  expect(() => render(<ScoreCards />)).not.toThrow();
});