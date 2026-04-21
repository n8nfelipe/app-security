import { render } from "@testing-library/react";
import { expect, test } from "vitest";

import { FindingsTable } from "./FindingsTable";

test("renders with empty array", () => {
  expect(() => render(<FindingsTable findings={[]} />)).not.toThrow();
});

test("renders with valid array", () => {
  const findings = [{ id: "1", severity: "HIGH", title: "Test" }];
  expect(() => render(<FindingsTable findings={findings} />)).not.toThrow();
});