import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { ProcessChart } from "./ProcessChart";

const emptyProcesses = [];

test("renders with processes", () => {
  const processes = [{ pid: 123, command: "nginx", cpu_percent: 10, memory_percent: 5 }];
  render(<ProcessChart processes={processes} />);
  expect(screen.getByText("nginx")).toBeInTheDocument();
});

test("handles empty array", () => {
  render(<ProcessChart processes={emptyProcesses} />);
});

test("renders pid information", () => {
  const processes = [{ pid: 123, command: "nginx", cpu_percent: 10, memory_percent: 5 }];
  render(<ProcessChart processes={processes} />);
  expect(screen.getByText(/123/)).toBeInTheDocument();
});

test("renders memory percentage", () => {
  const processes = [{ pid: 123, command: "nginx", cpu_percent: 10, memory_percent: 5 }];
  render(<ProcessChart processes={processes} />);
  expect(screen.getByText(/5/)).toBeInTheDocument();
});