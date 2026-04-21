import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { EmptyState } from "./EmptyState";

test("renders default message", () => {
  render(<EmptyState />);
  expect(screen.getByText(/nenhuma coleta realizada/i)).toBeInTheDocument();
});

test("renders loading state", () => {
  render(<EmptyState loading={true} />);
  expect(screen.getByText(/coletando/i)).toBeInTheDocument();
});

test("button is disabled when loading", () => {
  render(<EmptyState loading={true} />);
  expect(screen.getByRole("button")).toBeDisabled();
});