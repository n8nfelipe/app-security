import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";

import { ThemeToggle } from "./ThemeToggle";

test("renders with light theme", () => {
  const onToggle = vi.fn();
  render(<ThemeToggle theme="light" onToggle={onToggle} />);
  expect(screen.getByRole("button")).toBeInTheDocument();
});

test("renders with dark theme", () => {
  const onToggle = vi.fn();
  render(<ThemeToggle theme="dark" onToggle={onToggle} />);
  expect(screen.getByRole("button")).toBeInTheDocument();
});

test("button has correct aria-label", () => {
  const onToggle = vi.fn();
  render(<ThemeToggle theme="light" onToggle={onToggle} />);
  expect(screen.getByRole("button")).toHaveAttribute("aria-label", "Alternar tema");
});