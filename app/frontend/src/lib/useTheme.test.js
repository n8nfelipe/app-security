import { expect, test, vi, beforeEach } from "vitest";

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

import { renderHook, act } from "@testing-library/react";

import { useTheme } from "./useTheme";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});

test("returns theme by default", () => {
  const { result } = renderHook(() => useTheme());
  expect(result.current.theme).toBeDefined();
});

test("toggleTheme switches from light to dark", () => {
  const { result } = renderHook(() => useTheme());
  const initialTheme = result.current.theme;

  act(() => {
    result.current.toggleTheme();
  });

  expect(result.current.theme).not.toBe(initialTheme);
});

test("toggleTheme switches back", () => {
  const { result } = renderHook(() => useTheme());
  const initialTheme = result.current.theme;

  act(() => {
    result.current.toggleTheme();
  });
  act(() => {
    result.current.toggleTheme();
  });

  expect(result.current.theme).toBe(initialTheme);
});

test("sets theme in localStorage", () => {
  const { result } = renderHook(() => useTheme());

  act(() => {
    result.current.toggleTheme();
  });

  const newTheme = result.current.theme;
  expect(localStorage.getItem("app-security-theme")).toBe(newTheme);
});