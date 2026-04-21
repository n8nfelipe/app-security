import { renderHook, act, waitFor } from "@testing-library/react";
import { expect, test, vi, beforeEach } from "vitest";

import { useAuditData } from "./useAuditData";

vi.mock("./api", () => ({
  api: {
    history: vi.fn().mockResolvedValue({ items: [] }),
    createScan: vi.fn().mockResolvedValue({ scan_id: "scan-123" }),
    scanStatus: vi.fn().mockResolvedValue({ status: "completed" }),
    scanResults: vi.fn().mockResolvedValue({ machine_hostname: "test-host" }),
    exportJson: vi.fn().mockResolvedValue({ payload: {}, file_name: "test.json" }),
    exportPdf: vi.fn().mockResolvedValue(new Blob()),
  },
}));

import { api } from "./api";

beforeEach(() => {
  vi.clearAllMocks();
});

test("initializes with empty result", () => {
  const { result } = renderHook(() => useAuditData());
  expect(result.current.result).toBeNull();
  expect(result.current.loading).toBe(false);
});

test("startScan sets loading state", async () => {
  const { result } = renderHook(() => useAuditData());

  act(() => {
    result.current.startScan();
  });

  expect(result.current.loading).toBe(true);
});

test("startScan completes and sets result", async () => {
  const { result } = renderHook(() => useAuditData());

  await act(async () => {
    await result.current.startScan();
  });

  expect(result.current.result).toEqual({ machine_hostname: "test-host" });
  expect(result.current.loading).toBe(false);
});

test("exportJson returns early if no result", async () => {
  const { result } = renderHook(() => useAuditData());

  await act(async () => {
    await result.current.exportJson();
  });

  expect(api.exportJson).not.toHaveBeenCalled();
});

test("exportPdf returns early if no result", async () => {
  const { result } = renderHook(() => useAuditData());

  await act(async () => {
    await result.current.exportPdf();
  });

  expect(api.exportPdf).not.toHaveBeenCalled();
});