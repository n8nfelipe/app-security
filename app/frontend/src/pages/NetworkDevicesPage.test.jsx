import { render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import { NetworkDevicesPage } from "./NetworkDevicesPage";
import { api } from "../lib/api";

vi.mock("../lib/api", () => ({
  api: {
    listNetworkDevices: vi.fn(),
  },
}));

test("shows loading state", async () => {
  vi.mocked(api.listNetworkDevices).mockImplementation(() => new Promise(() => {}));
  render(<NetworkDevicesPage />);
  expect(screen.getByText(/carregando/i)).toBeInTheDocument();
});

test("shows empty state", async () => {
  vi.mocked(api.listNetworkDevices).mockResolvedValue({ devices: [], total: 0 });
  render(<NetworkDevicesPage />);
  await waitFor(() => {
    expect(screen.getByText(/nenhum dispositivo/i)).toBeInTheDocument();
  });
});

test("renders devices list", async () => {
  vi.mocked(api.listNetworkDevices).mockResolvedValue({
    devices: [{ ip: "192.168.1.1", mac: "00:11:22:33:44:55" }],
    total: 1,
  });
  render(<NetworkDevicesPage />);
  await waitFor(() => {
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
  });
});

test("renders mac address", async () => {
  vi.mocked(api.listNetworkDevices).mockResolvedValue({
    devices: [{ ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff" }],
    total: 1,
  });
  render(<NetworkDevicesPage />);
  await waitFor(() => {
    expect(screen.getByText("aa:bb:cc:dd:ee:ff")).toBeInTheDocument();
  });
});