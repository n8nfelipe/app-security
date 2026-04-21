import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";

import { ContainersPage } from "./ContainersPage";
import { api } from "../lib/api";

vi.mock("../lib/api", () => ({
  api: {
    listContainers: vi.fn(),
  },
}));

test("shows loading state", () => {
  api.listContainers.mockImplementation(() => new Promise(() => {}));
  render(<ContainersPage />);
  expect(screen.getByText("Carregando containers…")).toBeInTheDocument();
});

test("shows error state", async () => {
  api.listContainers.mockRejectedValue(new Error("Docker offline"));
  render(<ContainersPage />);
  await waitFor(() => {
    expect(screen.getByText("Docker offline")).toBeInTheDocument();
  });
});

test("shows empty state", async () => {
  api.listContainers.mockResolvedValue({ containers: [] });
  render(<ContainersPage />);
  await waitFor(() => {
    expect(screen.getByText("Nenhum container em execução.")).toBeInTheDocument();
  });
});

test("renders containers table", async () => {
  api.listContainers.mockResolvedValue({
    containers: [
      {
        id: "abc123def456",
        name: "nginx-web",
        image: "nginx:latest",
        status: "running",
        ports: null,
      },
    ],
  });
  render(<ContainersPage />);
  await waitFor(() => {
    expect(screen.getByText("nginx-web")).toBeInTheDocument();
    expect(screen.getByText("nginx:latest")).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
    expect(screen.getByText("abc123def456")).toBeInTheDocument();
  });
});

test("renders ports column", async () => {
  api.listContainers.mockResolvedValue({
    containers: [
      {
        id: "abc123",
        name: "redis",
        image: "redis:7",
        status: "running",
        ports: {
          "6379/tcp": [{ HostIp: "0.0.0.0", HostPort: "6379" }],
        },
      },
    ],
  });
  render(<ContainersPage />);
  await waitFor(() => {
    expect(screen.getByText(/6379\/tcp/)).toBeInTheDocument();
  });
});