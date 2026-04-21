import { render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import { UsersPage } from "./UsersPage";
import { api } from "../lib/api";

vi.mock("../lib/api", () => ({
  api: {
    listUsers: vi.fn(),
  },
}));

test("shows loading state", () => {
  vi.mocked(api.listUsers).mockImplementation(() => new Promise(() => {}));
  render(<UsersPage />);
  expect(screen.getByText(/carregando/i)).toBeInTheDocument();
});

test("shows error state", async () => {
  vi.mocked(api.listUsers).mockRejectedValue(new Error("Falha na API"));
  render(<UsersPage />);
  await waitFor(() => {
    expect(screen.getByText("Falha na API")).toBeInTheDocument();
  });
});

test("shows empty state", async () => {
  vi.mocked(api.listUsers).mockResolvedValue({ total: 0, human_users: 0, users: [] });
  render(<UsersPage />);
  await waitFor(() => {
    expect(screen.getByText(/nenhum usuario/i)).toBeInTheDocument();
  });
});

test("renders users table with data", async () => {
  vi.mocked(api.listUsers).mockResolvedValue({
    total: 2,
    human_users: 1,
    users: [
      { username: "admin", uid: 1000, gid: 1000, home: "/home/admin", shell: "/bin/bash" },
      { username: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/bash" },
    ],
  });
  render(<UsersPage />);
  await waitFor(() => {
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
  });
});

test("displays total count", async () => {
  vi.mocked(api.listUsers).mockResolvedValue({
    total: 5,
    human_users: 3,
    users: [],
  });
  render(<UsersPage />);
  await waitFor(() => {
    expect(screen.getByText("5")).toBeInTheDocument();
  });
});