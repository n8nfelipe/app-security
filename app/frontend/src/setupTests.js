import "@testing-library/jest-dom";

import { vi } from "vitest";
import * as ReactRouter from "react-router-dom";

export const mockNavigate = vi.fn();
export const mockParams = {};
export const mockLocation = { pathname: "/", search: "", hash: "" };

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => mockParams,
    useLocation: () => mockLocation,
    MemoryRouter: ({ children }) => children,
    Routes: ({ children }) => children,
    Route: ({ children }) => children,
    NavLink: ({ children }) => children,
  };
});

beforeEach(() => {
  vi.clearAllMocks();
});