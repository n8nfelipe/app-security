import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { RecommendationList } from "./RecommendationList";

test("renders multiple recommendations", () => {
  const recs = [
    { id: "1", title: "Rec 1", action: "Action 1" },
    { id: "2", title: "Rec 2", action: "Action 2" },
  ];
  render(<RecommendationList recommendations={recs} />);
  expect(screen.getByText("Rec 1")).toBeInTheDocument();
  expect(screen.getByText("Rec 2")).toBeInTheDocument();
});

test("renders with priority", () => {
  const recs = [
    { id: "1", title: "High Priority", priority: "HIGH" },
    { id: "2", title: "Low Priority", priority: "LOW" },
  ];
  render(<RecommendationList recommendations={recs} />);
  expect(screen.getByText("High Priority")).toBeInTheDocument();
});

test("renders action text", () => {
  const recs = [
    { id: "1", title: "Rec", action: "Configure firewall" },
  ];
  render(<RecommendationList recommendations={recs} />);
  expect(screen.getByText("Configure firewall")).toBeInTheDocument();
});