import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { FindingsTable } from "./FindingsTable";

test("shows finding row", () => {
  render(
    <FindingsTable
      findings={[
        {
          id: 1,
          check_id: "sec_test",
          domain: "security",
          severity: "HIGH",
          title: "Teste",
          rationale: "Explica",
          evidence: "Evidencia",
          recommendation: "Acao",
        },
      ]}
    />,
  );
  expect(screen.getByText("Teste")).toBeInTheDocument();
  expect(screen.getByText("Evidencia")).toBeInTheDocument();
});
