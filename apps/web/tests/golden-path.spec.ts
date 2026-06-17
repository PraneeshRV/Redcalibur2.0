import { expect, test } from "@playwright/test";

test("golden path: run baseline, see findings, ask analyst", async ({ page }) => {
  await page.goto("/findings");
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();

  // Run a baseline assessment (blocking) and wait for findings to populate.
  await page.getByRole("button", { name: /Run Baseline/ }).click();

  // The demo's vulnerable npm package should surface as a finding.
  await expect(page.getByText("demo-vulnerable-package").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/OSV-DEMO-/).first()).toBeVisible();

  // Ask the AI analyst what to fix first; expect a cited answer.
  await page.getByRole("button", { name: "What should I fix first?" }).click();
  await expect(page.getByText(/cites \d+ evidence item/).first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/Provider: mock/)).toBeVisible();
});
