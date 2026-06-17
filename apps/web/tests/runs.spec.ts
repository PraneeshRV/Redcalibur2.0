import { expect, test } from "@playwright/test";

test("runs a baseline assessment and shows multi-job evidence", async ({ page }) => {
  await page.goto("/runs");
  await expect(page.getByRole("heading", { name: "Runs", exact: true })).toBeVisible();

  await page.getByRole("button", { name: /Start Baseline Assessment/ }).click();

  // The run reaches a terminal state via live polling.
  await expect(page.getByText(/Status: (complete|failed)/)).toBeVisible({ timeout: 30_000 });

  // Baseline fans out into the four developer-surface jobs.
  await expect(page.getByText("manifest_scan", { exact: true })).toBeVisible();
  await expect(page.getByText("secrets_baseline", { exact: true })).toBeVisible();

  // The run appears in history.
  await expect(page.getByText("baseline").first()).toBeVisible();
});
