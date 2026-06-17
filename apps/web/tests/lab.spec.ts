import { expect, test } from "@playwright/test";

test("AI lab runs eval suites and verifies a finding", async ({ page }) => {
  await page.goto("/lab");
  await expect(page.getByRole("heading", { name: "AI Security Lab" })).toBeVisible();

  await page.getByRole("button", { name: /Run Eval Suites/ }).click();

  // The unhardened mock target trips all three categories.
  await expect(page.getByText("Prompt Injection", { exact: false }).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Unsafe Tool Use", { exact: false }).first()).toBeVisible();

  // Verify the first finding against a hardened target → becomes verified.
  await page.getByRole("button", { name: "Verify", exact: true }).first().click();
  await expect(page.getByText("Verified").first()).toBeVisible({ timeout: 15_000 });
});
