import { expect, test } from "@playwright/test";

test("shows demo workspace and blocks external URL in Demo mode", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("RedCalibur Demo - AI Coding Stack")).toBeVisible();
  await expect(page.getByText("Mode: demo")).toBeVisible();
  await expect(page.getByText("Scope: configured")).toBeVisible();
  await page.getByRole("button", { name: "Preview Decision" }).click();
  await expect(page.getByRole("heading", { name: "blocked" })).toBeVisible();
  await expect(page.getByText("Demo mode blocks arbitrary network targets.")).toBeVisible();
  await expect(page.getByText(/redacted:/).first()).toBeVisible();
});

test("allows local fixture preview", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Target", { exact: true }).fill("fixtures/demo-ai-stack/package.json");
  await page.getByLabel("Target type").selectOption("local_path");
  await page.getByLabel("Risk tier").selectOption("1");
  await page.getByRole("button", { name: "Preview Decision" }).click();
  await expect(page.getByRole("heading", { name: "allowed" })).toBeVisible();
  await expect(page.getByText("Target is within declared scope and risk tier.")).toBeVisible();
});
