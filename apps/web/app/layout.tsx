import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
  title: "RedCalibur 2.0",
  description: "AI security and developer exposure workbench",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

