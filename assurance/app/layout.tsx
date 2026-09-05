import type { Metadata } from "next";
import "./globals.css";
import "./beacon.css";
import "./marketing.css";

export const metadata: Metadata = {
  title: "Beacon | Evidence you can stand behind",
  description: "A connected workspace for evidence, continuous validation, assessment, and trust.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
