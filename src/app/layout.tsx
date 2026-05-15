import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const site = new URL("https://cloakbuster.com");

export const metadata: Metadata = {
  metadataBase: site,
  title: {
    default: "Cloakbuster — free webpage security scanner",
    template: "%s · Cloakbuster",
  },
  description:
    "Scan any public URL for cloaked links, hidden injections, suspicious scripts, and other compromise signals — server-side fetch plus optional headless rendering.",
  openGraph: {
    type: "website",
    url: site,
    siteName: "Cloakbuster",
    title: "Cloakbuster",
    description:
      "Bust cloaked hacks and parasite-style injections on webpages you control.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="scroll-smooth">
      <body
        className={`${geistSans.variable} ${geistMono.variable} min-h-screen bg-background font-sans text-foreground antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
