import "./globals.css";
import React from "react";
import HeaderNav from "./HeaderNav";

export const metadata = {
  title: "AI Agent Tool-Call Risk Detector",
  description: "Enterprise safety guardrail inspecting AI tool calls and stopping dangerous actions in real time.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full">
      <body className="h-full overflow-hidden bg-[#09090B] text-[#E4E4E7] flex flex-col font-sans selection:bg-[#27272A] selection:text-white">
        <HeaderNav />
        <main className="flex-1 overflow-hidden p-3 sm:p-4 max-w-[1600px] w-full mx-auto flex flex-col">
          {children}
        </main>
      </body>
    </html>
  );
}
