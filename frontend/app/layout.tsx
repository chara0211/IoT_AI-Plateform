import "./globals.css";
import Link from "next/link";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <nav className="bg-black text-white px-6 py-3 flex gap-6">
          <Link href="/">Home</Link>
          <Link href="/dashboard">Dashboard</Link>
        </nav>
        {children}
      </body>
    </html>
  );
}
