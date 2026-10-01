import "./globals.css";

export const metadata = {
  title: "Cyberouter Lab — Security Workbench",
  description: "Review GitHub code, pull requests, and bounded public website assessments with Cyberouter models.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
