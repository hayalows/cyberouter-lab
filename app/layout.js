import "./globals.css";

export const metadata = {
  title: "Cyberouter Lab",
  description: "A private browser-side workspace and remote MCP bridge for Enclave Cyberouter.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
