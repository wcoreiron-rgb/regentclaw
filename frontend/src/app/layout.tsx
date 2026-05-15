import type { Metadata } from 'next';
import './globals.css';
import Sidebar from '@/components/Sidebar';
import { ThemeProvider } from '@/components/ThemeProvider';

export const metadata: Metadata = {
  title: 'RegentClaw — Zero Trust Security Ecosystem',
  description: 'Modular, governed security ecosystem with Zero Trust enforcement',
  icons: {
    icon: [
      { url: '/favicon.png', type: 'image/png', sizes: '512x512' },
    ],
    shortcut: '/favicon.png',
    apple: '/favicon.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="icon"             type="image/png" sizes="512x512" href="/favicon.png" />
        <link rel="icon"             type="image/png" sizes="192x192" href="/favicon.png" />
        <link rel="icon"             type="image/png" sizes="64x64"   href="/favicon.png" />
        <link rel="icon"             type="image/png" sizes="32x32"   href="/favicon.png" />
        <link rel="shortcut icon"    type="image/png"                 href="/favicon.png" />
        <link rel="apple-touch-icon" sizes="180x180"                  href="/favicon.png" />
      </head>
      <body className="min-h-screen" style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-1)' }}>
        <ThemeProvider>
          <div className="flex min-h-screen">
            <Sidebar />
            <main className="flex-1 overflow-auto p-8">
              {children}
            </main>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
