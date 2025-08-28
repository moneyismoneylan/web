import type { ReactNode } from 'react';
import { Inter } from 'next/font/google';
import '../styles/globals.css';
import { Providers } from './providers';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'CyberScan Dashboard',
  description: 'Security tools platform',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  const year = new Date().getFullYear();
  return (
    <html lang="en">
      <body
        className={`${inter.className} bg-gradient-to-br from-gray-900 via-gray-800 to-black text-gray-100 min-h-screen flex flex-col`}
      >
        <header className="bg-gray-900/80 border-b border-gray-700 backdrop-blur">
          <div className="max-w-6xl mx-auto px-4 py-4">
            <span className="text-2xl font-bold tracking-wide">CyberScan</span>
          </div>
        </header>
        <Providers>
          <main className="flex-1 max-w-6xl w-full mx-auto p-6">{children}</main>
        </Providers>
        <footer className="bg-gray-900/80 border-t border-gray-700 text-center py-4 text-sm">
          © {year} CyberScan Dashboard
        </footer>
      </body>
    </html>
  );
}
