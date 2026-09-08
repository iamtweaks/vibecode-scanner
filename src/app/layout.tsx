import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'VibeChecker - Free Vibe Coding Security Scanner',
  description: 'Free security scanner for vibe-coded apps. Find critical vulnerabilities before they become breaches.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={inter.className}>
      <body className="min-h-screen bg-kanagawa-bg text-kanagawa-fg antialiased">
        {children}
        <Analytics />
      </body>
    </html>
  )
}