import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Next.js RAG with InfraLayer',
  description: 'RAG application with pre-LLM security filtering',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
