export interface BenignFixture {
  id: string;
  description: string;
  sourceUrl: string;
  content: string;
  expectedPreservedPhrases: string[];
}

export const BENIGN_DOC_CORPUS: readonly BenignFixture[] = [
  {
    id: 'benign-01-typescript-docs',
    description: 'TypeScript Handbook style documentation with code, anchors, and responsive CSS',
    sourceUrl: 'https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#the-primitives',
    content: `
      <!doctype html>
      <html>
        <head>
          <style>
            @media (max-width: 768px) { .mobile-drawer { display: none; } }
            .btn-primary { background: #1d4ed8; }
          </style>
        </head>
        <body>
          <!-- Main documentation header -->
          <header class="mobile-drawer">
            <button style="color: white">Toggle Navigation</button>
          </header>
          <main>
            <h1>Everyday Types</h1>
            <p>TypeScript checks types at compile time and supports primitives like string, number, and boolean.</p>
            <p>Use <a href="https://www.typescriptlang.org/docs/#getting-started">Getting Started</a> to learn how the compiler resolves modules and system configuration files.</p>
            <pre><code>function greet(name: string): string {
  return "Hello, " + name;
}</code></pre>
            <svg width="16" height="16" viewBox="0 0 16 16"><path d="M2 2h12v12H2z"/></svg>
          </main>
        </body>
      </html>
    `,
    expectedPreservedPhrases: [
      'Everyday Types',
      'Toggle Navigation',
      'TypeScript checks types at compile time',
      'function greet(name: string): string',
    ],
  },
  {
    id: 'benign-02-mdn-fetch-docs',
    description: 'MDN style Fetch API reference mentioning fetch, headers, and ignore-cache options',
    sourceUrl: 'https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#supplying_request_options',
    content: `
      <article>
        <h1>Using the Fetch API</h1>
        <p>The Fetch API provides a JavaScript interface for making HTTP requests using fetch().</p>
        <p>You can configure cache directives, system headers, and CORS mode, or instruct the browser to ignore cached responses via cache: "no-store".</p>
        <p>Always validate user input on the server and escape untrusted HTML before rendering.</p>
      </article>
    `,
    expectedPreservedPhrases: [
      'Using the Fetch API',
      'making HTTP requests using fetch()',
      'cache: "no-store"',
    ],
  },
  {
    id: 'benign-03-markdown-guide',
    description: 'Clean Markdown API guide with standard image and code fence',
    sourceUrl: 'https://yours.sh/docs/getting-started#installation',
    content: `# Getting Started with @yours/guard

Install the package with npm:

\`\`\`bash
npm install @yours/guard
\`\`\`

See the [architecture diagram](https://yours.sh/docs/architecture#overview) or view ![Architecture Preview](https://yours.sh/assets/diagram.png).`,
    expectedPreservedPhrases: [
      'Getting Started with @yours/guard',
      'npm install @yours/guard',
    ],
  },
  {
    id: 'benign-04-math-comparisons',
    description: 'Page containing < and > angle operators in mathematical prose',
    sourceUrl: 'https://en.wikipedia.org/wiki/Inequality_(mathematics)#Properties',
    content:
      '<p>If a < b and b < c, then by transitivity a < c. When x > 0, the function is strictly increasing.</p>',
    expectedPreservedPhrases: ['a < b', 'x > 0'],
  },
];
