/**
 * @license
 * Copyright Google LLC All Rights Reserved.
 *
 * Use of this source code is governed by an MIT-style license that can be
 * found in the LICENSE file at https://angular.dev/license
 */

import { autoCsp, hashScriptText } from './auto-csp';

describe('auto-csp', () => {
  it('should rewrite a single inline script', async () => {
    const result = await autoCsp(`
      <html>
        <head>
        </head>
        <body>
          <script>console.log('foo');</script>
          <div>Some text </div>
        </body>
      </html>
    `);

    expect(result).toContain(
      `<meta http-equiv="Content-Security-Policy" content="script-src 'strict-dynamic' ${hashScriptText("console.log('foo');")} https: 'unsafe-inline';object-src 'none';base-uri 'self';">`,
    );
  });

  it('should rewrite a single source script', async () => {
    const result = await autoCsp(`
      <html>
        <head>
        </head>
        <body>
          <script src="./main.js"></script>
          <div>Some text </div>
        </body>
      </html>
    `);

    expect(result).toContain(
      `<meta http-equiv="Content-Security-Policy" content="script-src 'strict-dynamic' 'sha256-cfa69N/DhgtxzDzIHo+IFj9KPigQLDJgb6ZGZa3g5Cs=' https: 'unsafe-inline';object-src 'none';base-uri 'self';">`,
    );
    expect(result).toContain(`var scripts = [['./main.js', undefined, false, false]];`);
  });

  it('should rewrite a single source script in place', async () => {
    const result = await autoCsp(`
      <html>
        <head>
        </head>
        <body>
          <div>Some text</div>
          <script src="./main.js"></script>
        </body>
      </html>
    `);

    expect(result).toContain(
      `<meta http-equiv="Content-Security-Policy" content="script-src 'strict-dynamic' 'sha256-cfa69N/DhgtxzDzIHo+IFj9KPigQLDJgb6ZGZa3g5Cs=' https: 'unsafe-inline';object-src 'none';base-uri 'self';">`,
    );
    // Our loader script appears after the HTML text content.
    expect(result).toMatch(
      /Some text<\/div>\s*<script>\s*var scripts = \[\['.\/main.js', undefined, false, false\]\];/,
    );
  });

  it('should rewrite a multiple source scripts with attributes', async () => {
    const result = await autoCsp(`
      <html>
        <head>
        </head>
        <body>
          <script src="./main1.js"></script>
          <script async src="./main2.js"></script>
          <script type="module" async defer src="./main3.js"></script>
          <script type="application/not-javascript" src="./main4.js"></script>
          <div>Some text </div>
        </body>
      </html>
    `);

    expect(result).toContain(
      `<meta http-equiv="Content-Security-Policy" content="script-src 'strict-dynamic' 'sha256-oK8+CQgKHPljcYJpTNKJt/y0A0oiBIm3LRke3EhzHVQ=' https: 'unsafe-inline';object-src 'none';base-uri 'self';">`,
    );
    expect(result).toContain(
      `var scripts = [['./main1.js', undefined, false, false],['./main2.js', undefined, true, false],['./main3.js', 'module', true, true]];`,
    );
    // Only one loader script is created.
    expect(Array.from(result.matchAll(/\<script\>/g)).length).toEqual(1);
  });

  it('should rewrite all script tags', async () => {
    const result = await autoCsp(`
      <html>
        <head>
        </head>
        <body>
          <script>console.log('foo');</script>
          <script src="./main.js"></script>
          <script src="./main2.js"></script>
          <script>console.log('bar');</script>
          <script src="./main3.js"></script>
          <script src="./main4.js"></script>
          <div>Some text </div>
        </body>
      </html>
    `);

    expect(result).toContain(
      `<meta http-equiv="Content-Security-Policy" content="script-src 'strict-dynamic' ${hashScriptText("console.log('foo');")} 'sha256-6q4qOp9MMB///5kaRda2I++J9l0mJiqWRxQ9/8hoSyw=' ${hashScriptText("console.log('bar');")} 'sha256-AUmEDzNdja438OLB3B8Opyxy9B3Tr1Tib+aaGZdhhWQ=' https: 'unsafe-inline';object-src 'none';base-uri 'self';">`,
    );
    // Loader script for main.js and main2.js appear after 'foo' and before 'bar'.
    expect(result).toMatch(
      /console.log\('foo'\);<\/script>\s*<script>\s*var scripts = \[\['.\/main.js', undefined, false, false\],\['.\/main2.js', undefined, false, false\]\];[\s\S]*console.log\('bar'\);/,
    );
    // Loader script for main3.js and main4.js appear after 'bar'.
    expect(result).toMatch(
      /console.log\('bar'\);<\/script>\s*<script>\s*var scripts = \[\['.\/main3.js', undefined, false, false\],\['.\/main4.js', undefined, false, false\]\];/,
    );
    // Exactly 4 scripts should be left.
    expect(Array.from(result.matchAll(/\<script\>/g)).length).toEqual(4);
  });
});
