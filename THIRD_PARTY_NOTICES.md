# Third-Party Notices

This package is licensed under the MIT License (see LICENSE). It depends on the open-source
packages below, which are installed from their own distributions at install time and are not
bundled in this package. Each remains under its own license.

| Package | Version range | License | Source |
|---|---|---|---|
| `@azure/identity` | ^4.13.1 | MIT | https://github.com/Azure/azure-sdk-for-js |
| `@azure/identity-cache-persistence` | ^1.3.2 | MIT | https://github.com/Azure/azure-sdk-for-js |
| `@azure/msal-node-extensions` | ^5.5.1 | MIT | https://github.com/AzureAD/microsoft-authentication-library-for-js |
| `@microsoft/microsoft-graph-client` | ^3.0.7 | MIT | https://github.com/microsoftgraph/msgraph-sdk-javascript |
| `@modelcontextprotocol/sdk` | ^1.29.0 | MIT | https://github.com/modelcontextprotocol/typescript-sdk |
| `isomorphic-fetch` | ^3.0.0 | MIT | https://github.com/matthew-andrews/isomorphic-fetch |
| `jsonwebtoken` | ^9.0.3 | MIT | https://github.com/auth0/node-jsonwebtoken |
| `jwks-rsa` | ^4.1.0 | MIT | https://github.com/auth0/node-jwks-rsa |
| `node-html-parser` | ^9.0.4 | MIT | https://github.com/taoqf/node-html-parser |
| `pdfjs-dist` | ^6.3.289 | Apache-2.0 | https://github.com/mozilla/pdf.js |
| `xlsx` | https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz | Apache-2.0 | https://sheetjs.com (Community Edition) |
| `yauzl` | ^3.3.0 | MIT | https://github.com/thejoshwolfe/yauzl |
| `zod` | ^4.6.5 | MIT | https://github.com/colinhacks/zod |

`xlsx` is the SheetJS Community Edition, installed from the SheetJS CDN tarball pinned by integrity
hash in `package-lock.json`.

Transitive dependencies are licensed under MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0,
0BSD and BlueOak-1.0.0. Run `npx license-checker-rseidelsohn --production --summary` in a checkout
to reproduce the list for the installed lockfile.

Microsoft, Microsoft Graph, SharePoint, Azure and Entra are trademarks of Microsoft Corporation.
This project is independent and not affiliated with or endorsed by Microsoft.
