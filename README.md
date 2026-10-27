# AgentShield

Agent tooling for AgentShield. The first module is Exa-backed web search: it
calls Exa's search API with highlights so an app or agent can pull relevant
pages and the passages that answer its query.

## Setup

```bash
npm install
cp .env.example .env   # then paste your key from https://dashboard.exa.ai/api-keys
```

`EXA_API_KEY` is read from the environment. A locally created `.env` is loaded
for the CLI; anywhere else, export the variable (`setx EXA_API_KEY "..."` on
Windows).

## Web search

```bash
npm run search -- "accident detection using smartphone sensors"
```

```js
import { searchWeb } from "./src/exaSearch.js";

const results = await searchWeb("latest road-safety guidance", {
  numResults: 5,
  includeDomains: ["who.int"],
});

for (const { title, url, highlights } of results) {
  console.log(title, url, highlights);
}
```

`searchWeb(query, options)` returns `{ title, url, publishedDate, author,
highlights }` per result. Options: `numResults`, `includeDomains`,
`excludeDomains`, `objective` (the goal the query serves) and `apiKey`.

Docs: https://exa.ai/docs
