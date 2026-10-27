import { searchWeb } from "./exaSearch.js";

// Local runs may keep the key in a .env file; the process environment wins.
try {
  process.loadEnvFile();
} catch (error) {
  if (error.code !== "ENOENT") {
    throw error;
  }
}

const query = process.argv.slice(2).join(" ").trim();

if (!query) {
  console.error('Usage: npm run search -- "your query"');
  process.exitCode = 1;
} else {
  try {
    const results = await searchWeb(query);

    if (results.length === 0) {
      console.log("No results.");
    } else {
      console.log(`${results.length} result(s) for "${query}":`);
    }

    for (const result of results) {
      console.log(`\n${result.title || "(untitled)"}\n${result.url}`);
      for (const highlight of result.highlights) {
        console.log(`  - ${highlight}`);
      }
    }
  } catch (error) {
    console.error(`Exa search failed: ${error.message}`);
    process.exitCode = 1;
  }
}
