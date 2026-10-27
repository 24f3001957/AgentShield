import Exa from "exa-js";

const DEFAULT_NUM_RESULTS = 5;
const MAX_NUM_RESULTS = 100;

/** Thrown when no Exa API key is available to the process. */
export class MissingExaApiKeyError extends Error {
  constructor() {
    super(
      "EXA_API_KEY is not set. Copy .env.example to .env and add your key from https://dashboard.exa.ai/api-keys."
    );
    this.name = "MissingExaApiKeyError";
  }
}

/**
 * Builds an Exa client from an explicit key or the EXA_API_KEY environment
 * variable, which the SDK also reads on its own.
 */
export function createExaClient(apiKey = process.env.EXA_API_KEY) {
  if (!apiKey) {
    throw new MissingExaApiKeyError();
  }
  return new Exa(apiKey);
}

function assertSearchInput(query, numResults) {
  if (typeof query !== "string" || query.trim() === "") {
    throw new TypeError("query must be a non-empty string.");
  }
  if (!Number.isInteger(numResults) || numResults < 1 || numResults > MAX_NUM_RESULTS) {
    throw new RangeError(`numResults must be an integer between 1 and ${MAX_NUM_RESULTS}.`);
  }
}

/**
 * Runs a web search with Exa and returns the relevant pages with the
 * highlights Exa extracts for each of them.
 *
 * @param {string} query What to search the web for.
 * @param {object} [options]
 * @param {number} [options.numResults] How many pages to return (default 5).
 * @param {string[]} [options.includeDomains] Only search these domains.
 * @param {string[]} [options.excludeDomains] Skip these domains.
 * @param {string} [options.objective] The broader goal the query serves.
 * @param {string} [options.apiKey] Defaults to process.env.EXA_API_KEY.
 * @returns {Promise<Array<{title: string, url: string, publishedDate: string | null, author: string | null, highlights: string[]}>>}
 */
export async function searchWeb(query, options = {}) {
  const {
    numResults = DEFAULT_NUM_RESULTS,
    includeDomains,
    excludeDomains,
    objective,
    apiKey,
  } = options;

  assertSearchInput(query, numResults);

  const exa = createExaClient(apiKey);

  const response = await exa.search(query, {
    type: "auto",
    numResults,
    contents: { highlights: true },
    ...(includeDomains && { includeDomains }),
    ...(excludeDomains && { excludeDomains }),
    ...(objective && { objective }),
  });

  return (response.results ?? []).map((result) => ({
    title: result.title ?? "",
    url: result.url,
    publishedDate: result.publishedDate ?? null,
    author: result.author ?? null,
    highlights: result.highlights ?? [],
  }));
}
