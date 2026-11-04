/**
 * Domain lists pasted from spreadsheets: CSV, TSV or one domain per line.
 * Shared by the bulk-check REST API and the crawler's seed file.
 */

/**
 * The most of one line the byte form decodes. Only the first cell is used,
 * and parseDomain rejects any input longer than 2048 characters, so a valid
 * cell (a domain, URL or email) is at most about 6 KiB of UTF-8 and a longer
 * line's outcome is settled within its first 16 KiB, unless whitespace in or
 * before the first cell carries some of the cell past that mark: leading
 * whitespace (before the cell or just inside its opening quote) can push all
 * or part of the cell out of the decoded part (17,000 spaces before
 * 'example.com' give nothing from the bytes; 16,375 spaces before
 * 'shop.example.com' give shop.exam, so the whitespace need not reach the
 * mark itself), and a run of whitespace inside the cell can cut off the rest
 * of it ('example.com', 17,000 spaces and 'x,1' gives example.com from the
 * bytes, while the text's cell is rejected).
 *
 * The cut can also split a multi-byte whitespace character (a no-break or
 * ideographic space, say): the decoder turns the split part into U+FFFD,
 * which trim() keeps. Between the first cell's content and whatever ends the
 * cell (a separator, a closing quote or the end of the line), that leaves
 * U+FFFD at the end of a cell whose content is decoded whole, and the bytes
 * reject it unless parseDomain drops it with the rest of a path, query or
 * fragment, everything from the first /, ?, # or backslash after the
 * hostname ('example.com', 6,000 ideographic spaces and ',1' gives
 * example.com from the text and an invalid cell from the bytes, while 16,370
 * spaces, 'example.com/', 10 ideographic spaces and ',1' still give
 * example.com: the leading spaces are trimmed off, so the cell stays under
 * parseDomain's 2048 characters, and its hostname ends at the '/'; a header
 * cell followed by such a run is counted invalid instead of skipped). In
 * leading whitespace that reaches the mark, it gives an invalid cell instead
 * of nothing, even on a line the text skips as blank or a comment; when that
 * line comes before the header row, the header is counted invalid instead of
 * skipped too (see domainListLines). The cut stays where it falls rather than
 * moving to a character boundary: on fuzzed lines straddling the mark, moving
 * it saved about as many listed domains from this as it turned into domains
 * the text rejects (cut cleanly, a run of no-break spaces inside the cell
 * keeps the cell's head, as the 17,000 spaces above do, where the split
 * character's U+FFFD makes the bytes reject the cell as the text does, short
 * of a path, query or fragment as above).
 *
 * The cap also keeps a file without line breaks (a CSV saved with bare CR
 * line endings) from being decoded in one blocking call.
 */
const MAX_LINE_BYTES = 16 * 1024;

/** Spreadsheet header cells that name the domain column; a first line made of one is skipped. */
const HEADER_CELLS = new Set(["domain", "domains", "website", "websites", "url", "urls", "site", "sites", "host", "hostname", "email", "company domain", "company website"]);

/**
 * One step per line of a domain list: the line's first column with
 * surrounding quotes removed, or null for a blank line, a comment (#) or the
 * header row. Lines are found as they are read rather than by splitting the
 * whole text up front, so a caller working through a list of millions of
 * lines (the crawler's seed file) can yield between slices of it and never
 * sits in one long pass.
 *
 * The list can also be given as the file's raw UTF-8 bytes. Each line is then
 * found in the bytes and decoded on its own when it is reached, so a large
 * file is never decoded in one blocking call either (at most MAX_LINE_BYTES
 * of each line). The steps give the same targets as those of the decoded
 * text, though not always the same strings: a first cell running past
 * MAX_LINE_BYTES comes out cut, and is rejected either way. The exceptions
 * are where whitespace in or before the first cell carries some of it past
 * MAX_LINE_BYTES, or the cut splits a multi-byte whitespace character ahead
 * of whatever ends the first cell (see MAX_LINE_BYTES). Some of those also
 * change a later line: only a line that is neither blank nor a comment ends
 * the search for the header row, so a leading line that one form skips and
 * the other does not (17,000 spaces before 'example.com', which the bytes
 * skip, or 6,000 ideographic spaces alone or before '# note', which the bytes
 * give as U+FFFD) lets the next line that is neither blank nor a comment be
 * the header row in one form only, and a header cell there ('domain', with
 * no whitespace at all) is skipped by one form and counted invalid by the
 * other, however many blank and comment lines come between. Up to the cut,
 * each line decodes as it does in the text: 0x0A is never part of a
 * multi-byte UTF-8 sequence, so an invalid sequence before a line break is
 * replaced the same way whether the decoder stops there or runs on, and a BOM
 * stays at the start of the first line, where trim() removes it as it does in
 * the text.
 */
export function* domainListLines(source: string | Buffer): Generator<string | null, void, undefined> {
  const { length } = source;
  const lineEnd = typeof source === "string" ? (from: number) => source.indexOf("\n", from) : (from: number) => source.indexOf(0x0a, from);
  const lineAt = typeof source === "string" ? (from: number, to: number) => source.slice(from, to) : (from: number, to: number) => source.toString("utf8", from, Math.min(to, from + MAX_LINE_BYTES));
  let first = true;
  for (let start = 0; start <= length;) {
    let end = lineEnd(start);
    if (end === -1) end = length;
    // trim() also drops the \r of a CRLF line ending.
    const line = lineAt(start, end).trim();
    start = end + 1;
    if (!line || line.startsWith("#")) {
      yield null;
      continue;
    }
    let cell: string;
    if (line.startsWith('"')) {
      const close = line.indexOf('"', 1);
      cell = close === -1 ? line.slice(1) : line.slice(1, close);
    } else {
      // The first column only, without splitting a wide row into all of its columns.
      const cut = line.search(/[,;\t]/);
      cell = cut === -1 ? line : line.slice(0, cut);
    }
    cell = cell.trim();
    const isHeader = first && HEADER_CELLS.has(cell.toLowerCase());
    first = false;
    yield cell && !isHeader ? cell : null;
  }
}

/** First column of each non-empty line, with surrounding quotes removed; comments (#) and a header row are skipped. */
export function parseDomainList(text: string): string[] {
  const out: string[] = [];
  for (const cell of domainListLines(text)) if (cell !== null) out.push(cell);
  return out;
}
