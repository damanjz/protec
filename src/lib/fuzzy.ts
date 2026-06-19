/// Returns true if all chars of `query` appear in order within `text` (case-insensitive).
export function fuzzyMatch(query: string, text: string): boolean {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  let i = 0;
  for (const ch of t) {
    if (i < q.length && ch === q[i]) i++;
  }
  return i === q.length;
}

export interface Searchable {
  title: string;
  username: string;
}

/// Filter and rank items by a subsequence match on title+username.
export function fuzzyFilter<T extends Searchable>(query: string, items: T[]): T[] {
  if (!query.trim()) return items;
  return items.filter(
    (it) => fuzzyMatch(query, it.title) || fuzzyMatch(query, it.username),
  );
}
