import { describe, it, expect } from "vitest";
import { fuzzyMatch, fuzzyFilter } from "./fuzzy";

describe("fuzzy", () => {
  it("matches a subsequence", () => {
    expect(fuzzyMatch("gh", "GitHub")).toBe(true);
    expect(fuzzyMatch("ghb", "GitHub")).toBe(true);
    expect(fuzzyMatch("xyz", "GitHub")).toBe(false);
  });

  it("empty query matches everything", () => {
    expect(fuzzyMatch("", "anything")).toBe(true);
  });

  it("filters items by title or username", () => {
    const items = [
      { title: "GitHub", username: "octocat" },
      { title: "Gmail", username: "me" },
    ];
    expect(fuzzyFilter("oct", items)).toHaveLength(1);
    expect(fuzzyFilter("g", items)).toHaveLength(2);
  });
});
