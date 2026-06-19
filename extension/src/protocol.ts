export type Request =
  | { type: "find"; origin: string }
  | { type: "submit"; origin: string; username: string; password: string }
  | { type: "status" };

export type Response =
  | { type: "credential"; username: string; password: string }
  | { type: "no_match" }
  | { type: "locked" }
  | { type: "denied" }
  | { type: "acknowledged" }
  | { type: "status"; unlocked: boolean }
  | { type: "error"; message: string };
