import { describe, it, expect } from "vitest";

import { ActionError, errorMessage } from "./errors.ts";

describe("ActionError", () => {
  it("sets name, message, and code, and is an instanceof Error", () => {
    const err = new ActionError("msg", "CODE");
    expect(err.name).toBe("ActionError");
    expect(err.message).toBe("msg");
    expect(err.code).toBe("CODE");
    expect(err instanceof Error).toBeTruthy();
  });

  it("derives name from the concrete subclass via new.target", () => {
    class FooError extends ActionError {}
    const err = new FooError("msg2", "CODE2");
    expect(err.name).toBe("FooError");
    expect(err.message).toBe("msg2");
    expect(err.code).toBe("CODE2");
    expect(err instanceof ActionError).toBeTruthy();
  });
});

describe("errorMessage", () => {
  it("takes the message of a real Error", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
  });

  it("stringifies anything else", () => {
    expect(errorMessage("boom")).toBe("boom");
    expect(errorMessage(undefined)).toBe("undefined");
  });
});
