import { describe, expect, it } from "vitest";
import { generatePassword } from "../client/src/lib/passwordGenerator.js";

describe("password generation", () => {
  it("generates a password matching selected character options", () => {
    const password = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      digits: true,
      special: true
    });

    expect(password).toHaveLength(32);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/\d/);
    expect(password).toMatch(/[^A-Za-z0-9]/);
  });

  it("rejects generator settings with no character sets", () => {
    expect(() =>
      generatePassword({
        length: 16,
        uppercase: false,
        lowercase: false,
        digits: false,
        special: false
      })
    ).toThrow("Изберете поне един тип символи.");
  });

  it("rejects password lengths below 8 characters", () => {
    expect(() => generatePassword({ length: 7 })).toThrow("Дължината трябва да бъде между 8 и 128.");
  });
});
