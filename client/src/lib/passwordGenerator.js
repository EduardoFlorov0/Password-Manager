const CHARSETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  special: "!@#$%^&*()-_=+[]{};:,.?/"
};

function getCrypto() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Сигурният генератор на случайни стойности не е достъпен.");
  }
  return globalThis.crypto;
}

function randomInt(maxExclusive) {
  const values = new Uint32Array(1);
  const limit = 0xffffffff - (0xffffffff % maxExclusive);

  do {
    getCrypto().getRandomValues(values);
  } while (values[0] >= limit);

  return values[0] % maxExclusive;
}

function pickOne(charset) {
  return charset[randomInt(charset.length)];
}

function shuffle(items) {
  const result = [...items];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInt(index + 1);
    [result[index], result[swapIndex]] = [result[swapIndex], result[index]];
  }
  return result;
}

export function generatePassword(options = {}) {
  const settings = {
    length: Number(options.length || 16),
    uppercase: options.uppercase ?? true,
    lowercase: options.lowercase ?? true,
    digits: options.digits ?? true,
    special: options.special ?? true
  };

  const selectedSets = Object.entries(CHARSETS)
    .filter(([name]) => settings[name])
    .map(([, charset]) => charset);

  if (selectedSets.length === 0) {
    throw new Error("Изберете поне един тип символи.");
  }

  if (!Number.isInteger(settings.length) || settings.length < 8 || settings.length > 128) {
    throw new Error("Дължината трябва да бъде между 8 и 128.");
  }

  const allCharacters = selectedSets.join("");
  const password = selectedSets.map(pickOne);

  while (password.length < settings.length) {
    password.push(pickOne(allCharacters));
  }

  return shuffle(password).join("");
}

export { CHARSETS };
