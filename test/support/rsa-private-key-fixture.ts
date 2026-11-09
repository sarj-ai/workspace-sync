import { exportPKCS8, generateKeyPair } from "jose";

let privateKey: Promise<string> | undefined;

export function rsaPrivateKeyFixture(): Promise<string> {
  privateKey ??= generatePrivateKey();
  return privateKey;
}

async function generatePrivateKey(): Promise<string> {
  const pair = await generateKeyPair("RS256", { extractable: true });
  return exportPKCS8(pair.privateKey);
}
