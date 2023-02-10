import { encodeBase64, decodeBase64 } from "./base64";
import { open, seal } from "./sealedbox";

export async function encodeBox<T>(
  data: T,
  publicKey: Uint8Array
): Promise<{
  key: string;
  data: string;
}> {
  const enc = new TextEncoder();

  // Encode data to JSON, to bytes
  const rawData = enc.encode(JSON.stringify(data));

  // Seal bytes into box
  const sealedBox = seal(rawData, publicKey);

  // Base64 parameters into request
  const body = {
    key: await encodeBase64(publicKey),
    data: await encodeBase64(sealedBox)
  };

  return body;
}

export async function decodeBox<T>(
  data: string,
  publicKey: Uint8Array,
  secretKey: Uint8Array
): Promise<T | null> {
  const dec = new TextDecoder();

  // Decode base64'd string
  const sealedBox = await decodeBase64(data);

  // Unseal box into bytes
  const rawData = open(sealedBox, publicKey, secretKey);

  if (!rawData) {
    throw new Error("Invalid data");
  }

  // Decode and parse bytes from JSON.
  return JSON.parse(dec.decode(rawData));
}
