// This is an implementation of libsodium's sealed box algorithm (also known as
// "anonymous box" in Golang.) It generates an ephemeral keypair to use for the
// sender, and then generates a nonce using the blake2b digest of the ephemeral
// public key and the recipient public key. This is trivially implemented using
// only tweetnacl's nacl.box.* namespace, and blakejs for the nonce generation.
// The ephemeral public key is prepended to a sealed box, so only the recipient
// keypair is needed for opening - the ephemeral private key is just discarded.

import { box as naclBox } from 'tweetnacl';
import { blake2b } from 'blakejs';

export const overheadLength = naclBox.overheadLength + naclBox.publicKeyLength;

export const keyPair = naclBox.keyPair;

export function open(
  sealedbox: Uint8Array,
  pk: Uint8Array,
  sk: Uint8Array,
): Uint8Array|null {
  const epk = sealedbox.subarray(0, naclBox.publicKeyLength);
  const data = sealedbox.subarray(naclBox.publicKeyLength);
  return naclBox.open(data, nonce(epk, pk), epk, sk);
};

export function seal(data: Uint8Array, pk: Uint8Array): Uint8Array {
  const sealedbox = new Uint8Array(overheadLength + data.length);
  const ek = naclBox.keyPair();
  const box = naclBox(data, nonce(ek.publicKey, pk), pk, ek.secretKey);
  sealedbox.set(ek.publicKey);
  sealedbox.set(box, ek.publicKey.length);
  return sealedbox;
};

function nonce(epk: Uint8Array, pk: Uint8Array): Uint8Array {
  const data: Uint8Array = new Uint8Array(epk.length + pk.length);
  data.set(epk);
  data.set(pk, epk.length);
  return blake2b(data, undefined, naclBox.nonceLength);
};

