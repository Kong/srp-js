// HKDF - https://tools.ietf.org/html/rfc5869
import crypto from 'crypto';
import process from 'process';
import { Buffer } from 'buffer';

function zeros(length: number) {
  var buf = Buffer.alloc(length);

  buf.fill(0);

  return buf.toString();
}

export class HKDF {
  hashAlg: string;
  salt: string;
  ikm: string;
  hashLength: number;
  prk: Buffer;

  constructor(hashAlg: string, salt: string, ikm: string) {
    this.hashAlg = hashAlg;

    // create the hash alg to see if it exists and get its length
    const hash = crypto.createHash(this.hashAlg);
    this.hashLength = hash.digest().length;
  
    this.salt = salt || zeros(this.hashLength);
    this.ikm = ikm;
  
    // now we compute the PRK
    const hmac = crypto.createHmac(this.hashAlg, this.salt);
    hmac.update(this.ikm);
    this.prk = hmac.digest();
  };

  derive(info: Buffer | crypto.BinaryLike, size: number, cb: { (buffer: Buffer): void; (arg0: any): void; }) {
    let prev = Buffer.alloc(0);
    let output: Buffer;
    const buffers = [];
    const num_blocks = Math.ceil(size / this.hashLength);
    info = Buffer.from(info.toString());

    for (let i=0; i < num_blocks; i++) {
      const hmac = crypto.createHmac(this.hashAlg, this.prk);
      hmac.update(prev);
      hmac.update(info);
      hmac.update(Buffer.from([i + 1]));
      prev = hmac.digest();
      buffers.push(prev);
    }
    output = Buffer.concat(buffers, size);

    process.nextTick(function() {cb(output);});
  }
}