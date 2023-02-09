import { Buffer } from "buffer";
import { BigInteger as _BigInteger } from "jsbn";

export class BigInteger extends _BigInteger {
  bigNum = true;

  constructor(v: number | string, r?: number) {
    super(v.toString(), r);
  }

  toBuffer() {
    let h = super.toString(16);

    // Fix odd-length hex values from BigInteger
    if (h.length % 2 === 1) {
      h = "0" + h;
    }

    return Buffer.from(h, "hex");
  }
  bitLength() {
    return super.bitLength();
  }
  mod(n: BigInteger) {
    return this.ensureBI(super.mod(this.ensureBI(n)));
  }
  add(n: BigInteger | number) {
    return this.ensureBI(super.add(this.ensureBI(n)));
  }
  mul(n: BigInteger) {
    return this.ensureBI(super.multiply(this.ensureBI(n)));
  }
  sub(n: BigInteger) {
    return this.ensureBI(super.subtract(this.ensureBI(n)));
  }
  powm(n: BigInteger, m: BigInteger) {
    return this.ensureBI(super.modPow(this.ensureBI(n), this.ensureBI(m)));
  }
  eq(n: BigInteger) {
    return this.ensureBI(super.equals(this.ensureBI(n)));
  }
  ge(n: BigInteger) {
    return super.compareTo(n) >= 0;
  }
  le(n: BigInteger) {
    return super.compareTo(n) <= 0;
  }
  static fromBuffer(buffer: Buffer) {
    const hex = buffer.toString("hex");
    return new BigInteger(hex, 16);
  }
  ensureBI(n: BigInteger | _BigInteger | number) {
    if (n && typeof n === "object" && "bigNum" in n && n.bigNum) {
      return n as BigInteger;
    }

    return new BigInteger(n.toString());
  }
}
