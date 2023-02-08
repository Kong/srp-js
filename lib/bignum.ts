import { Buffer } from "buffer";
import { BigInteger } from "jsbn";

BigInteger.prototype.bigNum = true;
BigInteger.prototype.toBuffer = function () {
  var h = this.toString(16);

  // Fix odd-length hex values from BigInteger
  if (h.length % 2 === 1) {
    h = "0" + h;
  }

  return new Buffer(h, "hex");
};

function ensureBI(n) {
  if (!n.bigNum) {
    n = bignum(n);
  }

  return n;
}

BigInteger.prototype.oldAdd = BigInteger.prototype.add;
BigInteger.prototype.add = function (n) {
  return this.oldAdd(ensureBI(n));
};

BigInteger.prototype.mul = function (n) {
  return this.multiply(ensureBI(n));
};

BigInteger.prototype.sub = function (n) {
  return this.subtract(ensureBI(n));
};

BigInteger.prototype.powm = function (n, m) {
  return this.modPow(ensureBI(n), ensureBI(m));
};

BigInteger.prototype.eq = function (n) {
  return this.equals(ensureBI(n));
};

BigInteger.prototype.ge = function (n) {
  return this.compareTo(n) >= 0;
};

BigInteger.prototype.le = function (n) {
  return this.compareTo(n) <= 0;
};

function fromBuffer(buffer) {
  var hex = buffer.toString("hex");
  return new BigInteger(hex, 16);
}

function bignum(v: number, r?: number) {
  return new BigInteger(v.toString(), r);
}

export { bignum, fromBuffer };
