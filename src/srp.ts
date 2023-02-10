import * as crypto from "crypto";
import { BigInteger } from "./bigInt";
import { Buffer } from "buffer";

const zero = new BigInteger(0);

function invariant(condition: boolean, message?: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

type Params = {
  N: BigInteger;
  g: BigInteger;
  hash: string;
  N_length_bits: number;
};

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 */
function padTo(n: Buffer, len: number) {
  invariant(Buffer.isBuffer(n), "Type error: n must be a buffer");

  const padding = len - n.length;
  invariant(padding > -1, "Negative padding.  Very uncomfortable.");
  const result = Buffer.alloc(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  invariant(result.length === len, "Padding failed");
  return result;
}

function padToN(number: BigInteger, params: Params) {
  invariant(number.bigNum === true);
  return padTo(number.toBuffer(), params.N_length_bits / 8);
}

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 */
function getx(params: Params, salt: Buffer, I: Buffer, P: Buffer) {
  invariant(Buffer.isBuffer(salt), "Type error: salt (salt) must be a buffer");
  invariant(Buffer.isBuffer(I), "Type error: identity (I) must be a buffer");
  invariant(Buffer.isBuffer(P), "Type error: password (P) must be a buffer");

  const hashIP = Buffer.from(
    crypto
      .createHash(params.hash)
      .update(Buffer.concat([I, Buffer.from(":"), P]))
      .digest()
  );

  const hashX = Buffer.from(
    crypto.createHash(params.hash).update(salt).update(hashIP).digest()
  );

  return BigInteger.fromBuffer(hashX);
}

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 */
function computeVerifier(params: Params, salt: Buffer, I: Buffer, P: Buffer) {
  invariant(Buffer.isBuffer(salt), "Type error: salt (salt) must be a buffer");
  invariant(Buffer.isBuffer(I), "Type error: identity (I) must be a buffer");
  invariant(Buffer.isBuffer(P), "Type error: password (P) must be a buffer");

  const v_num = params.g.powm(getx(params, salt, I, P), params.N);
  return padToN(v_num, params);
}

/*
 * Calculate the SRP-6 multiplier
 */
function getk(params: Params) {
  const k_buf = crypto
    .createHash(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();
  return BigInteger.fromBuffer(k_buf);
}

/*
 * Generate a random key
 */
async function genKey(bytes = 32) {
  return new Promise<Buffer>((resolve, reject) => {
    crypto.randomBytes(bytes, function (err, buf) {
      if (err) {
        reject(err);
      }

      resolve(Buffer.from(buf));
    });
  });
}

/*
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 */
function getB(params: Params, k: BigInteger, v: BigInteger, b: BigInteger) {
  invariant(v.bigNum === true);
  invariant(k.bigNum === true);
  invariant(b.bigNum === true);

  var N = params.N;
  var r = k.mul(v).add(params.g.powm(b, N)).mod(N);
  return padToN(r, params);
}

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 */
function getA(params: Params, a_num: BigInteger) {
  invariant(a_num.bigNum === true);

  if (Math.ceil(a_num.bitLength() / 8) < 256 / 8) {
    console.warn(
      "getA: client key length",
      a_num.bitLength(),
      "is less than the recommended 256"
    );
  }
  return padToN(params.g.powm(a_num, params.N), params);
}

/*
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 */
function getu(params: Params, A: Buffer, B: Buffer) {
  invariant(Buffer.isBuffer(A), "Type error: A must be a buffer");
  invariant(
    A.length === params.N_length_bits / 8,
    "A was " + A.length + ", expected " + params.N_length_bits / 8
  );
  invariant(Buffer.isBuffer(B), "Type error: B must be a buffer");
  invariant(
    B.length === params.N_length_bits / 8,
    "B was " + B.length + ", expected " + params.N_length_bits / 8
  );

  const u_buf = crypto.createHash(params.hash).update(A).update(B).digest();
  return BigInteger.fromBuffer(u_buf);
}

/*
 * The TLS premaster secret as calculated by the client
 */

function client_getS(
  params: Params,
  k_num: BigInteger,
  x_num: BigInteger,
  a_num: BigInteger,
  B_num: BigInteger,
  u_num: BigInteger
) {
  invariant(k_num.bigNum === true);
  invariant(x_num.bigNum === true);
  invariant(a_num.bigNum === true);
  invariant(B_num.bigNum === true);
  invariant(u_num.bigNum === true);

  const { g, N } = params;

  if (zero.ge(B_num) || N.le(B_num)) {
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  }
  const S_num = B_num.sub(k_num.mul(g.powm(x_num, N)))
    .powm(a_num.add(u_num.mul(x_num)), N)
    .mod(N);
  return padToN(S_num, params);
}

/*
 * The TLS premastersecret as calculated by the server
 */
function server_getS(
  params: Params,
  v_num: BigInteger,
  A_num: BigInteger,
  b_num: BigInteger,
  u_num: BigInteger
) {
  invariant(v_num.bigNum === true);
  invariant(A_num.bigNum === true);
  invariant(b_num.bigNum === true);
  invariant(u_num.bigNum === true);

  const { N } = params;

  if (zero.ge(A_num) || N.le(A_num))
    throw new Error("invalid client-supplied 'A', must be 1..N-1");
  const S_num = A_num.mul(v_num.powm(u_num, N)).powm(b_num, N).mod(N);
  return padToN(S_num, params);
}

/*
 * Compute the shared session key K from S
 */
function getK(params: Params, S_buf: Buffer) {
  invariant(Buffer.isBuffer(S_buf), "Type error: S must be a buffer");
  invariant(
    S_buf.length === params.N_length_bits / 8,
    "S was " + S_buf.length + ", expected " + params.N_length_bits / 8
  );

  return Buffer.from(crypto.createHash(params.hash).update(S_buf).digest());
}

function getM1(params: Params, A_buf: Buffer, B_buf: Buffer, S_buf: Buffer) {
  invariant(Buffer.isBuffer(A_buf), "Type error: A must be a buffer");
  invariant(
    A_buf.length === params.N_length_bits / 8,
    "A was " + A_buf.length + ", expected " + params.N_length_bits / 8
  );

  invariant(Buffer.isBuffer(B_buf), "Type error: B must be a buffer");
  invariant(
    B_buf.length === params.N_length_bits / 8,
    "B was " + B_buf.length + ", expected " + params.N_length_bits / 8
  );

  invariant(Buffer.isBuffer(S_buf), "Type error: S must be a buffer");
  invariant(
    S_buf.length === params.N_length_bits / 8,
    "S was " + S_buf.length + ", expected " + params.N_length_bits / 8
  );

  return Buffer.from(
    crypto
      .createHash(params.hash)
      .update(A_buf)
      .update(B_buf)
      .update(S_buf)
      .digest()
  );
}

function getM2(params: Params, A_buf: Buffer, M_buf: Buffer, K_buf: Buffer) {
  invariant(Buffer.isBuffer(A_buf), "Type error: A must be a buffer");
  invariant(
    A_buf.length === params.N_length_bits / 8,
    "A was " + A_buf.length + ", expected " + params.N_length_bits / 8
  );
  invariant(Buffer.isBuffer(M_buf), "Type error: M must be a buffer");
  invariant(Buffer.isBuffer(K_buf), "Type error: K must be a buffer");

  return Buffer.from(
    crypto
      .createHash(params.hash)
      .update(A_buf)
      .update(M_buf)
      .update(K_buf)
      .digest()
  );
}

function equal(buf1: Buffer, buf2: Buffer) {
  // Constant-time comparison. A drop in the ocean compared to our
  // non-constant-time modexp operations, but still good practice.
  var mismatch = buf1.length - buf2.length;
  if (mismatch) {
    return false;
  }
  for (var i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i];
  }
  return mismatch === 0;
}

export class Client {
  _private: {
    params: Params;
    k_num: BigInteger;
    x_num: BigInteger;
    a_num: BigInteger;
    u_num?: BigInteger;
    A_buf: Buffer;
    K_buf?: Buffer;
    M1_buf?: Buffer;
    M2_buf?: Buffer;
    S_buf?: Buffer;
  };

  constructor(
    params: Params,
    salt_buf: Buffer,
    identity_buf: Buffer,
    password_buf: Buffer,
    secret1_buf: Buffer
  ) {
    invariant(
      Buffer.isBuffer(salt_buf),
      "Type error: salt (salt) must be a buffer"
    );
    invariant(
      Buffer.isBuffer(identity_buf),
      "Type error: identity (I) must be a buffer"
    );
    invariant(
      Buffer.isBuffer(password_buf),
      "Type error: password (P) must be a buffer"
    );
    invariant(
      Buffer.isBuffer(secret1_buf),
      "Type error: secret1 must be a buffer"
    );

    const a_num = BigInteger.fromBuffer(secret1_buf);

    this._private = {
      params: params,
      k_num: getk(params),
      x_num: getx(params, salt_buf, identity_buf, password_buf),
      a_num,
      A_buf: getA(params, a_num)
    };
  }

  computeA() {
    return this._private.A_buf;
  }

  setB(B_buf: Buffer) {
    var p = this._private;
    var B_num = BigInteger.fromBuffer(B_buf);
    var u_num = getu(p.params, p.A_buf, B_buf);
    var S_buf = client_getS(p.params, p.k_num, p.x_num, p.a_num, B_num, u_num);
    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, p.A_buf, B_buf, S_buf);
    p.M2_buf = getM2(p.params, p.A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf; // only for tests
  }

  computeM1() {
    invariant(
      typeof this._private.M1_buf !== "undefined",
      "incomplete protocol"
    );

    return this._private.M1_buf;
  }

  checkM2(serverM2_buf: Buffer) {
    invariant(
      typeof this._private.M2_buf !== "undefined" &&
        equal(this._private.M2_buf, serverM2_buf),
      "M2 didn't check"
    );
  }

  computeK() {
    invariant(
      typeof this._private.K_buf !== "undefined",
      "incomplete protocol"
    );

    return this._private.K_buf;
  }
}

export class Server {
  _private: {
    params: Params;
    k_num: BigInteger;
    b_num: BigInteger;
    v_num: BigInteger;
    B_buf: Buffer;
    u_num?: BigInteger;
    A_buf?: Buffer;
    K_buf?: Buffer;
    M1_buf?: Buffer;
    M2_buf?: Buffer;
    S_buf?: Buffer;
  };

  constructor(params: Params, verifier_buf: Buffer, secret2_buf: Buffer) {
    invariant(
      Buffer.isBuffer(verifier_buf),
      "Type error: verifier must be a buffer"
    );
    invariant(
      Buffer.isBuffer(secret2_buf),
      "Type error: secret2 must be a buffer"
    );

    const k_num = getk(params);
    const b_num = BigInteger.fromBuffer(secret2_buf);
    const v_num = BigInteger.fromBuffer(verifier_buf);

    this._private = {
      params: params,
      k_num,
      b_num,
      v_num,
      B_buf: getB(params, k_num, v_num, b_num)
    };
  }

  computeB() {
    return this._private.B_buf;
  }

  setA(A_buf: Buffer) {
    const p = this._private;
    const A_num = BigInteger.fromBuffer(A_buf);
    const u_num = getu(p.params, A_buf, p.B_buf);
    const S_buf = server_getS(p.params, p.v_num, A_num, p.b_num, u_num);
    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, A_buf, p.B_buf, S_buf);
    p.M2_buf = getM2(p.params, A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf; // only for tests
  }

  checkM1(clientM1_buf: Buffer) {
    invariant(
      typeof this._private.M1_buf !== "undefined",
      "incomplete protocol"
    );
    invariant(
      equal(this._private.M1_buf, clientM1_buf),
      "client did not use the same password"
    );

    return this._private.M2_buf;
  }

  computeK() {
    invariant(
      typeof this._private.K_buf !== "undefined",
      "incomplete protocol"
    );

    return this._private.K_buf;
  }
}

export { genKey, computeVerifier };
