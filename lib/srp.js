'use strict';

const crypto = require('crypto'),
      bignum = require('./bignum'),
      Buffer = require('./buffer'),
      assert = require('assert');

const zero = bignum(0);

function assert_(val, msg) {
  if (!val)
    throw new Error(msg||"assertion");
}

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         len (int)        length of the resulting Buffer
 *
 * returns: buffer
 */
function padTo(n, len) {
  assertIsBuffer(n, "n");
  var padding = len - n.length;
  assert_(padding > -1, "Negative padding.  Very uncomfortable.");
  var result = new Buffer(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  assert.equal(result.length, len);
  return result;
};

function padToN(number, params) {
  assertIsBignum(number);
  return padTo(number.toBuffer(), params.N_length_bits/8);
}

function padToH(number, params) {
  assertIsBignum(number);
  var hashlen_bits;
  if (params.hash === "sha1")
    hashlen_bits = 160;
  else if (params.hash === "sha256")
    hashlen_bits = 256;
  else if (params.hash === "sha512")
    hashlen_bits = 512;
  else
    throw Error("cannot determine length of hash '"+params.hash+"'");

  return padTo(number.toBuffer(), hashlen_bits/8);
}

function assertIsBuffer(arg, argname) {
  argname = argname || "arg";
  assert_(Buffer.isBuffer(arg), "Type error: "+argname+" must be a buffer");
}

function assertIsNBuffer(arg, params, argname) {
  argname = argname || "arg";
  assert_(Buffer.isBuffer(arg), "Type error: "+argname+" must be a buffer");
  if (arg.length != params.N_length_bits/8)
    assert_(false, argname+" was "+arg.length+", expected "+(params.N_length_bits/8));
}

function assertIsBignum(arg) {
  assert.equal(arg.bigNum, true);
}

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: x (bignum)      user secret
 */
function getx(params, salt, I, P) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");

  var hashIP = crypto.createHash(params.hash)
    .update(Buffer.concat([I, new Buffer(':'), P]))
    .digest();

  var hashX = crypto.createHash(params.hash)
    .update(salt)
    .update(hashIP)
    .digest();

  return bignum.fromBuffer(hashX);
};

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: buffer
 */
function computeVerifier(params, salt, I, P) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  var v_num = params.g.powm(getx(params, salt, I, P), params.N);
  return padToN(v_num, params);
};

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *
 * returns: bignum
 */
function getk(params) {
  var k_buf = crypto
    .createHash(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();

  return bignum.fromBuffer(k_buf);
};

/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: nothing, but runs callback with a Buffer
 */
function genKey(bytes, callback) {
  // bytes is optional
  if (arguments.length < 2) {
    callback = bytes;
    bytes = 32;
  }
  if (typeof callback !== 'function') {
    throw("Callback required");
  }
  crypto.randomBytes(bytes, function(err, buf) {
    if (err) return callback (err);
    return callback(null, buf);
  });
};

/*
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored)
 *         b (bignum)       server secret exponent
 *
 * returns: B (buffer)      the server public message
 */
function getB(params, k, v, b) {
  assertIsBignum(v);
  assertIsBignum(k);
  assertIsBignum(b);
  var N = params.N;
  var r = k.mul(v).add(params.g.powm(b, N)).mod(N);
  return padToN(r, params);
};

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         a (bignum)       client secret exponent
 *
 * returns A (bignum)       the client public message
 */
function getA(params, a_num) {
  assertIsBignum(a_num);
  if (Math.ceil(a_num.bitLength() / 8) < 256/8) {
    console.warn("getA: client key length", a_num.bitLength(), "is less than the recommended 256");
  }
  return padToN(params.g.powm(a_num, params.N), params);
};

/*
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         A (Buffer)       client ephemeral public key
 *         B (Buffer)       server ephemeral public key
 *
 * returns: u (bignum)      shared scrambling parameter
 */
function getu(params, A, B) {
  assertIsNBuffer(A, params, "A");
  assertIsNBuffer(B, params, "B");

  var u_buf = crypto.createHash(params.hash)
    .update(A)
    .update(B)
    .digest();

  return bignum.fromBuffer(u_buf);
};

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: buffer
 */

function client_getS(params, k_num, x_num, a_num, B_num, u_num) {
  assertIsBignum(k_num);
  assertIsBignum(x_num);
  assertIsBignum(a_num);
  assertIsBignum(B_num);
  assertIsBignum(u_num);
  var g = params.g;
  var N = params.N;
  if (zero.ge(B_num) || N.le(B_num))
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  var S_num = B_num.sub(k_num.mul(g.powm(x_num, N))).powm(a_num.add(u_num.mul(x_num)), N).mod(N);
  return padToN(S_num, params);
};

/*
 * The TLS premastersecret as calculated by the server
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored on server)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */

function server_getS(params, v_num, A_num, b_num, u_num) {
  assertIsBignum(v_num);
  assertIsBignum(A_num);
  assertIsBignum(b_num);
  assertIsBignum(u_num);
  var N = params.N;
  if (zero.ge(A_num) || N.le(A_num))
    throw new Error("invalid client-supplied 'A', must be 1..N-1");
  var S_num = A_num.mul(v_num.powm(u_num, N)).powm(b_num, N).mod(N);
  return padToN(S_num, params);
};

/*
 * Compute the shared session key K from S
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         S (buffer)       Session key
 *
 * returns: buffer
 */
function getK(params, S_buf) {
  assertIsNBuffer(S_buf, params, "S");
  return crypto.createHash(params.hash)
    .update(S_buf)
    .digest();
};

function HNxorG(params) {
  function xor(a, b) {
    if (!Buffer.isBuffer(a)) a = new Buffer(a)
    if (!Buffer.isBuffer(b)) b = new Buffer(b)
    var res = []
    if (a.length > b.length) {
      for (var i = 0; i < b.length; i++) {
        res.push(a[i] ^ b[i])
      }
    } else {
      for (var i = 0; i < a.length; i++) {
        res.push(a[i] ^ b[i])
      }
   }
   return new Buffer(res);
  }
  const hN = crypto.createHash(params.hash)
    .update(params.N)
    .digest();
  const hg = crypto.createHash(params.hash)
    .update(params.g)
    .digest();

  return xor(hN, hg);
}

// Follows the old SRP RFC: https://tools.ietf.org/html/rfc2945#section-3
// which writes this about `M` value:
// ```
// M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
// ```
// which the also the python lib used in ios-adapter follows: https://github.com/cocagne/pysrp/blob/master/srp/_ctsrp.py#L303-L312
function getM1(params, A_buf, B_buf, K_buf, salt_buf, identity_buf) {
  const identity_hash_buf = crypto.createHash(params.hash)
    .update(identity_buf)
    .digest()

  return crypto.createHash(params.hash)
    .update(HNxorG(params))
    .update(identity_hash_buf)
    .update(salt_buf)
    .update(A_buf)
    .update(B_buf)
    .update(K_buf)
    .digest();
}

function getM2(params, A_buf, M_buf, K_buf) {
  assertIsNBuffer(A_buf, params, "A");
  assertIsBuffer(M_buf, "M");
  assertIsBuffer(K_buf, "K");

  return crypto.createHash(params.hash)
    .update(A_buf)
    .update(M_buf)
    .update(K_buf)
    .digest();
}

function equal(buf1, buf2) {
  // constant-time comparison. A drop in the ocean compared to our
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

function Client(params, secret1_buf) {
  if (!(this instanceof Client)) {
    return new Client(params, secret1_buf);
  }

  assertIsBuffer(secret1_buf, "secret1");
  this._private = {
    params: params,
    k_num: getk(params),
    a_num: bignum.fromBuffer(secret1_buf)
  };
  this._private.A_buf = getA(params, this._private.a_num);
}

Client.prototype = {
  setup: function setup(salt_buf, identity_buf, password_buf) {
    assertIsBuffer(salt_buf, "salt (salt)");
    assertIsBuffer(identity_buf, "identity (I)");
    assertIsBuffer(password_buf, "password (P)");

    this._private.salt_buf = salt_buf;
    this._private.identity_buf = identity_buf;
    this._private.x_num = getx(this._private.params, salt_buf, identity_buf, password_buf);
  },
  computeA: function computeA() {
    return this._private.A_buf;
  },
  setB: function setB(B_buf) {
    var p = this._private;
    var B_num = bignum.fromBuffer(B_buf);
    var u_num = getu(p.params, p.A_buf, B_buf);
    var S_buf = client_getS(p.params, p.k_num, p.x_num, p.a_num, B_num, u_num);
    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, p.A_buf, B_buf, p.K_buf, p.salt_buf, p.identity_buf);
    p.M2_buf = getM2(p.params, p.A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf; // only for tests
  },
  computeM1: function computeM1() {
    if (this._private.M1_buf === undefined)
      throw new Error("incomplete protocol");
    return this._private.M1_buf;
  },
  checkM2: function checkM2(serverM2_buf) {
    if (!equal(this._private.M2_buf, serverM2_buf))
      throw new Error("server is not authentic");
  },
  computeK: function computeK() {
    if (this._private.K_buf === undefined)
      throw new Error("incomplete protocol");
    return this._private.K_buf;
  }
};

function Server(params, verifier_buf, secret2_buf) {
  if (!(this instanceof Server))  {
    return new Server(params, verifier_buf, secret2_buf);
  }
  assertIsBuffer(verifier_buf, "verifier");
  assertIsBuffer(secret2_buf, "secret2");
  this._private = { params: params,
                    k_num: getk(params),
                    b_num: bignum.fromBuffer(secret2_buf),
                    v_num: bignum.fromBuffer(verifier_buf) };
  this._private.B_buf = getB(params, this._private.k_num,
                             this._private.v_num, this._private.b_num);
}

Server.prototype = {
  computeB: function computeB() {
    return this._private.B_buf;
  },
  setA: function setA(A_buf) {
    var p = this._private;
    var A_num = bignum.fromBuffer(A_buf);
    var u_num = getu(p.params, A_buf, p.B_buf);
    var S_buf = server_getS(p.params, p.v_num, A_num, p.b_num, u_num);
    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, A_buf, p.B_buf, S_buf);
    p.M2_buf = getM2(p.params, A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf; // only for tests
  },
  checkM1: function checkM1(clientM1_buf) {
    if (this._private.M1_buf === undefined)
      throw new Error("incomplete protocol");
    if (!equal(this._private.M1_buf, clientM1_buf))
      throw new Error("client did not use the same password");
    return this._private.M2_buf;
  },
  computeK: function computeK() {
    if (this._private.K_buf === undefined)
      throw new Error("incomplete protocol");
    return this._private.K_buf;
  }
};

module.exports = {
  params: require('./params'),
  genKey: genKey,
  computeVerifier: computeVerifier,
  Client: Client,
  Server: Server
};
