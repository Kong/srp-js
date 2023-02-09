import { Client, computeVerifier, params } from "./srp";
import type * as schema from "./schema";
import * as crypt from "./crypt";
import { Buffer } from "buffer";
import { decodeBase64, encodeBase64 } from "./base64";
import { seal } from "./sealedbox";
import { base64, sealedbox } from ".";

export interface BillingDetails {
  planId: string;
  description: string;
  isPaymentRequired: boolean;
  isBillingAdmin: boolean;
  subTrialing: boolean;
  subTrialEnd: string;
  subCancelled: boolean;
  subPeriodEnd: string;
  subPercentOff: number;
  customerId: string;
  subQuantity: number;
  subMemo: string;
  hasCard: boolean;
  lastFour: string;
}

export interface Team {
  id: string;
  name: string;
  ownerAccountId: string;
  isPersonal: boolean;
  accounts: {
    isAdmin: boolean;
    firstName: string;
    lastName: string;
    email: string;
    id: string;
  }[];
}

export interface Invoice {
  id: string;
  date: string;
  paid: boolean;
  total: number;
}

export interface InvoiceLink {
  downloadLink: string;
}

interface AuthSalts {
  saltKey: string;
  saltAuth: string;
}

interface Account {
  email: string;
  firstName: string;
  lastName: string;
  id: string;
  saltEnc: string;
  saltAuth: string;
  saltKey: string;
  verifier?: string;
  publicKey?: string;
  encPrivateKey?: string;
  encSymmetricKey?: string;
}

class SessionEvents extends EventTarget {
  login = () => {
    this.dispatchEvent(new CustomEvent("login"));
  };

  logout = () => {
    this.dispatchEvent(new CustomEvent("logout"));
  };
}

export const sessionEvents = new SessionEvents();

/** Create a new Account for the user */
export async function signup(
  firstName: string,
  lastName: string,
  rawEmail: string,
  rawPassphrase: string,
  loginAfter = false
) {
  const email = _sanitizeEmail(rawEmail);
  const passphrase = _sanitizePassphrase(rawPassphrase);

  // Get a fancy new Account object
  const account = await _initAccount(firstName, lastName, email);

  // Generate some secrets for the user base'd on password
  const authSecret = await crypt.deriveKey(
    passphrase,
    account.email,
    account.saltKey
  );
  const derivedSymmetricKey = await crypt.deriveKey(
    passphrase,
    account.email,
    account.saltEnc
  );

  // Generate public/private keypair and symmetric key for Account
  const { publicKey, privateKey } = await crypt.generateKeyPairJWK();
  const symmetricKeyJWK = await crypt.generateAES256Key();

  // Compute the verifier key and add it to the Account object
  account.verifier = computeVerifier(
    _getSrpParams(),
    Buffer.from(account.saltAuth, "hex"),
    Buffer.from(account.email, "utf8"),
    Buffer.from(authSecret, "hex")
  ).toString("hex");

  // Encode keypair
  const encSymmetricJWKMessage = crypt.encryptAES(
    derivedSymmetricKey,
    JSON.stringify(symmetricKeyJWK)
  );
  const encPrivateJWKMessage = crypt.encryptAES(
    symmetricKeyJWK,
    JSON.stringify(privateKey)
  );

  // Add keys to account
  account.publicKey = JSON.stringify(publicKey);
  account.encPrivateKey = JSON.stringify(encPrivateJWKMessage);
  account.encSymmetricKey = JSON.stringify(encSymmetricJWKMessage);

  const signupData = await fetch("http://localhost:8000/auth/signup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(account)
  });

  if (loginAfter) {
    await login(rawEmail, rawPassphrase, authSecret);
  }

  return signupData;
}

export async function deleteAccount() {
  await fetch("http://localhost:8000/auth/delete-account", {
    method: "DELETE"
  });
}

export function signupAndLogin(
  firstName: string,
  lastName: string,
  rawEmail: string,
  rawPassphrase: string
) {
  return signup(firstName, lastName, rawEmail, rawPassphrase, true);
}

/**
 * Performs an SRP login. When useCookies is set to false, the server uses the
 * negotiated SRP K value to create a valid session token. When useCookies is
 * set to true, the SRP K value is discarded and a pseudo-random session cookie
 * is created upon login instead, using HTTP-only mode.
 *
 * authSecret never needs to be passed; it is only passed by other auth
 * functions when the authSecret value has already been computed for another
 * reason (such as during signup.)
 *
 * useCookies needs to be set to false if the client needs access to a valid
 * session token.
 *
 * @param rawEmail The raw e-mail identity.
 * @param rawPassphrase The raw passphrase.
 * @param authSecret If already calculated, the derived passphrase key.
 * @param useCookies If true, the server creates a pseudo-random session cookie.
 * @returns The SRP K value.
 */
export async function login(
  rawEmail: string,
  rawPassphrase: string,
  authSecret: string | null = null,
  useCookies = true
) {
  // ~~~~~~~~~~~~~~~ //
  // Sanitize Inputs //
  // ~~~~~~~~~~~~~~~ //

  const email = _sanitizeEmail(rawEmail);
  const passphrase = _sanitizePassphrase(rawPassphrase);

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //
  // Fetch Salt and Submit A To Server //
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //

  const { saltKey, saltAuth } = await getAuthSalts(email);
  authSecret =
    authSecret || (await crypt.deriveKey(passphrase, email, saltKey));
  const secret1 = await crypt.srpGenKey();
  const c = new Client(
    _getSrpParams(),
    Buffer.from(saltAuth, "hex"),
    Buffer.from(email, "utf8"),
    Buffer.from(authSecret, "hex"),
    Buffer.from(secret1, "hex")
  );
  const srpA = c.computeA().toString("hex");
  const loginAResponse = await fetch("http://localhost:8000/auth/login-a", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      srpA,
      email
    })
  });

  const {
    sessionStarterId,
    srpB
  }: {
    sessionStarterId: string;
    srpB: string;
  } = await loginAResponse.json();

  // ~~~~~~~~~~~~~~~~~~~~~ //
  // Compute and Submit M1 //
  // ~~~~~~~~~~~~~~~~~~~~~ //

  c.setB(Buffer.from(srpB, "hex"));
  const srpM1 = c.computeM1().toString("hex");

  const loginM1Response = await fetch("http://localhost:8000/auth/login-m1", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      srpM1,
      sessionStarterId,
      useCookies
    })
  });

  const { srpM2 }: { srpM2: string } = await loginM1Response.json();

  // ~~~~~~~~~~~~~~~~~~~~~~~~~ //
  // Verify Server Identity M2 //
  // ~~~~~~~~~~~~~~~~~~~~~~~~~ //

  c.checkM2(Buffer.from(srpM2, "hex"));

  // Return K
  return c.computeK().toString("hex");
}

export async function subscribe(
  tokenId: string,
  planId: string,
  quantity: number,
  memo: string
) {
  const response = await fetch(
    "http://localhost:8000/api/billing/subscriptions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        token: tokenId,
        quantity: quantity,
        plan: planId,
        memo: memo
      })
    }
  );
  const data = await response.json();

  return data;
}

export async function logout() {
  try {
    await fetch("http://localhost:8000/auth/logout", {
      method: "POST"
    });
  } catch (e) {
    // Not a huge deal if this fails, but we don't want it to prevent the
    // user from signing out.
    console.warn("Failed to logout", e);
  } finally {
    unsetSessionData();
  }
}

export async function cancelAccount() {
  const response = await fetch(
    "http://localhost:8000/api/billing/subscriptions",
    {
      method: "DELETE"
    }
  );
  const data = await response.json();

  return data;
}

export async function whoami() {
  const response = await fetch("http://localhost:8000/auth/whoami");
  const data: schema.WhoamiResponse = await response.json();

  return data;
}

export async function keys() {
  const response = await fetch("http://localhost:8000/v1/keys");
  const data: schema.APIKeysResponse = await response.json();

  return data;
}

export async function invoices() {
  const response = await fetch("http://localhost:8000/v1/invoices");
  const data: Invoice[] = await response.json();

  return data;
}

export async function getInvoice(invoiceId: string) {
  const response = await fetch(
    "http://localhost:8000/v1/invoices/" + invoiceId
  );
  const data: InvoiceLink = await response.json();

  return data;
}

export async function verify() {
  const response = await fetch("http://localhost:8000/v1/verify");
  const data: {} = await response.json();

  return data;
}

export async function billingDetails() {
  try {
    const response = await fetch("http://localhost:8000/api/billing/details");
    const data: BillingDetails = await response.json();

    return data;
  } catch (e) {
    return null;
  }
}

export async function getAuthSalts(email: string) {
  const res = await fetch("http://localhost:8000/auth/login-s", {
    method: "POST",
    body: JSON.stringify({
      email
    })
  });

  const data: AuthSalts = await res.json();

  return data;
}

export async function changePasswordAndEmail(
  rawOldPassphrase: string,
  rawNewPassphrase: string,
  rawNewEmail: string,
  newFirstName: string,
  newLastName: string
) {
  // Sanitize inputs
  const oldPassphrase = _sanitizePassphrase(rawOldPassphrase);
  const newPassphrase = _sanitizePassphrase(rawNewPassphrase);
  const newEmail = _sanitizeEmail(rawNewEmail);

  // Fetch some things
  const { email: oldEmail, saltEnc, encSymmetricKey } = await whoami();
  const { saltKey, saltAuth } = await getAuthSalts(oldEmail);

  // Generate some secrets for the user base'd on password
  const oldSecret = await crypt.deriveKey(oldPassphrase, oldEmail, saltEnc);
  const newSecret = await crypt.deriveKey(newPassphrase, newEmail, saltEnc);
  const oldAuthSecret = await crypt.deriveKey(oldPassphrase, oldEmail, saltKey);
  const newAuthSecret = await crypt.deriveKey(newPassphrase, newEmail, saltKey);

  // Compute the verifier key and add it to the Account object
  const oldVerifier = oldPassphrase
    ? computeVerifier(
        _getSrpParams(),
        Buffer.from(saltAuth, "hex"),
        Buffer.from(oldEmail, "utf8"),
        Buffer.from(oldAuthSecret, "hex")
      ).toString("hex")
    : "";

  const newVerifier = newPassphrase
    ? computeVerifier(
        _getSrpParams(),
        Buffer.from(saltAuth, "hex"),
        Buffer.from(newEmail, "utf8"),
        Buffer.from(newAuthSecret, "hex")
      ).toString("hex")
    : "";

  // Re-encrypt existing keys with new secret
  const newEncSymmetricKeyJSON = crypt.reEncryptAES(
    oldSecret,
    newSecret,
    JSON.parse(encSymmetricKey)
  );
  const newEncSymmetricKey = JSON.stringify(newEncSymmetricKeyJSON);

  const response = await fetch(`http://localhost:8000/auth/change-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      verifier: oldVerifier,
      newEmail,
      newFirstName,
      newLastName,
      encSymmetricKey: encSymmetricKey,
      newVerifier,
      newEncSymmetricKey
    })
  });

  return response.json();
}

export class NeedPassphraseError extends Error {
  constructor() {
    super("Passphrase required");

    // This trick is necessary to extend a native type from a transpiled ES6 class.
    Object.setPrototypeOf(this, NeedPassphraseError.prototype);
  }
}

export async function deriveSymmetricKey(
  whoami: Pick<schema.WhoamiResponse, "email" | "saltEnc">,
  rawPassphrase: string
): Promise<string> {
  const passPhrase = _sanitizePassphrase(rawPassphrase);
  const { email, saltEnc } = whoami;
  return await crypt.deriveKey(passPhrase, email, saltEnc);
}

async function getCachedPrivateKey(
  whoami: Pick<
    schema.WhoamiResponse,
    "email" | "saltEnc" | "encPrivateKey" | "encSymmetricKey"
  >,
  rawPassphrase: string | null
): Promise<JsonWebKey> {
  let privateKey: string | null = null;

  if (rawPassphrase !== null) {
    // We have a raw passphrase? Derive it from the passphrase.
    const secret = await deriveSymmetricKey(whoami, rawPassphrase);
    const { encPrivateKey, encSymmetricKey } = whoami;

    let symmetricKey: string;
    try {
      symmetricKey = crypt.decryptAES(secret, JSON.parse(encSymmetricKey));
    } catch (err) {
      console.log("Failed to decrypt wrapped private key", err);
      throw new Error("Invalid password");
    }

    privateKey = crypt.decryptAES(
      JSON.parse(symmetricKey),
      JSON.parse(encPrivateKey)
    );
    try {
      window.sessionStorage.setItem("privateKey", privateKey);
    } catch (err) {
      console.log("Failed to store private key into cache", err);
    }
  } else {
    // Otherwise, try to get it from the cache.
    try {
      privateKey = window.sessionStorage.getItem("privateKey");
    } catch (err) {
      console.log("Failed to fetch private key from cache", err);
    }

    if (privateKey === null) {
      throw new NeedPassphraseError();
    }
  }

  return JSON.parse(privateKey) as JsonWebKey;
}

export async function inviteToTeam(
  teamId: string,
  emailToInvite: string,
  rawPassphrase: string | null
) {
  // Ask the server what we need to do to invite the member
  const teamAddInstructionsResponse = await fetch(
    `http://localhost:8000/graphql?teamAddInstructions`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        variables: {
          teamId,
          email: emailToInvite
        },
        query: `
          query ($email: String!, $teamId: ID!) {
             teamAddInstructions(email: $email, teamId: $teamId) {
                accountId
                publicKey
    
                projectKeys {
                  projectId
                  encSymmetricKey
                }
             }
          }
        `
      })
    }
  );

  const {
    data,
    errors
  }: {
    data: {
      teamAddInstructions: {
        accountId: string;
        publicKey: string;
        projectKeys: {
          projectId: string;
          encSymmetricKey: string;
        }[];
      };
    };
    errors: Error[];
  } = await teamAddInstructionsResponse.json();

  if (errors && errors.length) {
    console.error("Failed to get instructions for adding to team", errors);
    throw new Error(errors[0].message);
  }

  const { accountId, publicKey, projectKeys } = data.teamAddInstructions;

  // Compute keys necessary to invite the member
  const privateKeyJWK = await getCachedPrivateKey(
    await whoami(),
    rawPassphrase
  );

  // Build the invite data request
  const nextKeys = [];
  for (const instruction of projectKeys) {
    const publicKeyJWK = JSON.parse(publicKey);
    const encSymmetricKey = crypt.reEncryptRSAWithJWK(
      privateKeyJWK,
      publicKeyJWK,
      instruction.encSymmetricKey
    );
    nextKeys.push({
      encSymmetricKey,
      projectId: instruction.projectId
    });
  }

  // Actually invite the member
  // Ask the server what we need to do to invite the member
  const teamAddResponse = await fetch(`http://localhost:8000/graphql?teamAdd`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      variables: {
        accountId,
        teamId,
        keys: nextKeys
      },
      query: `
        mutation ($accountId: ID!, $teamId: ID!, $keys: [TeamAddKeyInput!]!) {
          teamAdd(accountId: $accountId, teamId: $teamId, keys: $keys)
        }
      `
    })
  });

  const {
    errors: errorsMutation
  }: {
    errors: Error[];
  } = await teamAddResponse.json();

  if (errorsMutation && errorsMutation.length) {
    console.error("Failed adding user to team", errorsMutation);
    throw new Error(errorsMutation[0].message);
  }
}

export async function createTeam() {
  return fetch(`http://localhost:8000/api/teams`, {
    method: "POST"
  });
}

export async function leaveTeam(teamId: string) {
  const response = await fetch(`http://localhost:8000/graphql?teamLeave`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      variables: {
        teamId
      },
      query: `
          mutation ($teamId: ID!) {
            teamLeave(teamId: $teamId)
          }
        `
    })
  });

  const { errors }: { errors: Error[] } = await response.json();

  if (errors && errors.length) {
    console.error("Failed to leave team", errors);
    throw new Error(errors[0].message);
  }
}

export async function changeTeamAdminStatus(
  teamId: string,
  accountId: string,
  isAdmin: boolean
) {
  return fetch(`http://localhost:8000/api/teams/${teamId}/admin-status`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      isAdmin,
      accountId
    })
  });
}

export async function removeFromTeam(teamId: string, accountId: string) {
  const response = await fetch(`http://localhost:8000/graphql?teamRemove`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      variables: {
        accountIdToRemove: accountId,
        teamId
      },
      query: `
          mutation ($accountIdToRemove: ID!, $teamId: ID!) {
            teamRemove(accountIdToRemove: $accountIdToRemove, teamId: $teamId)
          }
        `
    })
  });

  const { errors }: { errors: Error[] } = await response.json();

  if (errors && errors.length) {
    console.error("Failed to remove member", errors);
    throw new Error(errors[0].message);
  }
}

export async function changeTeamName(teamId: string, name: string) {
  return fetch(`http://localhost:8000/api/teams/${teamId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name
    })
  });
}

export async function githubOauthConfig() {
  const response = await fetch("http://localhost:8000/v1/oauth/github/config");
  const data: { clientID: string } = await response.json();

  return data;
}

export async function updateEmailSubscription(unsubscribed: boolean) {
  if (unsubscribed) {
    await fetch(`http://localhost:8000/v1/email/unsubscribe`, {
      method: "POST"
    });
  } else {
    await fetch(`http://localhost:8000/v1/email/subscribe`, {
      method: "POST"
    });
  }
}

export async function signin({
  email,
  passphrase,
  currentWhoami,
  b64LoginKey
}: {
  email: string;
  passphrase: string;
  currentWhoami?: schema.WhoamiResponse;
  b64LoginKey?: string;
}) {
  let box: { token: string; key: string } | undefined;

  try {
    if (!currentWhoami) {
      await login(email, passphrase);
      currentWhoami = await whoami();
    }

    const token = await login(email, passphrase, undefined, false);
    const key = await deriveSymmetricKey(currentWhoami, passphrase);

    box = { token, key };
  } catch (e) {
    throw new Error(`Authentication failed: ${String(e)}`);
  }

  let loginKey: Uint8Array;
  try {
    loginKey = await decodeBase64(b64LoginKey ?? "");
  } catch (e) {
    throw new Error(`Invalid login key: ${String(e)}`);
  }

  let token: string;
  try {
    const enc = new TextEncoder();
    token = await encodeBase64(seal(enc.encode(JSON.stringify(box)), loginKey));
  } catch (e) {
    throw new Error(`Failed to create token: ${String(e)}`);
  }

  return {
    token
  };
}

// ~~~~~~~~~~~~~~~~ //
// Helper Functions //
// ~~~~~~~~~~~~~~~~ //

async function _initAccount(
  firstName: string,
  lastName: string,
  email: string
): Promise<Account> {
  return {
    email,
    firstName,
    lastName,
    id: await crypt.generateAccountId(),
    saltEnc: await crypt.getRandomHex(),
    saltAuth: await crypt.getRandomHex(),
    saltKey: await crypt.getRandomHex()
  };
}

function _sanitizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export interface WhoamiResponse {
  sessionAge: number;
  accountId: string;
  email: string;
  firstName: string;
  lastName: string;
  created: number;
  publicKey: string;
  encSymmetricKey: string;
  encPrivateKey: string;
  saltEnc: string;
  isPaymentRequired: boolean;
  isTrialing: boolean;
  isVerified: boolean;
  isAdmin: boolean;
  trialEnd: string;
  planName: string;
  planId: string;
  canManageTeams: boolean;
  maxTeamMembers: number;
}

export interface SessionData {
  accountId: string;
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  symmetricKey: JsonWebKey;
  publicKey: JsonWebKey;
  encPrivateKey: crypt.AESMessage;
}

/** Creates a session from a sessionId and derived symmetric key. */
export async function absorbKey(sessionId: string, key: string) {
  // Get and store some extra info (salts and keys)
  const {
    publicKey,
    encPrivateKey,
    encSymmetricKey,
    email,
    accountId,
    firstName,
    lastName
  } = await _whoami(sessionId);
  const symmetricKeyStr = crypt.decryptAES(key, JSON.parse(encSymmetricKey));
  // Store the information for later
  setSessionData({
    id: sessionId,
    accountId,
    firstName,
    lastName,
    email,
    symmetricKey: JSON.parse(symmetricKeyStr),
    publicKey: JSON.parse(publicKey),
    encPrivateKey: JSON.parse(encPrivateKey)
  });
}

export async function changePasswordWithToken(
  rawNewPassphrase: string,
  confirmationCode: string,
  sessionId: string | null = null
) {
  // Sanitize inputs
  const newPassphrase = _sanitizePassphrase(rawNewPassphrase);

  const newEmail = getEmail(); // Use the same one

  if (!newEmail) {
    throw new Error("Session e-mail unexpectedly not set");
  }

  // Fetch some things
  const { saltEnc, encSymmetricKey } = await _whoami(sessionId);
  const { saltKey, saltAuth } = await _getAuthSalts(newEmail, sessionId);
  // Generate some secrets for the user based on password
  const newSecret = await crypt.deriveKey(newPassphrase, newEmail, saltEnc);
  const newAuthSecret = await crypt.deriveKey(newPassphrase, newEmail, saltKey);
  const newVerifier = computeVerifier(
    _getSrpParams(),
    Buffer.from(saltAuth, "hex"),
    Buffer.from(newEmail || "", "utf8"),
    Buffer.from(newAuthSecret, "hex")
  ).toString("hex");
  // Re-encrypt existing keys with new secret
  const symmetricKey = JSON.stringify(_getSymmetricKey());
  const newEncSymmetricKeyJSON = crypt.encryptAES(newSecret, symmetricKey);
  const newEncSymmetricKey = JSON.stringify(newEncSymmetricKeyJSON);
  const response = await fetch("http://localhost:8000/auth/change-password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: confirmationCode,
      newEmail: newEmail,
      encSymmetricKey: encSymmetricKey,
      newVerifier,
      newEncSymmetricKey
    })
  });

  return response.json();
}

export async function sendPasswordChangeCode() {
  const response = await fetch(
    "http://localhost:8000/auth/send-password-code",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      }
    }
  );

  const data = await response.json();

  return data;
}

export function getPublicKey() {
  return getSessionData()?.publicKey;
}

export function getPrivateKey() {
  const sessionData = getSessionData();

  if (!sessionData) {
    throw new Error("Can't get private key: session is blank.");
  }

  const { symmetricKey, encPrivateKey } = sessionData;

  if (!symmetricKey || !encPrivateKey) {
    throw new Error("Can't get private key: session is missing keys.");
  }

  const privateKeyStr = crypt.decryptAES(symmetricKey, encPrivateKey);
  return JSON.parse(privateKeyStr);
}

export function getCurrentSessionId() {
  if (window) {
    return window.localStorage.getItem("currentSessionId");
  } else {
    return "";
  }
}

export function getAccountId() {
  return getSessionData()?.accountId;
}

export function getEmail() {
  return getSessionData()?.email;
}

export function getFirstName() {
  return getSessionData()?.firstName;
}

export function getLastName() {
  return getSessionData()?.lastName;
}

export function getFullName() {
  return `${getFirstName()} ${getLastName()}`.trim();
}

/** Check if we (think) we have a session */
export function isLoggedIn() {
  return !!getCurrentSessionId();
}

/** Set data for the new session and store it encrypted with the sessionId */
export function setSessionData(sessionData: {
  id: string;
  accountId: string;
  firstName: string;
  lastName: string;
  email: string;
  symmetricKey: JsonWebKey;
  publicKey: JsonWebKey;
  encPrivateKey: crypt.AESMessage;
}) {
  const dataStr = JSON.stringify(sessionData);
  window.localStorage.setItem(_getSessionKey(sessionData.id), dataStr);
  // NOTE: We're setting this last because the stuff above might fail
  window.localStorage.setItem("currentSessionId", sessionData.id);
}
export async function listTeams(sessionId: string | null) {
  const response = await fetch("http://localhost:8000/api/teams", {
    headers: {
      include: "credentials",
      ...(sessionId ? { Authorization: "Bearer " + sessionId } : {})
    }
  });

  const data: Team[] = await response.json();

  return data;
}

// ~~~~~~~~~~~~~~~~ //
// Helper Functions //
// ~~~~~~~~~~~~~~~~ //
function _getSymmetricKey() {
  return getSessionData()?.symmetricKey;
}

async function _whoami(sessionId: string | null) {
  const response = await fetch("http://localhost:8000/auth/whoami", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      include: "credentials",
      ...(sessionId ? { Authorization: "Bearer " + sessionId } : {})
    }
  });

  const data: WhoamiResponse = await response.json();

  return data;
}

async function _getAuthSalts(email: string, sessionId: string | null) {
  const response = await fetch("http://localhost:8000/auth/login-s", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(sessionId ? { Authorization: "Bearer " + sessionId } : {})
    },
    body: JSON.stringify({ email })
  });

  const data: AuthSalts = await response.json();

  return data;
}

const getSessionData = () => {
  const sessionId = getCurrentSessionId();

  if (!sessionId || typeof window === "undefined") {
    return null;
  }

  const dataStr = window.localStorage.getItem(_getSessionKey(sessionId));
  if (dataStr === null) {
    return null;
  }
  const data = JSON.parse(dataStr) as SessionData;

  return data;
};

function unsetSessionData() {
  const sessionId = getCurrentSessionId();
  window.localStorage.removeItem(_getSessionKey(sessionId));
  window.localStorage.removeItem("currentSessionId");
  sessionEvents.logout();
}

function _getSessionKey(sessionId: string | null) {
  return `session__${(sessionId || "").slice(0, 10)}`;
}

function _getSrpParams() {
  return params[2048];
}

function _sanitizePassphrase(passphrase: string) {
  return passphrase.trim().normalize("NFKD");
}

interface AuthBox {
  token: string;
  key: string;
}

async function authorizeApp({
  email,
  password,
  whoami: currentWhoami,
  b64LoginKey,
}: {
  email: string;
  password: string;
  whoami?: WhoamiResponse;
  b64LoginKey?: string;
}) {
  let box: AuthBox;

  try {
    if (!currentWhoami) {
      await login(email, password);
      currentWhoami = await whoami();
    }

    const token = await login(email, password, undefined, false);
    const key = await deriveSymmetricKey(currentWhoami, password);

    box = { token, key };
  } catch(e) {
    throw new Error(`Authentication failed: ${String(e)}`);
  }

  let loginKey: Uint8Array;
  try {
    loginKey = await base64.decodeBase64(b64LoginKey ?? "");
  } catch(e) {
    throw new Error(`Invalid login key: ${String(e)}`);
  }

  let token: string;
  try {
    const enc = new TextEncoder();
    token = await base64.encodeBase64(sealedbox.seal(enc.encode(JSON.stringify(box)), loginKey));
    return token;
  } catch(e) {
    throw new Error(`Failed to create token: ${String(e)}`);
  }
}
