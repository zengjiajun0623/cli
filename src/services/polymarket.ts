import { parseUnits, type Address } from 'viem';
import type { privateKeyToAccount } from 'viem/accounts';
import type { KeyringService } from './keyring';

// A viem LocalAccount as returned by privateKeyToAccount — narrow helper type
// so scopedSignTypedData doesn't need to know whether it's owner or subkey.
type SigningAccount = ReturnType<typeof privateKeyToAccount>;

// ─── Constants ─────────────────────────────────────────────────────
//
// Polymarket v2 migration — April 2026. This service targets:
//   - CTF Exchange V2 (new optimized contract, EIP-712 domain version "2")
//   - New collateral token: Polymarket USD (wrapped onramp of USDC.e)
//   - New 11-field Order struct (dropped taker/expiration/nonce/feeRateBps,
//     added timestamp/metadata/builder)
//   - POLY_1271 signature type is now available for smart-contract wallets,
//     though this service defaults to EOA type (used via subkey) to preserve
//     the existing scoped-signer architecture
//
// v1 addresses are left as comments for reference — the v1 exchange is still
// live during the migration window but v2 is now the canonical target.

const CLOB_BASE = 'https://clob.polymarket.com';
const GAMMA_BASE = 'https://gamma-api.polymarket.com';
const CHAIN_ID = 137; // Polygon
const COLLATERAL_DECIMALS = 6;

// Polygon contract addresses — per-version.
//
// Both v1 and v2 are kept because the CLOB server migration is staged:
// the v2 contracts are deployed, the v2 TypeScript client is published,
// but clob.polymarket.com still reports `{"version": 1}` during the
// rollout window (Polymarket's announced 2-3 week migration from April 6).
// We call /version at runtime to dispatch — see `resolveClobVersion()`.
//
// v1 contracts (legacy but currently live)
const CONTRACTS_V1 = {
  exchange: '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E' as Address,
  negRiskExchange: '0xC5d563A36AE78145C45a50134d48A1215220f80a' as Address,
  negRiskAdapter: '0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296' as Address,
  // v1 collateral is USDC.e directly
  collateral: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174' as Address,
  conditionalTokens: '0x4D97DCd97eC945f40cF65F87097ACe5EA0476045' as Address,
};

// v2 contracts (deployed, waiting on server rollout)
const CONTRACTS_V2 = {
  exchange: '0xE111180000d2663C0091e4f400237545B87B996B' as Address,
  negRiskExchange: '0xe2222d279d744050d28e00520010520000310F59' as Address,
  negRiskAdapter: '0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296' as Address,
  // v2 collateral is Polymarket USD (wrapped via CollateralOnramp)
  collateral: '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB' as Address,
  collateralOnramp: '0x93070a847efEf7F70739046A929D47a521F5B8ee' as Address,
  collateralOfframp: '0x2957922Eb93258b93368531d39fAcCA3B4dC5854' as Address,
  ctfCollateralAdapter: '0xADa100874d00e3331D00F2007a9c336a65009718' as Address,
  negRiskCtfCollateralAdapter: '0xAdA200001000ef00D07553cEE7006808F895c6F1' as Address,
  conditionalTokens: '0x4D97DCd97eC945f40cF65F87097ACe5EA0476045' as Address,
};

// Union type + current export — commands reference CONTRACTS.collateral etc.
// During the migration window this default points at v1. Once the server
// reports v2, `pickContracts(version)` switches.
const CONTRACTS = CONTRACTS_V1;
function pickContracts(version: 1 | 2) {
  return version === 2 ? CONTRACTS_V2 : CONTRACTS_V1;
}

// ─── EIP-712 Types ─────────────────────────────────────────────────

/** CLOB auth domain for L1 (API key creation). Unchanged between v1 and v2. */
const CLOB_AUTH_DOMAIN = {
  name: 'ClobAuthDomain' as const,
  version: '1' as const,
  chainId: CHAIN_ID,
};

const CLOB_AUTH_TYPES = {
  ClobAuth: [
    { name: 'address', type: 'address' },
    { name: 'timestamp', type: 'string' },
    { name: 'nonce', type: 'uint256' },
    { name: 'message', type: 'string' },
  ],
} as const;

const MSG_TO_SIGN = 'This message attests that I control the given wallet';

/**
 * Order signing domain — v1 Polymarket CTF Exchange.
 * Used when the CLOB server reports version 1.
 */
const ORDER_DOMAIN_V1 = {
  name: 'Polymarket CTF Exchange' as const,
  version: '1' as const,
  chainId: CHAIN_ID,
};

/**
 * Order signing domain — v2 Polymarket CTF Exchange.
 * Used when the CLOB server reports version 2.
 */
const ORDER_DOMAIN_V2 = {
  name: 'Polymarket CTF Exchange' as const,
  version: '2' as const,
  chainId: CHAIN_ID,
};

/** V1 order struct — 12 fields including taker/expiration/nonce/feeRateBps. */
const ORDER_TYPES_V1 = {
  Order: [
    { name: 'salt', type: 'uint256' },
    { name: 'maker', type: 'address' },
    { name: 'signer', type: 'address' },
    { name: 'taker', type: 'address' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'makerAmount', type: 'uint256' },
    { name: 'takerAmount', type: 'uint256' },
    { name: 'expiration', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'feeRateBps', type: 'uint256' },
    { name: 'side', type: 'uint8' },
    { name: 'signatureType', type: 'uint8' },
  ],
} as const;

/**
 * V2 Order struct — 11 fields.
 *
 * Dropped from v1: `taker`, `expiration`, `nonce`, `feeRateBps`
 *   - The v2 server enforces a max clock skew relative to `timestamp` rather
 *     than a client-specified expiration
 *   - Nonces are no longer part of the signed order struct
 *   - Fees are collected by the exchange based on market config, not signed
 *     into the order
 *
 * New in v2: `timestamp` (unix ms), `metadata` (bytes32, client-attached
 * metadata hash), `builder` (bytes32, builder attribution code; zero if none)
 */
const ORDER_TYPES_V2 = {
  Order: [
    { name: 'salt', type: 'uint256' },
    { name: 'maker', type: 'address' },
    { name: 'signer', type: 'address' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'makerAmount', type: 'uint256' },
    { name: 'takerAmount', type: 'uint256' },
    { name: 'side', type: 'uint8' },
    { name: 'signatureType', type: 'uint8' },
    { name: 'timestamp', type: 'uint256' },
    { name: 'metadata', type: 'bytes32' },
    { name: 'builder', type: 'bytes32' },
  ],
} as const;

/** Zero address used as default taker for v1 orders. */
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as Address;

/** Zero bytes32 used as default metadata / builder when not set. */
const BYTES32_ZERO =
  '0x0000000000000000000000000000000000000000000000000000000000000000' as `0x${string}`;

// ─── Types ─────────────────────────────────────────────────────────

export interface ApiKeyCreds {
  key: string;
  secret: string;
  passphrase: string;
}

export enum Side {
  BUY = 'BUY',
  SELL = 'SELL',
}

export enum OrderType {
  GTC = 'GTC',
  FOK = 'FOK',
  GTD = 'GTD',
  FAK = 'FAK',
}

enum OrderSide {
  BUY = 0,
  SELL = 1,
}

enum SignatureType {
  /** ECDSA EIP-712 signatures signed by EOAs (this is what the subkey flow uses) */
  EOA = 0,
  /** EIP-712 signatures signed by EOAs that own Polymarket Proxy wallets */
  POLY_PROXY = 1,
  /** EIP-712 signatures signed by EOAs that own Polymarket Gnosis Safes */
  POLY_GNOSIS_SAFE = 2,
  /** EIP-1271 signatures signed by smart contract wallets (v2 only; available
   *  for direct Elytro smart-account signing as a future alternative to the
   *  subkey pattern) */
  POLY_1271 = 3,
}

export interface OrderBookSummary {
  market: string;
  asset_id: string;
  bids: { price: string; size: string }[];
  asks: { price: string; size: string }[];
  hash: string;
  timestamp: string;
}

export interface OrderResponse {
  success: boolean;
  errorMsg: string;
  orderID: string;
  transactionsHashes: string[];
  status: string;
}

export interface OpenOrder {
  id: string;
  status: string;
  market: string;
  asset_id: string;
  side: string;
  original_size: string;
  size_matched: string;
  price: string;
  outcome: string;
  created_at: number;
  order_type: string;
}

export interface GammaMarket {
  id: string;
  question: string;
  description: string;
  outcomes: string;
  outcomePrices: string;
  volume: string;
  active: boolean;
  closed: boolean;
  liquidity: string;
  slug: string;
  endDate: string;
  clobTokenIds: string;
  conditionId: string;
  negRisk: boolean;
}

/**
 * Signed order — superset of v1 and v2 fields. Fields optional on v1 (taker,
 * expiration, nonce, feeRateBps) are always present on a v1 build; the v2
 * fields (timestamp, metadata, builder) are always present on a v2 build.
 * The `version` discriminator tells `postOrder` which payload shape to send.
 */
interface SignedOrder {
  version: 1 | 2;
  salt: string;
  maker: string;
  signer: string;
  tokenId: string;
  makerAmount: string;
  takerAmount: string;
  side: OrderSide;
  signatureType: SignatureType;
  signature: string;
  // v1-only
  taker?: string;
  expiration?: string;
  nonce?: string;
  feeRateBps?: string;
  // v2-only
  timestamp?: string;
  metadata?: string;
  builder?: string;
}

// ─── HMAC-SHA256 (L2 Auth) ─────────────────────────────────────────

async function buildHmacSignature(
  secret: string,
  timestamp: number,
  method: string,
  requestPath: string,
  body?: string,
): Promise<string> {
  let message = `${timestamp}${method}${requestPath}`;
  if (body !== undefined) message += body;

  // Decode base64url → base64
  const sanitized = secret
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/[^A-Za-z0-9+/=]/g, '');
  const binaryString = atob(sanitized);
  const keyData = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    keyData[i] = binaryString.charCodeAt(i);
  }

  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const messageBuffer = new TextEncoder().encode(message);
  const signatureBuffer = await globalThis.crypto.subtle.sign('HMAC', cryptoKey, messageBuffer);

  // base64 → url-safe base64
  const bytes = new Uint8Array(signatureBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const sig = btoa(binary);
  return sig.replace(/\+/g, '-').replace(/\//g, '_');
}

// ─── Scoped Signer ─────────────────────────────────────────────────
//
// Security: this helper ONLY signs Polymarket-specific EIP-712 typed data:
//   1. ClobAuthDomain          — for API key derivation
//   2. Polymarket CTF Exchange — for order signing
// Any other domain is rejected. Combined with the subkey pattern (a scoped
// EOA that is disjoint from any smart-account owner), an attacker that
// reaches this signer can only produce Polymarket orders or CLOB auth,
// and only for the balance sitting on the subkey — not the owner EOA or
// any smart account the owner controls.
//
// The account argument is a viem LocalAccount — caller decides whether
// that's an owner key or a subkey. Signing goes straight through
// account.signTypedData, no walletClient needed.

const ALLOWED_DOMAINS = new Set(['ClobAuthDomain', 'Polymarket CTF Exchange']);

async function scopedSignTypedData(
  account: SigningAccount,
  params: {
    domain: { name?: string; [key: string]: unknown };
    // Accept both readonly and mutable shapes. The EIP-712 type tables are
    // declared `as const` elsewhere in this file which produces readonly
    // arrays; viem's signTypedData accepts them at runtime, and we only
    // pass them through without mutation.
    types: Readonly<
      Record<string, ReadonlyArray<{ readonly name: string; readonly type: string }>>
    >;
    primaryType: string;
    message: Record<string, unknown>;
  },
): Promise<string> {
  const domainName = params.domain.name as string | undefined;
  if (!domainName || !ALLOWED_DOMAINS.has(domainName)) {
    throw new Error(
      `Scoped signer rejected: domain "${domainName ?? 'unknown'}" is not allowed. ` +
        `Only Polymarket domains are permitted: ${[...ALLOWED_DOMAINS].join(', ')}.`,
    );
  }

  return account.signTypedData({
    domain: params.domain,
    types: params.types,
    primaryType: params.primaryType,
    // viem's signTypedData infers the message shape from types — cast to any-compatible.
    message: params.message,
  } as Parameters<SigningAccount['signTypedData']>[0]);
}

// ─── Polymarket Service ────────────────────────────────────────────

export class PolymarketService {
  private keyring: KeyringService;
  private creds: ApiKeyCreds | null = null;
  /**
   * If set, all trading signatures use this subkey (label or address) instead
   * of the current smart-account owner key. Subkeys are scoped EOAs disjoint
   * from owners — compromise bounded to subkey balance.
   */
  private subkeyRef: string | null = null;

  /**
   * Cached CLOB API version fetched from /version. `null` until the first call.
   * Polymarket is mid-migration (v1 → v2) and the switch-over happens on the
   * server side over a 2-3 week window starting April 6. The signing path
   * and the REST payload shape both depend on which version the server is
   * currently running, so we fetch and cache it at first use.
   */
  private clobVersion: 1 | 2 | null = null;

  constructor(keyring: KeyringService, subkeyRef?: string) {
    this.keyring = keyring;
    this.subkeyRef = subkeyRef ?? null;
  }

  /**
   * Resolve the CLOB server version by hitting /version.
   * Caches the result for the lifetime of this service instance.
   *
   * The clob-client-v2 reference implementation falls back to 2 on a
   * missing response; we prefer 1 as a safer default because the current
   * production host is on v1 and a v1 fallback lets us sign orders the
   * server will accept.
   */
  async resolveClobVersion(): Promise<1 | 2> {
    if (this.clobVersion !== null) return this.clobVersion;
    try {
      const res = await fetch(`${CLOB_BASE}/version`);
      if (!res.ok) {
        // If /version is unreachable, default to v1 (currently deployed)
        this.clobVersion = 1;
        return 1;
      }
      const body = (await res.json()) as { version?: number };
      this.clobVersion = body.version === 2 ? 2 : 1;
      return this.clobVersion;
    } catch {
      this.clobVersion = 1;
      return 1;
    }
  }

  /** Returns the viem LocalAccount to use for Polymarket-scoped signing. */
  private getSigningAccount(): SigningAccount {
    if (this.subkeyRef) {
      return this.keyring.getSubkeyAccount(this.subkeyRef);
    }
    return this.keyring.getAccount();
  }

  get signerAddress(): Address {
    return this.getSigningAccount().address;
  }

  /** Human-readable source label for display: "owner" or `subkey:<label>`. */
  get signerSource(): string {
    return this.subkeyRef ? `subkey:${this.subkeyRef}` : 'owner';
  }

  // ── L1 Auth: EIP-712 signature for API key creation ──────────────

  private async buildL1Signature(
    nonce = 0,
    timestamp?: number,
  ): Promise<{ sig: string; ts: number }> {
    const ts = timestamp ?? Math.floor(Date.now() / 1000);

    // Uses scoped signer — only ClobAuthDomain is allowed
    const sig = await scopedSignTypedData(this.getSigningAccount(), {
      domain: CLOB_AUTH_DOMAIN,
      types: CLOB_AUTH_TYPES,
      primaryType: 'ClobAuth',
      message: {
        address: this.signerAddress,
        timestamp: `${ts}`,
        nonce: BigInt(nonce),
        message: MSG_TO_SIGN,
      },
    });
    return { sig, ts };
  }

  private l1Headers(sig: string, ts: number, nonce = 0) {
    return {
      POLY_ADDRESS: this.signerAddress,
      POLY_SIGNATURE: sig,
      POLY_TIMESTAMP: `${ts}`,
      POLY_NONCE: `${nonce}`,
    };
  }

  // ── L2 Auth: HMAC headers for trading ────────────────────────────

  private async l2Headers(method: string, requestPath: string, body?: string) {
    if (!this.creds) throw new Error('Not authenticated. Run `elytro polymarket auth` first.');
    const ts = Math.floor(Date.now() / 1000);
    const sig = await buildHmacSignature(this.creds.secret, ts, method, requestPath, body);
    return {
      POLY_ADDRESS: this.signerAddress,
      POLY_SIGNATURE: sig,
      POLY_TIMESTAMP: `${ts}`,
      POLY_API_KEY: this.creds.key,
      POLY_PASSPHRASE: this.creds.passphrase,
    };
  }

  // ── Credential Management ────────────────────────────────────────

  setCreds(creds: ApiKeyCreds): void {
    this.creds = creds;
  }

  get isAuthenticated(): boolean {
    return this.creds !== null;
  }

  /** Create or derive API key credentials from the CLOB server. */
  async deriveApiKey(nonce = 0): Promise<ApiKeyCreds> {
    const { sig, ts } = await this.buildL1Signature(nonce);
    const headers = this.l1Headers(sig, ts, nonce);

    const res = await fetch(`${CLOB_BASE}/auth/derive-api-key`, {
      method: 'GET',
      headers: headers as Record<string, string>,
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to derive API key (${res.status}): ${text}`);
    }
    const raw = (await res.json()) as { apiKey: string; secret: string; passphrase: string };
    const creds: ApiKeyCreds = { key: raw.apiKey, secret: raw.secret, passphrase: raw.passphrase };
    this.creds = creds;
    return creds;
  }

  async createApiKey(nonce = 0): Promise<ApiKeyCreds> {
    const { sig, ts } = await this.buildL1Signature(nonce);
    const headers = this.l1Headers(sig, ts, nonce);

    const res = await fetch(`${CLOB_BASE}/auth/api-key`, {
      method: 'POST',
      headers: {
        ...(headers as Record<string, string>),
        'Content-Type': 'application/json',
      },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to create API key (${res.status}): ${text}`);
    }
    const raw = (await res.json()) as { apiKey: string; secret: string; passphrase: string };
    const creds: ApiKeyCreds = { key: raw.apiKey, secret: raw.secret, passphrase: raw.passphrase };
    this.creds = creds;
    return creds;
  }

  // ── Public Market Data (no auth) ─────────────────────────────────

  async getMarkets(
    params: {
      active?: boolean;
      closed?: boolean;
      limit?: number;
      offset?: number;
      order?: string;
      ascending?: boolean;
    } = {},
  ): Promise<GammaMarket[]> {
    const qs = new URLSearchParams();
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.offset !== undefined) qs.set('offset', String(params.offset));
    if (params.active !== undefined) qs.set('active', String(params.active));
    if (params.closed !== undefined) qs.set('closed', String(params.closed));
    if (params.order) qs.set('order', params.order);
    // Gamma defaults to ascending=true when an order is specified, which is
    // almost never what a caller wants ("top N by volume" means descending).
    // Always set the flag explicitly; default to descending.
    qs.set('ascending', params.ascending ? 'true' : 'false');

    const res = await fetch(`${GAMMA_BASE}/markets?${qs}`);
    if (!res.ok) throw new Error(`Gamma API error: ${res.status}`);
    return res.json() as Promise<GammaMarket[]>;
  }

  async getMarket(idOrSlug: string): Promise<GammaMarket> {
    // Gamma API: numeric IDs use /markets/<id>, slugs use ?slug=<slug>
    const isNumeric = /^\d+$/.test(idOrSlug);
    const url = isNumeric
      ? `${GAMMA_BASE}/markets/${idOrSlug}`
      : `${GAMMA_BASE}/markets?slug=${encodeURIComponent(idOrSlug)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Gamma API error: ${res.status}`);
    const data = await res.json();
    // slug query returns array, numeric returns single object
    if (Array.isArray(data)) {
      if (data.length === 0) throw new Error(`Market not found: ${idOrSlug}`);
      return data[0] as GammaMarket;
    }
    return data as GammaMarket;
  }

  async searchMarkets(query: string, limit = 10): Promise<GammaMarket[]> {
    const qs = new URLSearchParams({ q: query, limit: String(limit) });
    const res = await fetch(`${GAMMA_BASE}/markets?${qs}`);
    if (!res.ok) throw new Error(`Gamma API error: ${res.status}`);
    return res.json() as Promise<GammaMarket[]>;
  }

  // ── Geoblock / Ban Status ─────────────────────────────────────────

  async checkGeoblock(): Promise<{ closed_only: boolean }> {
    const headers = await this.l2Headers('GET', '/auth/ban-status/closed-only');
    const res = await fetch(`${CLOB_BASE}/auth/ban-status/closed-only`, {
      headers: headers as Record<string, string>,
    });
    if (!res.ok) throw new Error(`Geoblock check error: ${res.status} ${await res.text()}`);
    return res.json() as Promise<{ closed_only: boolean }>;
  }

  // ── CLOB Public Data ─────────────────────────────────────────────

  async getPrice(tokenId: string, side: Side): Promise<{ price: string }> {
    const qs = new URLSearchParams({ token_id: tokenId, side });
    const res = await fetch(`${CLOB_BASE}/price?${qs}`);
    if (!res.ok) throw new Error(`CLOB price error: ${res.status}`);
    return res.json() as Promise<{ price: string }>;
  }

  async getMidpoint(tokenId: string): Promise<{ mid: string }> {
    const qs = new URLSearchParams({ token_id: tokenId });
    const res = await fetch(`${CLOB_BASE}/midpoint?${qs}`);
    if (!res.ok) throw new Error(`CLOB midpoint error: ${res.status}`);
    return res.json() as Promise<{ mid: string }>;
  }

  async getOrderBook(tokenId: string): Promise<OrderBookSummary> {
    const qs = new URLSearchParams({ token_id: tokenId });
    const res = await fetch(`${CLOB_BASE}/book?${qs}`);
    if (!res.ok) throw new Error(`CLOB book error: ${res.status}`);
    return res.json() as Promise<OrderBookSummary>;
  }

  async getSpread(tokenId: string): Promise<{ spread: string }> {
    const qs = new URLSearchParams({ token_id: tokenId });
    const res = await fetch(`${CLOB_BASE}/spread?${qs}`);
    if (!res.ok) throw new Error(`CLOB spread error: ${res.status}`);
    return res.json() as Promise<{ spread: string }>;
  }

  async getTickSize(tokenId: string): Promise<{ minimum_tick_size: string }> {
    const qs = new URLSearchParams({ token_id: tokenId });
    const res = await fetch(`${CLOB_BASE}/tick-size?${qs}`);
    if (!res.ok) throw new Error(`CLOB tick-size error: ${res.status}`);
    return res.json() as Promise<{ minimum_tick_size: string }>;
  }

  async getServerTime(): Promise<number> {
    const res = await fetch(`${CLOB_BASE}/time`);
    if (!res.ok) throw new Error(`CLOB time error: ${res.status}`);
    return res.json() as Promise<number>;
  }

  // ── Authenticated Trading ────────────────────────────────────────

  async getBalance(
    assetType: 'COLLATERAL' | 'CONDITIONAL' = 'COLLATERAL',
    tokenId?: string,
  ): Promise<{ balance: string; allowance: string }> {
    const qs = new URLSearchParams({
      asset_type: assetType,
      signature_type: '0', // EOA
    });
    if (tokenId) qs.set('token_id', tokenId);

    // HMAC signature covers only the endpoint path, not query params
    const headers = await this.l2Headers('GET', '/balance-allowance');
    const res = await fetch(`${CLOB_BASE}/balance-allowance?${qs}`, {
      headers: headers as Record<string, string>,
    });
    if (!res.ok) throw new Error(`Balance error: ${res.status} ${await res.text()}`);
    return res.json() as Promise<{ balance: string; allowance: string }>;
  }

  async getOpenOrders(params: { market?: string; asset_id?: string } = {}): Promise<OpenOrder[]> {
    const qs = new URLSearchParams();
    if (params.market) qs.set('market', params.market);
    if (params.asset_id) qs.set('asset_id', params.asset_id);

    // Paginate through all results
    let allOrders: OpenOrder[] = [];
    let cursor = 'MA=='; // INITIAL_CURSOR (base64 of "0")
    const endCursor = 'LTE='; // END_CURSOR (base64 of "-1")

    while (cursor !== endCursor) {
      const pageQs = new URLSearchParams(qs);
      pageQs.set('next_cursor', cursor);

      // HMAC signature covers only the endpoint path
      const headers = await this.l2Headers('GET', '/data/orders');
      const res = await fetch(`${CLOB_BASE}/data/orders?${pageQs}`, {
        headers: headers as Record<string, string>,
      });
      if (!res.ok) throw new Error(`Orders error: ${res.status} ${await res.text()}`);

      const body = (await res.json()) as { data: OpenOrder[]; next_cursor: string };
      allOrders = [...allOrders, ...body.data];
      cursor = body.next_cursor;
    }

    return allOrders;
  }

  /** Create and sign a limit order, then post it. */
  async createOrder(params: {
    tokenId: string;
    side: Side;
    price: number;
    size: number;
    orderType?: OrderType;
    negRisk?: boolean;
  }): Promise<OrderResponse> {
    const signedOrder = await this.buildAndSignOrder(params);
    return this.postOrder(signedOrder, params.orderType ?? OrderType.GTC);
  }

  async cancelOrder(orderId: string): Promise<{ canceled: string[] }> {
    const body = JSON.stringify({ orderID: orderId });
    const headers = await this.l2Headers('DELETE', '/order', body);
    const res = await fetch(`${CLOB_BASE}/order`, {
      method: 'DELETE',
      headers: { ...(headers as Record<string, string>), 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok) throw new Error(`Cancel error: ${res.status} ${await res.text()}`);
    return res.json() as Promise<{ canceled: string[] }>;
  }

  async cancelAll(): Promise<{ canceled: string[] }> {
    const headers = await this.l2Headers('DELETE', '/cancel-all');
    const res = await fetch(`${CLOB_BASE}/cancel-all`, {
      method: 'DELETE',
      headers: headers as Record<string, string>,
    });
    if (!res.ok) throw new Error(`Cancel-all error: ${res.status} ${await res.text()}`);
    return res.json() as Promise<{ canceled: string[] }>;
  }

  // ── Order Building & Signing ─────────────────────────────────────

  private async buildAndSignOrder(params: {
    tokenId: string;
    side: Side;
    price: number;
    size: number;
    negRisk?: boolean;
  }): Promise<SignedOrder> {
    const version = await this.resolveClobVersion();
    const address = this.signerAddress;
    const sideNum = params.side === Side.BUY ? OrderSide.BUY : OrderSide.SELL;

    // Compute maker/taker amounts from price/size
    const { rawMakerAmt, rawTakerAmt } = this.getOrderRawAmounts(
      params.side,
      params.size,
      params.price,
    );
    const makerAmount = parseUnits(rawMakerAmt.toFixed(6), COLLATERAL_DECIMALS).toString();
    const takerAmount = parseUnits(rawTakerAmt.toFixed(6), COLLATERAL_DECIMALS).toString();

    const contracts = pickContracts(version);
    const exchangeAddress = params.negRisk ? contracts.negRiskExchange : contracts.exchange;
    const salt = Math.round(Math.random() * Date.now()).toString();

    if (version === 1) {
      // V1 signing path: 12-field struct with taker/expiration/nonce/feeRateBps
      const order = {
        salt,
        maker: address,
        signer: address,
        taker: ZERO_ADDRESS,
        tokenId: params.tokenId,
        makerAmount,
        takerAmount,
        expiration: '0',
        nonce: '0',
        feeRateBps: '0',
        side: sideNum,
        signatureType: SignatureType.EOA,
      };

      const signature = await scopedSignTypedData(this.getSigningAccount(), {
        domain: { ...ORDER_DOMAIN_V1, verifyingContract: exchangeAddress },
        types: ORDER_TYPES_V1,
        primaryType: 'Order',
        message: {
          salt: BigInt(order.salt),
          maker: order.maker as Address,
          signer: order.signer as Address,
          taker: order.taker as Address,
          tokenId: BigInt(order.tokenId),
          makerAmount: BigInt(order.makerAmount),
          takerAmount: BigInt(order.takerAmount),
          expiration: BigInt(order.expiration),
          nonce: BigInt(order.nonce),
          feeRateBps: BigInt(order.feeRateBps),
          side: order.side,
          signatureType: order.signatureType,
        },
      });

      return { version: 1, ...order, signature };
    }

    // V2 signing path: 11-field struct with timestamp/metadata/builder
    // (taker/expiration/nonce/feeRateBps dropped from the signed struct)
    const timestamp = Date.now().toString();
    const order = {
      salt,
      maker: address,
      signer: address,
      tokenId: params.tokenId,
      makerAmount,
      takerAmount,
      side: sideNum,
      signatureType: SignatureType.EOA,
      timestamp,
      metadata: BYTES32_ZERO,
      builder: BYTES32_ZERO,
    };

    const signature = await scopedSignTypedData(this.getSigningAccount(), {
      domain: { ...ORDER_DOMAIN_V2, verifyingContract: exchangeAddress },
      types: ORDER_TYPES_V2,
      primaryType: 'Order',
      message: {
        salt: BigInt(order.salt),
        maker: order.maker as Address,
        signer: order.signer as Address,
        tokenId: BigInt(order.tokenId),
        makerAmount: BigInt(order.makerAmount),
        takerAmount: BigInt(order.takerAmount),
        side: order.side,
        signatureType: order.signatureType,
        timestamp: BigInt(order.timestamp),
        metadata: order.metadata,
        builder: order.builder,
      },
    });

    return { version: 2, ...order, signature };
  }

  private getOrderRawAmounts(
    side: Side,
    size: number,
    price: number,
  ): { rawMakerAmt: number; rawTakerAmt: number } {
    if (side === Side.BUY) {
      const rawTakerAmt = Math.floor(size * 100) / 100;
      let rawMakerAmt = rawTakerAmt * price;
      rawMakerAmt = Math.floor(rawMakerAmt * 1_000_000) / 1_000_000;
      return { rawMakerAmt, rawTakerAmt };
    }
    const rawMakerAmt = Math.floor(size * 100) / 100;
    let rawTakerAmt = rawMakerAmt * price;
    rawTakerAmt = Math.floor(rawTakerAmt * 1_000_000) / 1_000_000;
    return { rawMakerAmt, rawTakerAmt };
  }

  private async postOrder(signedOrder: SignedOrder, orderType: OrderType): Promise<OrderResponse> {
    // The POST /order payload shape is version-specific. The signed struct
    // that goes in `order` must match exactly what the server's version
    // expects, otherwise it fails parsing (v1 server gets confused by v2
    // missing `feeRateBps`, v2 server gets confused by v1 missing `timestamp`).
    let orderBody: Record<string, unknown>;
    if (signedOrder.version === 1) {
      orderBody = {
        salt: Number(signedOrder.salt),
        maker: signedOrder.maker,
        signer: signedOrder.signer,
        taker: signedOrder.taker,
        tokenId: signedOrder.tokenId,
        makerAmount: signedOrder.makerAmount,
        takerAmount: signedOrder.takerAmount,
        expiration: signedOrder.expiration,
        nonce: signedOrder.nonce,
        feeRateBps: signedOrder.feeRateBps,
        side: signedOrder.side === OrderSide.BUY ? 'BUY' : 'SELL',
        signatureType: signedOrder.signatureType,
        signature: signedOrder.signature,
      };
    } else {
      orderBody = {
        salt: Number(signedOrder.salt),
        maker: signedOrder.maker,
        signer: signedOrder.signer,
        tokenId: signedOrder.tokenId,
        makerAmount: signedOrder.makerAmount,
        takerAmount: signedOrder.takerAmount,
        side: signedOrder.side === OrderSide.BUY ? 'BUY' : 'SELL',
        signatureType: signedOrder.signatureType,
        timestamp: signedOrder.timestamp,
        metadata: signedOrder.metadata,
        builder: signedOrder.builder,
        signature: signedOrder.signature,
      };
    }
    const payload = {
      order: orderBody,
      owner: this.creds!.key,
      orderType,
    };

    const body = JSON.stringify(payload);
    const headers = await this.l2Headers('POST', '/order', body);
    const res = await fetch(`${CLOB_BASE}/order`, {
      method: 'POST',
      headers: { ...(headers as Record<string, string>), 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok) throw new Error(`Post order error: ${res.status} ${await res.text()}`);
    return res.json() as Promise<OrderResponse>;
  }
}
