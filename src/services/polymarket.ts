import { parseUnits, type Address, type WalletClient } from 'viem';
import { createWalletClient, http } from 'viem';
import { polygon } from 'viem/chains';
import type { KeyringService } from './keyring';

// ─── Constants ─────────────────────────────────────────────────────

const CLOB_BASE = 'https://clob.polymarket.com';
const GAMMA_BASE = 'https://gamma-api.polymarket.com';
const CHAIN_ID = 137; // Polygon
const COLLATERAL_DECIMALS = 6;

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as Address;

// Polygon contract addresses
const CONTRACTS = {
  exchange: '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E' as Address,
  negRiskExchange: '0xC5d563A36AE78145C45a50134d48A1215220f80a' as Address,
  negRiskAdapter: '0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296' as Address,
  collateral: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174' as Address,
  conditionalTokens: '0x4D97DCd97eC945f40cF65F87097ACe5EA0476045' as Address,
};

// ─── EIP-712 Types ─────────────────────────────────────────────────

/** CLOB auth domain for L1 (API key creation) */
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

/** Order signing domain (CTF Exchange) */
const ORDER_DOMAIN = {
  name: 'Polymarket CTF Exchange' as const,
  version: '1' as const,
  chainId: CHAIN_ID,
};

const ORDER_TYPES = {
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
  EOA = 0,
  POLY_PROXY = 1,
  POLY_GNOSIS_SAFE = 2,
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

interface SignedOrder {
  salt: string;
  maker: string;
  signer: string;
  taker: string;
  tokenId: string;
  makerAmount: string;
  takerAmount: string;
  expiration: string;
  nonce: string;
  feeRateBps: string;
  side: OrderSide;
  signatureType: SignatureType;
  signature: string;
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
// Security: the agent never gets a general-purpose signer.
// This signer ONLY signs Polymarket-specific EIP-712 typed data:
//   1. ClobAuthDomain  — for API key derivation
//   2. Polymarket CTF Exchange — for order signing
// Any other domain is rejected. This prevents the agent from signing
// arbitrary transactions, token approvals, or messages via the EOA.

const ALLOWED_DOMAINS = new Set(['ClobAuthDomain', 'Polymarket CTF Exchange']);

async function scopedSignTypedData(
  keyring: KeyringService,
  params: {
    domain: { name?: string; [key: string]: unknown };
    types: Record<string, Array<{ name: string; type: string }>>;
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

  const account = keyring.getAccount();
  const walletClient = createWalletClient({
    account,
    chain: polygon,
    transport: http('https://polygon-bor-rpc.publicnode.com'),
  });

  return walletClient.signTypedData({
    account,
    domain: params.domain,
    types: params.types,
    primaryType: params.primaryType,
    message: params.message,
  } as Parameters<WalletClient['signTypedData']>[0]);
}

// ─── Polymarket Service ────────────────────────────────────────────

export class PolymarketService {
  private keyring: KeyringService;
  private creds: ApiKeyCreds | null = null;

  constructor(keyring: KeyringService) {
    this.keyring = keyring;
  }

  get signerAddress(): Address {
    return this.keyring.getAccount().address;
  }

  // ── L1 Auth: EIP-712 signature for API key creation ──────────────

  private async buildL1Signature(
    nonce = 0,
    timestamp?: number,
  ): Promise<{ sig: string; ts: number }> {
    const ts = timestamp ?? Math.floor(Date.now() / 1000);

    // Uses scoped signer — only ClobAuthDomain is allowed
    const sig = await scopedSignTypedData(this.keyring, {
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
    if (params.ascending) qs.set('ascending', 'true');

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

    const exchangeAddress = params.negRisk ? CONTRACTS.negRiskExchange : CONTRACTS.exchange;
    const salt = Math.round(Math.random() * Date.now()).toString();

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

    // Sign using scoped signer — only "Polymarket CTF Exchange" domain is allowed
    const signature = await scopedSignTypedData(this.keyring, {
      domain: { ...ORDER_DOMAIN, verifyingContract: exchangeAddress },
      types: ORDER_TYPES,
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

    return { ...order, signature };
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
    const payload = {
      order: {
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
      },
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
