import { Command } from 'commander';
import ora from 'ora';
import { encodeFunctionData, parseUnits, formatUnits, type Address } from 'viem';
import type { AppContext } from '../context';
import {
  PolymarketService,
  Side,
  OrderType,
  type ApiKeyCreds,
  type GammaMarket,
} from '../services/polymarket';
import { requestSponsorship, applySponsorToUserOp } from '../utils/sponsor';
import { outputResult, outputError, sanitizeErrorMessage } from '../utils/display';

// Collateral decimals are the same on both v1 (USDC.e) and v2 (Polymarket USD).
// The collateral address itself is resolved per-call inside the approve command
// based on `svc.resolveClobVersion()` — v1 uses USDC.e, v2 uses Polymarket USD.
const COLLATERAL_DECIMALS = 6;

// Minimal ERC-20 ABI for transfer
const ERC20_TRANSFER_ABI = [
  {
    name: 'transfer',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'balanceOf',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
] as const;

// ─── Error Codes ──────────────────────────────────────────────────
const ERR_NOT_AUTH = -32002;
const ERR_INVALID_PARAMS = -32602;
const ERR_INTERNAL = -32000;

// ─── Credential Persistence ────────────────────────────────────────
//
// Keyed by trader address (lowercase) so owner + each subkey maintain
// separate CLOB credentials. Before this was a single global key, which
// leaked auth across signer identities when --subkey was introduced.

function credsStorageKey(traderAddress: Address): string {
  return `polymarket-creds:${traderAddress.toLowerCase()}`;
}

async function loadCreds(ctx: AppContext, traderAddress: Address): Promise<ApiKeyCreds | null> {
  return ctx.store.load<ApiKeyCreds>(credsStorageKey(traderAddress));
}

async function saveCreds(
  ctx: AppContext,
  traderAddress: Address,
  creds: ApiKeyCreds,
): Promise<void> {
  await ctx.store.save(credsStorageKey(traderAddress), creds);
}

function ensureUnlocked(ctx: AppContext): void {
  if (!ctx.keyring.isUnlocked) {
    throw new Error('Wallet not unlocked. Run `elytro init` first.');
  }
}

function createPolyService(ctx: AppContext, subkeyRef?: string): PolymarketService {
  ensureUnlocked(ctx);
  return new PolymarketService(ctx.keyring, subkeyRef);
}

async function ensureAuth(ctx: AppContext, svc: PolymarketService): Promise<void> {
  if (svc.isAuthenticated) return;

  // Try loading persisted credentials keyed on the current signer address
  const saved = await loadCreds(ctx, svc.signerAddress);
  if (saved) {
    svc.setCreds(saved);
    return;
  }

  throw new Error(
    `Not authenticated with Polymarket for ${svc.signerSource} (${svc.signerAddress}). Run \`elytro polymarket ${svc.signerSource.startsWith('subkey:') ? `--subkey ${svc.signerSource.slice(7)} ` : ''}auth\` first.`,
  );
}

// ─── Helpers ──────────────────────────────────────────────────────

function parseSide(s: string): Side {
  const upper = s.toUpperCase();
  if (upper === 'BUY') return Side.BUY;
  if (upper === 'SELL') return Side.SELL;
  throw new Error(`Invalid side "${s}". Must be BUY or SELL.`);
}

function parseOrderType(s: string): OrderType {
  const upper = s.toUpperCase();
  if (upper in OrderType) return upper as OrderType;
  throw new Error(`Invalid order type "${s}". Must be GTC, FOK, GTD, or FAK.`);
}

function formatMarket(m: GammaMarket): Record<string, unknown> {
  let outcomes: string[] = [];
  let prices: string[] = [];
  try {
    outcomes = JSON.parse(m.outcomes || '[]');
  } catch {}
  try {
    prices = JSON.parse(m.outcomePrices || '[]');
  } catch {}

  const formattedOutcomes = outcomes.map((o, i) => `${o}: ${prices[i] ?? '?'}`).join(', ');

  return {
    id: m.id,
    question: m.question,
    outcomes: formattedOutcomes,
    volume: m.volume,
    active: m.active,
    closed: m.closed,
    slug: m.slug,
    endDate: m.endDate,
  };
}

// ─── Command Registration ──────────────────────────────────────────

export function registerPolymarketCommand(program: Command, ctx: AppContext): void {
  const poly = program
    .command('polymarket')
    .alias('pm')
    .description('Polymarket prediction market trading via Elytro wallet')
    .option(
      '--subkey <label>',
      'Scoped trading subkey label (falls back to smart-account owner key if omitted)',
    );

  // ── auth ─────────────────────────────────────────────────────────

  poly
    .command('auth')
    .description('Authenticate with Polymarket CLOB (derive or create API key)')
    .option('--create', 'Create new API key instead of deriving existing')
    .option('--nonce <n>', 'Nonce for key derivation', '0')
    .action(async (opts: { create?: boolean; nonce?: string }) => {
      const spinner = ora('Authenticating with Polymarket...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const nonce = parseInt(opts.nonce ?? '0', 10);
        let creds: ApiKeyCreds;

        if (opts.create) {
          creds = await svc.createApiKey(nonce);
        } else {
          try {
            creds = await svc.deriveApiKey(nonce);
          } catch {
            // If derive fails, try create
            spinner.text = 'Deriving failed, creating new API key...';
            creds = await svc.createApiKey(nonce);
          }
        }

        await saveCreds(ctx, svc.signerAddress, creds);
        spinner.succeed('Authenticated with Polymarket.');
        outputResult({
          status: 'authenticated',
          signerSource: svc.signerSource,
          address: svc.signerAddress,
          apiKey: creds.key,
          hint: `Credentials saved locally (keyed on ${svc.signerAddress}). You can now trade.`,
        });
      } catch (err) {
        spinner.fail('Authentication failed.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── markets ──────────────────────────────────────────────────────

  poly
    .command('markets')
    .description('List prediction markets')
    .option('--active', 'Only active markets')
    .option('--limit <n>', 'Max results', '10')
    .option('--search <query>', 'Search markets by keyword')
    .option(
      '--order <field>',
      'Sort field: volume_num (all-time vol, default), volume24hr (trending today), liquidityClob, etc',
      'volume_num',
    )
    .option('--ascending', 'Sort ascending instead of descending')
    .action(
      async (opts: {
        active?: boolean;
        limit?: string;
        search?: string;
        order?: string;
        ascending?: boolean;
      }) => {
        const spinner = ora('Fetching markets...').start();
        try {
          const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
          const limit = parseInt(opts.limit ?? '10', 10);

          let markets: GammaMarket[];
          if (opts.search) {
            markets = await svc.searchMarkets(opts.search, limit);
          } else {
            markets = await svc.getMarkets({
              active: opts.active,
              limit,
              order: opts.order ?? 'volume_num',
              ascending: opts.ascending,
            });
          }

          spinner.stop();
          if (markets.length === 0) {
            outputResult({ markets: [], message: 'No markets found.' });
            return;
          }
          outputResult({ markets: markets.map(formatMarket) });
        } catch (err) {
          spinner.fail('Failed to fetch markets.');
          outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
        }
      },
    );

  // ── market (single) ──────────────────────────────────────────────

  poly
    .command('market')
    .description('Get details for a specific market')
    .argument('<id>', 'Market condition ID or slug')
    .action(async (id: string) => {
      const spinner = ora('Fetching market...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const market = await svc.getMarket(id);
        spinner.stop();

        let tokenIds: string[] = [];
        try {
          tokenIds = JSON.parse(market.clobTokenIds || '[]');
        } catch {}

        outputResult({
          ...formatMarket(market),
          description: market.description,
          conditionId: market.conditionId,
          tokenIds,
          negRisk: market.negRisk,
          liquidity: market.liquidity,
        });
      } catch (err) {
        spinner.fail('Failed to fetch market.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── price ────────────────────────────────────────────────────────

  poly
    .command('price')
    .description('Get price for a conditional token')
    .argument('<token_id>', 'Conditional token ID')
    .option('--side <side>', 'BUY or SELL', 'BUY')
    .action(async (tokenId: string, opts: { side: string }) => {
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const side = parseSide(opts.side);
        const result = await svc.getPrice(tokenId, side);
        outputResult({ tokenId, side, ...result });
      } catch (err) {
        outputError(ERR_INVALID_PARAMS, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── geoblock ──────────────────────────────────────────────────────
  //
  // Hits Polymarket's CLOB /auth/ban-status/closed-only endpoint using L2
  // HMAC headers to determine whether the current signer is allowed to
  // open new positions. Requires authentication first (runs `auth` if
  // credentials aren't cached) because the ban-status endpoint is L2-gated.
  //
  // Returns { closed_only: boolean }. `closed_only: true` means the
  // authenticated address can close existing positions but cannot open
  // new ones from this IP/jurisdiction. `closed_only: false` means the
  // endpoint does not flag the signer — but note this is NOT a guarantee
  // that a subsequent POST /order will succeed, because the order endpoint
  // runs its own region check that can still reject.

  poly
    .command('geoblock')
    .description('Check CLOB ban-status for the current signer (L2-authenticated)')
    .action(async () => {
      const spinner = ora('Checking geoblock status...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        await ensureAuth(ctx, svc);
        const result = await svc.checkGeoblock();
        spinner.stop();
        outputResult({
          trader: svc.signerAddress,
          signerSource: svc.signerSource,
          closedOnly: result.closed_only,
          interpretation: result.closed_only
            ? 'BLOCKED for new positions from this IP/jurisdiction. You can only close existing positions.'
            : 'CLOB ban-status endpoint does not flag this signer. Note: this is NOT a guarantee — the /order POST endpoint runs its own region check that can reject independently.',
          hint: 'If you hit a 403 on /order despite this check returning closedOnly: false, retry once after 30 seconds, then abort — the order endpoint enforces a separate rule.',
        });
      } catch (err) {
        spinner.fail('Geoblock check failed.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── midpoint ─────────────────────────────────────────────────────

  poly
    .command('midpoint')
    .description('Get midpoint price for a token')
    .argument('<token_id>', 'Conditional token ID')
    .action(async (tokenId: string) => {
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const result = await svc.getMidpoint(tokenId);
        outputResult({ tokenId, ...result });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── book ─────────────────────────────────────────────────────────

  poly
    .command('book')
    .description('Get order book for a token')
    .argument('<token_id>', 'Conditional token ID')
    .action(async (tokenId: string) => {
      const spinner = ora('Fetching order book...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const book = await svc.getOrderBook(tokenId);
        spinner.stop();

        const topBids = book.bids.slice(0, 5).map((b) => `${b.price} × ${b.size}`);
        const topAsks = book.asks.slice(0, 5).map((a) => `${a.price} × ${a.size}`);

        outputResult({
          tokenId,
          bids: topBids,
          asks: topAsks,
          bidCount: book.bids.length,
          askCount: book.asks.length,
        });
      } catch (err) {
        spinner.fail('Failed to fetch order book.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── spread ───────────────────────────────────────────────────────

  poly
    .command('spread')
    .description('Get bid-ask spread for a token')
    .argument('<token_id>', 'Conditional token ID')
    .action(async (tokenId: string) => {
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const result = await svc.getSpread(tokenId);
        outputResult({ tokenId, ...result });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── balance ──────────────────────────────────────────────────────

  poly
    .command('balance')
    .description('Get USDC balance and allowance on Polymarket')
    .option('--token-id <id>', 'Conditional token ID (for position balance)')
    .action(async (opts: { tokenId?: string }) => {
      const spinner = ora('Querying Polymarket balance...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        await ensureAuth(ctx, svc);

        if (opts.tokenId) {
          const result = await svc.getBalance('CONDITIONAL', opts.tokenId);
          spinner.stop();
          outputResult({ type: 'CONDITIONAL', tokenId: opts.tokenId, ...result });
        } else {
          const result = await svc.getBalance('COLLATERAL');
          spinner.stop();
          outputResult({ type: 'USDC', ...result });
        }
      } catch (err) {
        spinner.fail('Failed to query balance.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── orders (list open) ───────────────────────────────────────────

  poly
    .command('orders')
    .description('List open orders')
    .option('--market <id>', 'Filter by market condition ID')
    .action(async (opts: { market?: string }) => {
      const spinner = ora('Fetching open orders...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        await ensureAuth(ctx, svc);

        const orders = await svc.getOpenOrders({ market: opts.market });
        spinner.stop();

        if (orders.length === 0) {
          outputResult({ orders: [], message: 'No open orders.' });
          return;
        }
        outputResult({
          orders: orders.map((o) => ({
            id: o.id,
            side: o.side,
            price: o.price,
            size: o.original_size,
            matched: o.size_matched,
            status: o.status,
            market: o.market,
          })),
        });
      } catch (err) {
        spinner.fail('Failed to fetch orders.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── order (create) ───────────────────────────────────────────────

  poly
    .command('order')
    .description('Place a limit order')
    .requiredOption('--token <id>', 'Conditional token ID')
    .requiredOption('--side <side>', 'BUY or SELL')
    .requiredOption('--price <price>', 'Limit price (0-1)')
    .requiredOption('--size <size>', 'Number of shares')
    .option('--type <type>', 'Order type: GTC, FOK, GTD, FAK', 'GTC')
    .option('--neg-risk', 'Use neg-risk exchange')
    .action(
      async (opts: {
        token: string;
        side: string;
        price: string;
        size: string;
        type: string;
        negRisk?: boolean;
      }) => {
        const spinner = ora('Placing order...').start();
        try {
          const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
          await ensureAuth(ctx, svc);

          const price = parseFloat(opts.price);
          const size = parseFloat(opts.size);
          if (isNaN(price) || price <= 0 || price >= 1) {
            throw new Error('Price must be between 0 and 1 (exclusive).');
          }
          if (isNaN(size) || size <= 0) {
            throw new Error('Size must be positive.');
          }

          const result = await svc.createOrder({
            tokenId: opts.token,
            side: parseSide(opts.side),
            price,
            size,
            orderType: parseOrderType(opts.type),
            negRisk: opts.negRisk,
          });

          spinner.stop();
          if (result.success) {
            outputResult({
              status: 'placed',
              orderID: result.orderID,
              orderStatus: result.status,
            });
          } else {
            outputError(ERR_INTERNAL, result.errorMsg || 'Order placement failed.');
          }
        } catch (err) {
          spinner.fail('Order failed.');
          outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
        }
      },
    );

  // ── cancel ───────────────────────────────────────────────────────

  poly
    .command('cancel')
    .description('Cancel an order (or all orders with --all)')
    .argument('[order_id]', 'Order ID to cancel')
    .option('--all', 'Cancel all open orders')
    .action(async (orderId?: string, opts?: { all?: boolean }) => {
      const spinner = ora('Cancelling...').start();
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        await ensureAuth(ctx, svc);

        if (opts?.all) {
          const result = await svc.cancelAll();
          spinner.stop();
          outputResult({ status: 'cancelled_all', canceled: result.canceled });
        } else if (orderId) {
          const result = await svc.cancelOrder(orderId);
          spinner.stop();
          outputResult({ status: 'cancelled', canceled: result.canceled });
        } else {
          spinner.fail('Provide an order ID or use --all.');
          outputError(ERR_INVALID_PARAMS, 'Provide an order ID or use --all.');
        }
      } catch (err) {
        spinner.fail('Cancel failed.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── approve (one-off: subkey/owner → USDC + CTF approvals for CTFExchange) ──
  //
  // Minimal approval path needed before the first trade. For neg-risk markets
  // pass --neg-risk to target the NegRiskExchange + NegRiskAdapter instead.
  // Uses direct EOA tx signing from the active signer (subkey or owner),
  // NOT a UserOp — approvals live on whatever EOA ends up being the CLOB maker.

  poly
    .command('approve')
    .description('Set USDC + CTF approvals on the active signer (subkey or owner)')
    .option('--neg-risk', 'Approve NegRiskExchange + NegRiskAdapter instead of CTFExchange')
    .action(async (opts: { negRisk?: boolean }) => {
      const spinner = ora('Approving...').start();
      try {
        ensureUnlocked(ctx);
        const subkeyRef = (poly.opts() as { subkey?: string }).subkey;
        const svc = createPolyService(ctx, subkeyRef);

        const viemAccount = subkeyRef
          ? ctx.keyring.getSubkeyAccount(subkeyRef)
          : ctx.keyring.getAccount();

        // Pick the right chain: for subkey, use its bound chain; for owner, use active account's chain.
        // DO NOT rely on ctx.chain.currentChain — that's the CLI config's default,
        // which can be stale relative to the active account.
        const currentAccount = ctx.account.currentAccount;
        const targetChainId = subkeyRef
          ? (() => {
              const list = ctx.keyring.listSubkeys();
              const sk = list.find((s) => s.label === subkeyRef || s.id === subkeyRef);
              if (!sk) throw new Error(`Subkey "${subkeyRef}" not found.`);
              return sk.boundChainId;
            })()
          : (currentAccount?.chainId ?? 137);
        const chainConfig = ctx.chain.chains.find((c) => c.id === targetChainId);
        if (!chainConfig) {
          throw new Error(`Chain ${targetChainId} not in CLI config.`);
        }
        // Polymarket contracts only live on Polygon.
        if (targetChainId !== 137) {
          throw new Error(
            `Polymarket approvals only make sense on Polygon (137), got chain ${targetChainId}.`,
          );
        }

        const { createWalletClient, createPublicClient, http } = await import('viem');
        const { polygon } = await import('viem/chains');

        const walletClient = createWalletClient({
          account: viemAccount,
          chain: polygon,
          transport: http(chainConfig.endpoint),
        });

        // Separate public client for waitForTransactionReceipt between sends.
        // Without this wait, a second back-to-back send with an explicit next
        // nonce can be silently dropped by some RPCs even though the first
        // landed successfully (observed on Polygon public RPC).
        const publicClient = createPublicClient({
          chain: polygon,
          transport: http(chainConfig.endpoint),
        });

        // Fetch gas price from the *correct* RPC (the subkey's bound chain),
        // add 20% buffer, use legacy tx type. viem's auto fee estimation on
        // Polygon can over-reserve via fee history.
        // (cast through unknown — viem's strict Method union doesn't include
        // plain eth_gasPrice but the underlying JSON-RPC call is valid)
        const rawGasPrice = await (
          walletClient.request as unknown as (args: { method: string }) => Promise<string>
        )({ method: 'eth_gasPrice' });
        const gasPrice = (BigInt(rawGasPrice) * 120n) / 100n;

        // Polymarket is mid-migration (v1 → v2) and the production CLOB at
        // clob.polymarket.com still reports version 1 as of April 14, 2026.
        // The signed orders, the approve targets, and the collateral token
        // all differ between v1 and v2, so we dispatch based on what the
        // server currently reports. Once Polymarket cuts over to v2, the
        // same `resolveClobVersion()` call returns 2 and every downstream
        // command automatically targets the v2 contracts.
        const clobVersion = await svc.resolveClobVersion();
        spinner.text = `Approving (CLOB v${clobVersion})...`;

        // v1 contracts (legacy but currently live)
        const V1 = {
          exchange: '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E' as Address,
          negRiskExchange: '0xC5d563A36AE78145C45a50134d48A1215220f80a' as Address,
          collateral: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174' as Address, // USDC.e
          label: 'CTFExchange',
          negRiskLabel: 'NegRiskExchange',
        };
        // v2 contracts (deployed, activated when /version returns 2)
        const V2 = {
          exchange: '0xE111180000d2663C0091e4f400237545B87B996B' as Address,
          negRiskExchange: '0xe2222d279d744050d28e00520010520000310F59' as Address,
          collateral: '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB' as Address, // Polymarket USD
          label: 'CTFExchangeV2',
          negRiskLabel: 'NegRiskExchangeV2',
        };
        const SET = clobVersion === 2 ? V2 : V1;

        const NEG_RISK_ADAPTER = '0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296' as Address;
        const CONDITIONAL_TOKENS = '0x4D97DCd97eC945f40cF65F87097ACe5EA0476045' as Address;
        const COLLATERAL_FOR_APPROVE = SET.collateral;
        const MAX_UINT256 = 2n ** 256n - 1n;

        const ERC20_APPROVE_ABI = [
          {
            name: 'approve',
            type: 'function',
            stateMutability: 'nonpayable',
            inputs: [
              { name: 'spender', type: 'address' },
              { name: 'amount', type: 'uint256' },
            ],
            outputs: [{ name: '', type: 'bool' }],
          },
        ] as const;

        const CTF_SET_APPROVAL_ABI = [
          {
            name: 'setApprovalForAll',
            type: 'function',
            stateMutability: 'nonpayable',
            inputs: [
              { name: 'operator', type: 'address' },
              { name: 'approved', type: 'bool' },
            ],
            outputs: [],
          },
        ] as const;

        // Non-neg-risk: just the exchange; neg-risk: exchange + adapter.
        // `SET` is resolved from the live CLOB version above.
        const targets: Array<{ spender: Address; label: string }> = opts.negRisk
          ? [
              { spender: SET.negRiskExchange, label: SET.negRiskLabel },
              { spender: NEG_RISK_ADAPTER, label: 'NegRiskAdapter' },
            ]
          : [{ spender: SET.exchange, label: SET.label }];

        const txs: Array<{ kind: string; label: string; txHash: `0x${string}` }> = [];

        for (const t of targets) {
          // Skip if already approved (idempotent — lets users rerun approve safely)
          const currentUsdcAllowance = (await publicClient.readContract({
            address: COLLATERAL_FOR_APPROVE,
            abi: [
              {
                name: 'allowance',
                type: 'function',
                stateMutability: 'view',
                inputs: [
                  { name: 'owner', type: 'address' },
                  { name: 'spender', type: 'address' },
                ],
                outputs: [{ name: '', type: 'uint256' }],
              },
            ] as const,
            functionName: 'allowance',
            args: [svc.signerAddress, t.spender],
          })) as bigint;

          if (currentUsdcAllowance < MAX_UINT256 / 2n) {
            spinner.text = `Approving collateral → ${t.label}...`;
            const usdcCalldata = encodeFunctionData({
              abi: ERC20_APPROVE_ABI,
              functionName: 'approve',
              args: [t.spender, MAX_UINT256],
            });
            const hash1 = await walletClient.sendTransaction({
              to: COLLATERAL_FOR_APPROVE,
              data: usdcCalldata,
              gas: 80000n,
              gasPrice,
            } as Parameters<typeof walletClient.sendTransaction>[0]);
            // CRITICAL: wait for confirmation before sending the next tx.
            // Some RPCs silently drop a second tx with an incremented nonce if
            // the first hasn't been mined yet — observed on Polygon public RPC.
            await publicClient.waitForTransactionReceipt({ hash: hash1 });
            txs.push({ kind: 'Collateral.approve', label: t.label, txHash: hash1 });
          }

          const currentCtfApproval = (await publicClient.readContract({
            address: CONDITIONAL_TOKENS,
            abi: [
              {
                name: 'isApprovedForAll',
                type: 'function',
                stateMutability: 'view',
                inputs: [
                  { name: 'owner', type: 'address' },
                  { name: 'operator', type: 'address' },
                ],
                outputs: [{ name: '', type: 'bool' }],
              },
            ] as const,
            functionName: 'isApprovedForAll',
            args: [svc.signerAddress, t.spender],
          })) as boolean;

          if (!currentCtfApproval) {
            spinner.text = `Approving CTF → ${t.label}...`;
            const ctfCalldata = encodeFunctionData({
              abi: CTF_SET_APPROVAL_ABI,
              functionName: 'setApprovalForAll',
              args: [t.spender, true],
            });
            const hash2 = await walletClient.sendTransaction({
              to: CONDITIONAL_TOKENS,
              data: ctfCalldata,
              gas: 70000n,
              gasPrice,
            } as Parameters<typeof walletClient.sendTransaction>[0]);
            await publicClient.waitForTransactionReceipt({ hash: hash2 });
            txs.push({ kind: 'CTF.setApprovalForAll', label: t.label, txHash: hash2 });
          }
        }

        spinner.stop();
        outputResult({
          status: 'approved',
          signer: svc.signerAddress,
          signerSource: svc.signerSource,
          negRisk: !!opts.negRisk,
          approvals: txs,
        });
      } catch (err) {
        spinner.fail('Approve failed.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // NOTE: `pm deposit` and `pm withdraw` are intentionally removed.
  // They were superseded by `elytro subkey fund` (smart account → subkey,
  // SecurityHook-gated UserOp) and `elytro subkey sweep` (subkey → smart
  // account, direct EOA tx). The old `deposit`/`withdraw` flow also referenced
  // an outdated SDK API that no longer compiles against upstream/main.

  // ── info ─────────────────────────────────────────────────────────

  poly
    .command('info')
    .description('Show Polymarket wallet info and auth status')
    .action(async () => {
      try {
        const svc = createPolyService(ctx, (poly.opts() as { subkey?: string }).subkey);
        const creds = await loadCreds(ctx, svc.signerAddress);
        const account = ctx.account.currentAccount;
        outputResult({
          vault: account
            ? { address: account.address, chain: account.chainId, alias: account.alias }
            : null,
          trader: svc.signerAddress,
          signerSource: svc.signerSource,
          authenticated: !!creds,
          apiKey: creds ? creds.key : null,
          chain: 'Polygon (137)',
          clobVersion: await svc.resolveClobVersion(),
          exchange:
            (await svc.resolveClobVersion()) === 2
              ? '0xE111180000d2663C0091e4f400237545B87B996B (CTFExchangeV2)'
              : '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E (CTFExchange v1)',
          collateral:
            (await svc.resolveClobVersion()) === 2
              ? '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB (Polymarket USD)'
              : '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 (USDC.e)',
          hint: svc.signerSource.startsWith('subkey:')
            ? `Use \`elytro subkey fund ${svc.signerSource.slice(7)} --usdc <amount> --native 0.1\` to fund, then trade with \`elytro pm --subkey ${svc.signerSource.slice(7)} order ...\`.`
            : account?.chainId === 137
              ? 'Use `elytro subkey create <label>` + `elytro subkey fund <label>` for a scoped trading key instead of the owner EOA.'
              : 'Create a Polygon account with `elytro account create --chain 137` first.',
        });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });
}
