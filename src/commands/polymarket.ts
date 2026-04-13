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

// USDC.e on Polygon (Polymarket's collateral token)
const USDC_ADDRESS = '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174' as Address;
const USDC_DECIMALS = 6;

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

const POLY_CREDS_KEY = 'polymarket-creds';

async function loadCreds(ctx: AppContext): Promise<ApiKeyCreds | null> {
  return ctx.store.load<ApiKeyCreds>(POLY_CREDS_KEY);
}

async function saveCreds(ctx: AppContext, creds: ApiKeyCreds): Promise<void> {
  await ctx.store.save(POLY_CREDS_KEY, creds);
}

function ensureUnlocked(ctx: AppContext): void {
  if (!ctx.keyring.isUnlocked) {
    throw new Error('Wallet not unlocked. Run `elytro init` first.');
  }
}

function createPolyService(ctx: AppContext): PolymarketService {
  ensureUnlocked(ctx);
  return new PolymarketService(ctx.keyring);
}

async function ensureAuth(ctx: AppContext, svc: PolymarketService): Promise<void> {
  if (svc.isAuthenticated) return;

  // Try loading persisted credentials
  const saved = await loadCreds(ctx);
  if (saved) {
    svc.setCreds(saved);
    return;
  }

  throw new Error('Not authenticated with Polymarket. Run `elytro polymarket auth` first.');
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
    .description('Polymarket prediction market trading via Elytro wallet');

  // ── auth ─────────────────────────────────────────────────────────

  poly
    .command('auth')
    .description('Authenticate with Polymarket CLOB (derive or create API key)')
    .option('--create', 'Create new API key instead of deriving existing')
    .option('--nonce <n>', 'Nonce for key derivation', '0')
    .action(async (opts: { create?: boolean; nonce?: string }) => {
      const spinner = ora('Authenticating with Polymarket...').start();
      try {
        const svc = createPolyService(ctx);
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

        await saveCreds(ctx, creds);
        spinner.succeed('Authenticated with Polymarket.');
        outputResult({
          status: 'authenticated',
          address: svc.signerAddress,
          apiKey: creds.key,
          hint: 'Credentials saved locally. You can now trade.',
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
    .action(async (opts: { active?: boolean; limit?: string; search?: string }) => {
      const spinner = ora('Fetching markets...').start();
      try {
        const svc = createPolyService(ctx);
        const limit = parseInt(opts.limit ?? '10', 10);

        let markets: GammaMarket[];
        if (opts.search) {
          markets = await svc.searchMarkets(opts.search, limit);
        } else {
          markets = await svc.getMarkets({
            active: opts.active,
            limit,
            order: 'volume_num',
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
    });

  // ── market (single) ──────────────────────────────────────────────

  poly
    .command('market')
    .description('Get details for a specific market')
    .argument('<id>', 'Market condition ID or slug')
    .action(async (id: string) => {
      const spinner = ora('Fetching market...').start();
      try {
        const svc = createPolyService(ctx);
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
        const svc = createPolyService(ctx);
        const side = parseSide(opts.side);
        const result = await svc.getPrice(tokenId, side);
        outputResult({ tokenId, side, ...result });
      } catch (err) {
        outputError(ERR_INVALID_PARAMS, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── midpoint ─────────────────────────────────────────────────────

  poly
    .command('midpoint')
    .description('Get midpoint price for a token')
    .argument('<token_id>', 'Conditional token ID')
    .action(async (tokenId: string) => {
      try {
        const svc = createPolyService(ctx);
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
        const svc = createPolyService(ctx);
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
        const svc = createPolyService(ctx);
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
        const svc = createPolyService(ctx);
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
        const svc = createPolyService(ctx);
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
          const svc = createPolyService(ctx);
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
        const svc = createPolyService(ctx);
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

  // ── deposit (smart account → EOA, goes through 2FA + spending limits) ──

  poly
    .command('deposit')
    .description('Transfer USDC from Elytro smart account to Polymarket EOA (triggers 2FA)')
    .requiredOption('--amount <usdc>', 'USDC amount to deposit (e.g. "50")')
    .action(async (opts: { amount: string }) => {
      const spinner = ora('Preparing deposit...').start();
      try {
        ensureUnlocked(ctx);
        const svc = createPolyService(ctx);
        const eoaAddress = svc.signerAddress;

        const amount = parseFloat(opts.amount);
        if (isNaN(amount) || amount <= 0) {
          throw new Error('Amount must be a positive number.');
        }

        // Resolve the current account on Polygon
        const account = ctx.account.currentAccount;
        if (!account)
          throw new Error('No active Elytro account. Run `elytro account create --chain 137`.');
        if (account.chainId !== 137) {
          throw new Error(
            `Active account is on chain ${account.chainId}, not Polygon (137). ` +
              'Switch with `elytro account switch <polygon-account>`.',
          );
        }

        const amountWei = parseUnits(opts.amount, USDC_DECIMALS);

        // Build ERC-20 transfer calldata: smart account → EOA
        const calldata = encodeFunctionData({
          abi: ERC20_TRANSFER_ABI,
          functionName: 'transfer',
          args: [eoaAddress, amountWei],
        });

        spinner.text = 'Building UserOperation (2FA may be required)...';

        // Ensure SDK + walletClient are on Polygon
        const polygonChain = ctx.chain.chains.find((c) => c.id === 137);
        if (!polygonChain) throw new Error('Polygon chain config not found.');
        ctx.walletClient.initForChain(polygonChain);
        await ctx.sdk.initForChain(polygonChain);

        // Build UserOp via SDK (this goes through the full security pipeline)
        const userOp = await ctx.sdk.createSendUserOp(account.address, [
          { to: USDC_ADDRESS, value: '0', data: calldata },
        ]);

        // Estimate gas
        const estimated = await ctx.sdk.estimateUserOp(userOp, account.address);
        Object.assign(userOp, estimated);

        // Get fee data
        const feeData = await ctx.sdk.getFeeData();
        userOp.maxFeePerGas = feeData.maxFeePerGas;
        userOp.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;

        // Try sponsorship
        try {
          const sponsor = await requestSponsorship(ctx.chain.currentChain, userOp);
          applySponsorToUserOp(userOp, sponsor);
        } catch {
          // No sponsor available, user pays gas
        }

        // Sign
        const { packedHash } = await ctx.sdk.getUserOpHash(userOp);
        const rawSig = await ctx.keyring.signDigest(packedHash);
        userOp.signature = await ctx.sdk.packUserOpSignature(rawSig);

        spinner.text = 'Sending deposit transaction...';

        // Send (this triggers 2FA / spending limit checks via SecurityHook)
        const opHash = await ctx.sdk.sendUserOp(userOp);
        spinner.text = 'Waiting for confirmation...';
        const receipt = await ctx.sdk.waitForReceipt(opHash);

        spinner.succeed('Deposit complete.');
        outputResult({
          status: 'deposited',
          from: account.address,
          to: eoaAddress,
          amount: `${opts.amount} USDC`,
          txHash: receipt?.receipt?.transactionHash ?? opHash,
          note: 'Funds are now on your Polymarket EOA. Trade with `elytro pm order`.',
        });
      } catch (err) {
        spinner.fail('Deposit failed.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── withdraw (EOA → smart account, direct EOA tx) ──────────────

  poly
    .command('withdraw')
    .description('Sweep USDC from Polymarket EOA back to Elytro smart account')
    .option('--amount <usdc>', 'USDC amount (default: all)')
    .action(async (opts: { amount?: string }) => {
      const spinner = ora('Preparing withdrawal...').start();
      try {
        ensureUnlocked(ctx);
        const svc = createPolyService(ctx);

        const account = ctx.account.currentAccount;
        if (!account) throw new Error('No active Elytro account.');

        const smartAccountAddress = account.address;
        const eoaAddress = svc.signerAddress;

        // Check EOA's USDC balance
        const balanceResult = await ctx.walletClient.readContract({
          address: USDC_ADDRESS,
          abi: ERC20_TRANSFER_ABI,
          functionName: 'balanceOf',
          args: [eoaAddress],
        });
        const balance = balanceResult as bigint;
        const amountWei = opts.amount ? parseUnits(opts.amount, USDC_DECIMALS) : balance;

        if (amountWei === 0n) {
          spinner.stop();
          outputResult({ status: 'nothing_to_withdraw', balance: '0 USDC' });
          return;
        }
        if (amountWei > balance) {
          throw new Error(
            `Insufficient balance. EOA has ${formatUnits(balance, USDC_DECIMALS)} USDC.`,
          );
        }

        spinner.text = 'Sending USDC back to smart account...';

        // Direct EOA transaction (no 2FA needed — funds are coming back to safety)
        const calldata = encodeFunctionData({
          abi: ERC20_TRANSFER_ABI,
          functionName: 'transfer',
          args: [smartAccountAddress, amountWei],
        });

        const viemAccount = ctx.keyring.getAccount();
        const { createWalletClient, http } = await import('viem');
        const { polygon } = await import('viem/chains');

        const walletClient = createWalletClient({
          account: viemAccount,
          chain: polygon,
          transport: http(ctx.chain.currentChain.endpoint),
        });

        const txHash = await walletClient.sendTransaction({
          to: USDC_ADDRESS,
          data: calldata,
        });

        spinner.succeed('Withdrawal complete.');
        outputResult({
          status: 'withdrawn',
          from: eoaAddress,
          to: smartAccountAddress,
          amount: `${formatUnits(amountWei, USDC_DECIMALS)} USDC`,
          txHash,
        });
      } catch (err) {
        spinner.fail('Withdrawal failed.');
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── info ─────────────────────────────────────────────────────────

  poly
    .command('info')
    .description('Show Polymarket wallet info and auth status')
    .action(async () => {
      try {
        const svc = createPolyService(ctx);
        const creds = await loadCreds(ctx);
        const account = ctx.account.currentAccount;
        outputResult({
          vault: account
            ? { address: account.address, chain: account.chainId, alias: account.alias }
            : null,
          trader: svc.signerAddress,
          authenticated: !!creds,
          apiKey: creds ? creds.key : null,
          chain: 'Polygon (137)',
          exchange: '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E',
          hint:
            account?.chainId === 137
              ? 'Use `elytro pm deposit` to move USDC from vault → trader (triggers 2FA).'
              : 'Create a Polygon account with `elytro account create --chain 137` for vault security.',
        });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });
}
