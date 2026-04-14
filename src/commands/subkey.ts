import { Command } from 'commander';
import ora from 'ora';
import {
  createWalletClient,
  encodeFunctionData,
  formatEther,
  formatUnits,
  http,
  isAddress,
  parseEther,
  parseUnits,
  type Address,
  type Hex,
  type Chain,
} from 'viem';
import type { AppContext } from '../context';
import type { ElytroUserOperation } from '../types';
import { requestSponsorship, applySponsorToUserOp } from '../utils/sponsor';
import { outputResult, outputError, sanitizeErrorMessage } from '../utils/display';
import { SecurityHookService, createSignMessageForAuth } from '../services/securityHook';
import { savePendingOtpAndOutput } from '../services/pendingOtp';
import { serializeUserOpForPending } from '../utils/userOpSerialization';
import { SECURITY_HOOK_ADDRESS_MAP } from '../constants/securityHook';
import { checkRecoveryBlocked } from '../utils/recoveryGuard';

// ─── Error Codes ──────────────────────────────────────────────────

const ERR_INVALID_PARAMS = -32602;
const ERR_ACCOUNT_NOT_READY = -32002;
const ERR_INSUFFICIENT_BALANCE = -32001;
const ERR_BUILD_FAILED = -32004;
const ERR_SEND_FAILED = -32005;
const ERR_EXECUTION_REVERTED = -32006;
const ERR_INTERNAL = -32000;

// ─── Known Tokens ──────────────────────────────────────────────────

// Polymarket collateral token on Polygon. The concrete address depends on
// which CLOB version the production server is currently running:
//   - v1: USDC.e (0x2791Bca1...), the original bridged USDC
//   - v2: Polymarket USD (0xC011a7E1...), wrapped via CollateralOnramp
// Polymarket is mid-migration between v1 and v2; we resolve the active
// version via `fetchClobVersion()` at command runtime instead of pinning
// a single address. USDC.e holders bridging into Polymarket USD should use
// the CollateralOnramp at 0x93070a847efEf7F70739046A929D47a521F5B8ee.
const COLLATERAL_V1 = '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174' as Address; // USDC.e
const COLLATERAL_V2 = '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB' as Address; // Polymarket USD
const COLLATERAL_DECIMALS = 6;

/**
 * Hit Polymarket's /version endpoint and return 1 or 2. Defaults to 1 on
 * any failure because that's the currently-live production version.
 */
async function fetchClobVersion(): Promise<1 | 2> {
  try {
    const res = await fetch('https://clob.polymarket.com/version');
    if (!res.ok) return 1;
    const body = (await res.json()) as { version?: number };
    return body.version === 2 ? 2 : 1;
  } catch {
    return 1;
  }
}

const ERC20_ABI = [
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

// ─── Helpers ──────────────────────────────────────────────────────

function ensureUnlocked(ctx: AppContext): void {
  if (!ctx.keyring.isUnlocked) {
    throw new Error('Wallet not unlocked. Run `elytro init` first.');
  }
}

function viemChainFromConfig(ctx: AppContext, chainId: number): Chain {
  const cfg = ctx.chain.chains.find((c) => c.id === chainId);
  if (!cfg) throw new Error(`Chain ${chainId} not in config.`);
  return {
    id: cfg.id,
    name: cfg.name,
    nativeCurrency: cfg.nativeCurrency,
    rpcUrls: { default: { http: [cfg.endpoint] } },
    blockExplorers: cfg.blockExplorer
      ? { default: { name: cfg.name, url: cfg.blockExplorer } }
      : undefined,
  };
}

// ─── Command Registration ──────────────────────────────────────────

export function registerSubkeyCommand(program: Command, ctx: AppContext): void {
  const sk = program
    .command('subkey')
    .description('Manage scoped trading/agent subkeys (disjoint from smart-account owners)');

  // ── create ───────────────────────────────────────────────────────

  sk.command('create')
    .description('Generate a new subkey bound to the current smart account')
    .argument('<label>', 'Unique label, e.g. "polymarket-main"')
    .option('--scope <scope>', 'Scope hint (advisory), e.g. "polymarket-clob"', 'general')
    .action(async (label: string, opts: { scope: string }) => {
      try {
        ensureUnlocked(ctx);
        const account = ctx.account.currentAccount;
        if (!account) {
          throw new Error(
            'No active smart account. Run `elytro account create` first, then `elytro subkey create`.',
          );
        }

        const address = await ctx.keyring.createSubkey({
          label,
          scope: opts.scope,
          boundAccount: account.address,
          boundChainId: account.chainId,
        });

        outputResult({
          status: 'created',
          label,
          scope: opts.scope,
          address,
          boundAccount: account.address,
          boundChainId: account.chainId,
          hint: `Fund with \`elytro subkey fund ${label} --usdc <amount> [--native <amount>]\`, then use with \`elytro polymarket --subkey ${label} ...\``,
        });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── list ─────────────────────────────────────────────────────────

  sk.command('list')
    .description('List subkeys in the vault')
    .option('--scope <scope>', 'Filter by scope')
    .option('--bound <address>', 'Filter by bound smart account address')
    .action(async (opts: { scope?: string; bound?: string }) => {
      try {
        ensureUnlocked(ctx);
        const filter: { scope?: string; boundAccount?: Address } = {};
        if (opts.scope) filter.scope = opts.scope;
        if (opts.bound) {
          if (!isAddress(opts.bound)) {
            outputError(ERR_INVALID_PARAMS, 'Invalid --bound address.');
            return;
          }
          filter.boundAccount = opts.bound as Address;
        }

        const list = ctx.keyring.listSubkeys(filter);
        outputResult({
          subkeys: list.map((s) => ({
            label: s.label,
            scope: s.scope,
            address: s.id,
            boundAccount: s.boundAccount,
            boundChainId: s.boundChainId,
            createdAt: new Date(s.createdAt).toISOString(),
          })),
          total: list.length,
        });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── info ─────────────────────────────────────────────────────────

  sk.command('info')
    .description('Show details and on-chain balances for a subkey')
    .argument('<label>', 'Subkey label or address')
    .action(async (label: string) => {
      const spinner = ora('Fetching subkey info...').start();
      try {
        ensureUnlocked(ctx);
        // Use list filter or search by address for robustness
        const all = ctx.keyring.listSubkeys();
        const target = all.find(
          (s) => s.label === label || s.id.toLowerCase() === label.toLowerCase(),
        );
        if (!target) {
          throw new Error(`Subkey "${label}" not found.`);
        }

        const chain = ctx.chain.chains.find((c) => c.id === target.boundChainId);
        if (!chain) {
          throw new Error(`Bound chain ${target.boundChainId} is not in CLI config.`);
        }

        // Switch walletClient to the subkey's bound chain for balance reads.
        ctx.walletClient.initForChain(chain);

        const nativeWei = (await ctx.walletClient.getBalance(target.id)).wei;

        let usdcBalance: bigint | null = null;
        let collateralLabel = 'collateral';
        if (target.boundChainId === 137) {
          const version = await fetchClobVersion();
          const collateralAddr = version === 2 ? COLLATERAL_V2 : COLLATERAL_V1;
          collateralLabel = version === 2 ? 'Polymarket USD (v2)' : 'USDC.e (v1)';
          usdcBalance = (await ctx.walletClient.readContract({
            address: collateralAddr,
            abi: ERC20_ABI,
            functionName: 'balanceOf',
            args: [target.id],
          })) as bigint;
        }

        spinner.stop();
        outputResult({
          label: target.label,
          scope: target.scope,
          address: target.id,
          boundAccount: target.boundAccount,
          boundChain: chain.name,
          boundChainId: target.boundChainId,
          native: `${formatEther(nativeWei)} ${chain.nativeCurrency.symbol}`,
          usdc:
            usdcBalance !== null
              ? `${formatUnits(usdcBalance, COLLATERAL_DECIMALS)} ${collateralLabel}`
              : null,
          createdAt: new Date(target.createdAt).toISOString(),
        });
      } catch (err) {
        spinner.stop();
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── remove ───────────────────────────────────────────────────────

  sk.command('remove')
    .description('Remove a subkey from the vault (scrubs key material)')
    .argument('<label>', 'Subkey label or address')
    .action(async (label: string) => {
      try {
        ensureUnlocked(ctx);
        await ctx.keyring.removeSubkey(label);
        outputResult({
          status: 'removed',
          label,
          hint: 'Any remaining on-chain balance at the subkey address is now unrecoverable from this vault. Sweep before removing if needed.',
        });
      } catch (err) {
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });

  // ── fund: smart account → subkey (UserOp, SecurityHook-gated) ────

  sk.command('fund')
    .description('Transfer USDC and/or native gas from smart account → subkey (triggers 2FA)')
    .argument('<label>', 'Subkey label')
    .option('--usdc <amount>', 'Polymarket USD amount (v2 collateral), e.g. "3.0"')
    .option('--native <amount>', 'Native gas amount, e.g. "0.1"')
    .option('--no-sponsor', 'Skip sponsorship check')
    .option('--no-hook', 'Skip SecurityHook signing (bypass 2FA)')
    .action(
      async (
        label: string,
        opts: { usdc?: string; native?: string; sponsor?: boolean; hook?: boolean },
      ) => {
        const spinner = ora('Preparing fund transaction...').start();
        try {
          ensureUnlocked(ctx);

          const all = ctx.keyring.listSubkeys();
          const subkey = all.find(
            (s) => s.label === label || s.id.toLowerCase() === label.toLowerCase(),
          );
          if (!subkey) {
            throw new Error(`Subkey "${label}" not found.`);
          }

          if (!opts.usdc && !opts.native) {
            throw new Error('Specify at least one of --usdc or --native.');
          }

          const account = ctx.account.currentAccount;
          if (!account) throw new Error('No active smart account.');
          if (checkRecoveryBlocked(account)) return;

          // BOUND-ACCOUNT MATCH CHECK
          //
          // The subkey was created with a specific `boundAccount`. Fund must
          // originate from THAT account, not any same-chain account the user
          // happens to have switched to. Otherwise a user with multiple smart
          // accounts on the same chain can accidentally fund a subkey bound
          // to account A from account B — since `sweep` always returns funds
          // to `subkey.boundAccount`, this leaks money from the active
          // account into the bound account via a round trip.
          //
          // The chainId check is now a prerequisite of the address check.
          if (account.chainId !== subkey.boundChainId) {
            throw new Error(
              `Subkey "${subkey.label}" is bound to chain ${subkey.boundChainId}, but active account "${account.alias}" is on chain ${account.chainId}. Switch with \`elytro account switch <alias-on-chain-${subkey.boundChainId}>\`.`,
            );
          }
          if (account.address.toLowerCase() !== subkey.boundAccount.toLowerCase()) {
            throw new Error(
              `Subkey "${subkey.label}" is bound to smart account ${subkey.boundAccount}, but the currently active account is "${account.alias}" (${account.address}). ` +
                `Fund must originate from the bound account — run \`elytro account switch\` to the bound account first, or create a new subkey bound to the currently active account.`,
            );
          }
          if (!account.isDeployed) {
            throw new Error(
              `Smart account "${account.alias}" is not deployed. Run \`elytro account activate\` first.`,
            );
          }

          const chainConfig = ctx.chain.chains.find((c) => c.id === account.chainId);
          if (!chainConfig) throw new Error(`Chain ${account.chainId} not in config.`);

          // Build tx list: optional USDC transfer + optional native transfer.
          const txs: Array<{ to: string; value?: string; data?: string }> = [];

          if (opts.usdc) {
            if (subkey.boundChainId !== 137) {
              throw new Error(
                'Collateral transfer is currently only wired for Polygon (137). Use --native for other chains.',
              );
            }
            // Pick the live collateral token based on CLOB version — v1 uses
            // USDC.e, v2 uses Polymarket USD. Both are ERC-20 with 6 decimals.
            const version = await fetchClobVersion();
            const collateralAddr = version === 2 ? COLLATERAL_V2 : COLLATERAL_V1;
            const amountWei = parseUnits(opts.usdc, COLLATERAL_DECIMALS);
            if (amountWei <= 0n) throw new Error('--usdc must be positive.');
            const data = encodeFunctionData({
              abi: ERC20_ABI,
              functionName: 'transfer',
              args: [subkey.id, amountWei],
            });
            txs.push({ to: collateralAddr, value: '0x0', data });
          }

          if (opts.native) {
            const wei = parseEther(opts.native);
            if (wei <= 0n) throw new Error('--native must be positive.');
            // tx.ts serializes value to hex before passing to SDK
            txs.push({
              to: subkey.id,
              value: `0x${wei.toString(16)}`,
              data: '0x',
            });
          }

          // ── Init SDK + walletClient for the target chain ──
          await ctx.sdk.initForChain(chainConfig);
          ctx.walletClient.initForChain(chainConfig);

          // ── Balance pre-check for native value ──
          let nativeTotal = 0n;
          if (opts.native) nativeTotal += parseEther(opts.native);
          if (nativeTotal > 0n) {
            const { wei: bal } = await ctx.walletClient.getBalance(account.address);
            if (bal < nativeTotal) {
              throw new Error(
                `Insufficient native balance on smart account: need ${formatEther(nativeTotal)} ${chainConfig.nativeCurrency.symbol}, have ${formatEther(bal)}.`,
              );
            }
          }

          // ── Build UserOp ──
          spinner.text = 'Building UserOperation...';
          let userOp: ElytroUserOperation;
          try {
            userOp = await ctx.sdk.createSendUserOp(account.address, txs);
          } catch (err) {
            throw new Error(`Failed to build UserOp: ${(err as Error).message}`);
          }

          // ── Fee data ──
          spinner.text = 'Fetching gas prices...';
          const feeData = await ctx.sdk.getFeeData(chainConfig);
          userOp.maxFeePerGas = feeData.maxFeePerGas;
          userOp.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;

          // ── Estimate ──
          spinner.text = 'Estimating gas...';
          try {
            const gasEstimate = await ctx.sdk.estimateUserOp(userOp, { fakeBalance: true });
            userOp.callGasLimit = gasEstimate.callGasLimit;
            userOp.verificationGasLimit = gasEstimate.verificationGasLimit;
            userOp.preVerificationGas = gasEstimate.preVerificationGas;
          } catch (err) {
            throw new Error(`Gas estimation failed: ${(err as Error).message}`);
          }

          // ── Sponsorship ──
          let sponsored = false;
          if (opts.sponsor !== false) {
            spinner.text = 'Checking sponsorship...';
            const { sponsor: sponsorResult } = await requestSponsorship(
              ctx.chain.graphqlEndpoint,
              account.chainId,
              ctx.sdk.entryPoint,
              userOp,
            );
            if (sponsorResult) {
              applySponsorToUserOp(userOp, sponsorResult);
              sponsored = true;
            } else {
              // Sponsorship unavailable; ensure account has gas
              const { wei: balance } = await ctx.walletClient.getBalance(account.address);
              if (balance === 0n) {
                throw new Error(
                  `Sponsorship unavailable and smart account has no ${chainConfig.nativeCurrency.symbol} to pay gas. Fund ${account.address} first.`,
                );
              }
            }
          }

          // ── Sign + Hook + Send ──
          spinner.text = 'Signing UserOperation...';
          const { packedHash, validationData } = await ctx.sdk.getUserOpHash(userOp);
          const rawSignature = await ctx.keyring.signDigest(packedHash);

          let hookSigned = false;
          const useHook = opts.hook !== false;

          if (useHook) {
            const hookAddress = SECURITY_HOOK_ADDRESS_MAP[account.chainId];
            if (hookAddress) {
              const hookService = new SecurityHookService({
                store: ctx.store,
                graphqlEndpoint: ctx.chain.graphqlEndpoint,
                signMessageForAuth: createSignMessageForAuth({
                  signDigest: (digest) => ctx.keyring.signDigest(digest),
                  packRawHash: (hash) => ctx.sdk.packRawHash(hash),
                  packSignature: (rawSig, valData) => ctx.sdk.packUserOpSignature(rawSig, valData),
                }),
                readContract: async (params) =>
                  ctx.walletClient.readContract(
                    params as Parameters<typeof ctx.walletClient.readContract>[0],
                  ),
                getBlockTimestamp: async () => {
                  const blockNum = await ctx.walletClient.raw.getBlockNumber();
                  const block = await ctx.walletClient.raw.getBlock({ blockNumber: blockNum });
                  return block.timestamp;
                },
              });

              spinner.text = 'Checking SecurityHook status...';
              const hookStatus = await hookService.getHookStatus(account.address, account.chainId);

              if (hookStatus.installed && hookStatus.capabilities.preUserOpValidation) {
                // Pre-sign without hook for authorization request
                userOp.signature = await ctx.sdk.packUserOpSignature(rawSignature, validationData);

                spinner.text = 'Requesting hook authorization (2FA may be required)...';
                const hookResult = await hookService.getHookSignature(
                  account.address,
                  account.chainId,
                  ctx.sdk.entryPoint,
                  userOp,
                );

                // Handle OTP challenge → deferred flow
                if (hookResult.error) {
                  const errCode = hookResult.error.code;
                  if (errCode === 'OTP_REQUIRED' || errCode === 'SPENDING_LIMIT_EXCEEDED') {
                    spinner.stop();

                    if (!hookResult.error.challengeId) {
                      const otpRequestSpinner = ora('Requesting OTP challenge...').start();
                      try {
                        const otpChallenge = await hookService.requestSecurityOtp(
                          account.address,
                          account.chainId,
                          ctx.sdk.entryPoint,
                          userOp,
                        );
                        hookResult.error.challengeId = otpChallenge.challengeId;
                        hookResult.error.maskedEmail ??= otpChallenge.maskedEmail;
                        hookResult.error.otpExpiresAt ??= otpChallenge.otpExpiresAt;
                        otpRequestSpinner.stop();
                      } catch (otpErr) {
                        otpRequestSpinner.fail('Failed to request OTP challenge.');
                        throw new Error(
                          `Unable to request OTP challenge: ${(otpErr as Error).message}`,
                        );
                      }
                    }

                    const challengeId = hookResult.error.challengeId!;
                    const authSessionId = await hookService.getAuthSession(
                      account.address,
                      account.chainId,
                    );

                    // Rebuild txSpec strings for deferred resume context
                    const txSpec: string[] = [];
                    if (opts.usdc) {
                      // Note: on resume, we'd need to rebuild calldata; easier to re-run the command.
                      txSpec.push(`subkey-fund:${label}:usdc:${opts.usdc}`);
                    }
                    if (opts.native) {
                      txSpec.push(`subkey-fund:${label}:native:${opts.native}`);
                    }

                    await savePendingOtpAndOutput(ctx.store, {
                      id: challengeId,
                      account: account.address,
                      chainId: account.chainId,
                      action: 'tx_send',
                      challengeId,
                      authSessionId,
                      maskedEmail: hookResult.error.maskedEmail,
                      otpExpiresAt: hookResult.error.otpExpiresAt,
                      createdAt: new Date().toISOString(),
                      data: {
                        userOp: serializeUserOpForPending(userOp),
                        entryPoint: ctx.sdk.entryPoint,
                        txSpec,
                      },
                    });
                    return;
                  }
                  throw new Error(
                    `Hook authorization failed: ${hookResult.error.message ?? errCode}`,
                  );
                }

                userOp.signature = await ctx.sdk.packUserOpSignatureWithHook(
                  rawSignature,
                  validationData,
                  hookAddress,
                  hookResult.signature! as Hex,
                );
                hookSigned = true;
              }
            }
          }

          if (!hookSigned) {
            userOp.signature = await ctx.sdk.packUserOpSignature(rawSignature, validationData);
          }

          // ── Send ──
          spinner.text = 'Sending to bundler...';
          const opHash = await ctx.sdk.sendUserOp(userOp);

          spinner.text = 'Waiting for on-chain confirmation...';
          const receipt = await ctx.sdk.waitForReceipt(opHash);

          spinner.stop();

          if (!receipt.success) {
            outputError(ERR_EXECUTION_REVERTED, 'UserOp included but execution reverted.', {
              transactionHash: receipt.transactionHash,
              blockNumber: receipt.blockNumber,
              gasCost: `${formatEther(BigInt(receipt.actualGasCost))} ${chainConfig.nativeCurrency.symbol}`,
            });
            return;
          }

          outputResult({
            status: 'funded',
            from: account.address,
            to: subkey.id,
            subkeyLabel: subkey.label,
            usdc: opts.usdc ?? null,
            native: opts.native ?? null,
            transactionHash: receipt.transactionHash,
            block: receipt.blockNumber,
            sponsored,
            hookSigned,
          });
        } catch (err) {
          spinner.stop();
          outputError(ERR_SEND_FAILED, sanitizeErrorMessage((err as Error).message));
        }
      },
    );

  // ── sweep: subkey → smart account (direct EOA tx) ─────────────
  //
  // Both USDC.e and native gas return to the bound smart account. Native
  // transfers require enough gas for the smart-account proxy's delegate
  // into its implementation's receive() (≥ ~30k on Elytro accounts;
  // 21k is insufficient, so we use 40k with an on-chain estimate probe
  // as the authoritative check).
  //
  // This keeps the architectural invariant clean: every owner-key path
  // (fund → subkey → sweep) returns to the smart account, so there is
  // no "owner EOA gas tank" that bypasses SecurityHook.

  sk.command('sweep')
    .description('Sweep USDC and/or native gas from subkey → bound smart account')
    .argument('<label>', 'Subkey label')
    .option('--usdc-only', 'Sweep only USDC')
    .option('--native-only', 'Sweep only native gas')
    .action(async (label: string, opts: { usdcOnly?: boolean; nativeOnly?: boolean }) => {
      const spinner = ora('Preparing sweep...').start();
      try {
        ensureUnlocked(ctx);

        const all = ctx.keyring.listSubkeys();
        const subkey = all.find(
          (s) => s.label === label || s.id.toLowerCase() === label.toLowerCase(),
        );
        if (!subkey) {
          throw new Error(`Subkey "${label}" not found.`);
        }

        const chainConfig = ctx.chain.chains.find((c) => c.id === subkey.boundChainId);
        if (!chainConfig) {
          throw new Error(`Subkey bound chain ${subkey.boundChainId} not in config.`);
        }

        const account = ctx.keyring.getSubkeyAccount(label);
        // Both USDC.e and native return to the bound smart account.
        // USDC transfer() works on any address (no recipient code executes).
        // Native transfer requires enough gas for the smart-account proxy's
        // delegatecall into receive() — we probe with eth_estimateGas and
        // fall back to a safe default + buffer.
        const dest = subkey.boundAccount;
        const viemChain = viemChainFromConfig(ctx, subkey.boundChainId);

        const walletClient = createWalletClient({
          account,
          chain: viemChain,
          transport: http(chainConfig.endpoint),
        });

        // Query balances via the already-initialized public walletClient
        ctx.walletClient.initForChain(chainConfig);

        // Explicit gas price from the target chain (not the CLI config's default).
        // viem's automatic fee estimation via eth_feeHistory on Polygon over-reserves
        // aggressively and can exceed available balance.
        // (cast through unknown — viem's strict Method union doesn't include
        // plain eth_gasPrice / eth_getTransactionCount but the underlying
        // JSON-RPC calls are valid)
        type LooseRequest = (args: { method: string; params?: unknown[] }) => Promise<string>;
        const rawRequest = walletClient.request as unknown as LooseRequest;
        const rawGasPrice = await rawRequest({ method: 'eth_gasPrice' });
        const gasPrice = (BigInt(rawGasPrice) * 120n) / 100n;

        // Manual nonce tracking: viem's internal nonce cache can stale-read
        // between sendTransaction calls even with waitForTransactionReceipt
        // in between. Fetch the live pending nonce and increment locally.
        const pendingNonceHex = await rawRequest({
          method: 'eth_getTransactionCount',
          params: [subkey.id, 'pending'],
        });
        let nonce = parseInt(pendingNonceHex, 16);

        const result: {
          usdc: Array<{ token: string; amount: string; txHash: Hex }>;
          native: { amount: string; txHash: Hex } | null;
        } = { usdc: [], native: null };

        // ── Collateral sweep (both v1 USDC.e and v2 Polymarket USD) ──
        //
        // A subkey created under v1 may hold USDC.e; a subkey created under
        // v2 may hold Polymarket USD; a subkey that spans the migration may
        // hold BOTH. Sweep any non-zero balance we find on either token so
        // removal doesn't orphan funds on the wrong-version collateral.
        if (!opts.nativeOnly && subkey.boundChainId === 137) {
          const tokens: Array<{ addr: Address; label: string }> = [
            { addr: COLLATERAL_V2, label: 'Polymarket USD' },
            { addr: COLLATERAL_V1, label: 'USDC.e' },
          ];
          for (const tok of tokens) {
            const bal = (await ctx.walletClient.readContract({
              address: tok.addr,
              abi: ERC20_ABI,
              functionName: 'balanceOf',
              args: [subkey.id],
            })) as bigint;
            if (bal === 0n) continue;

            spinner.text = `Sweeping ${formatUnits(bal, COLLATERAL_DECIMALS)} ${tok.label} → smart account...`;
            const calldata = encodeFunctionData({
              abi: ERC20_ABI,
              functionName: 'transfer',
              args: [dest, bal],
            });
            const txHash = await walletClient.sendTransaction({
              to: tok.addr,
              data: calldata,
              gas: 80000n,
              gasPrice,
              nonce: nonce++,
            } as Parameters<typeof walletClient.sendTransaction>[0]);
            await ctx.walletClient.raw.waitForTransactionReceipt({ hash: txHash });
            result.usdc.push({
              token: tok.label,
              amount: formatUnits(bal, COLLATERAL_DECIMALS),
              txHash,
            });
          }
        }

        // ── Native sweep → smart account ──
        if (!opts.usdcOnly) {
          const nativeBal = (await ctx.walletClient.getBalance(subkey.id)).wei;

          // Probe gas needed for this specific smart-account's receive() path.
          // Elytro accounts' proxy + impl typically need ~26k; 21k reverts.
          // We use the on-chain estimate + 50% buffer, floored at 40k.
          let estimatedGas: bigint;
          try {
            const gasHex = await rawRequest({
              method: 'eth_estimateGas',
              params: [
                {
                  from: subkey.id,
                  to: dest,
                  value: '0x1',
                },
              ],
            });
            estimatedGas = BigInt(gasHex);
          } catch (err) {
            throw new Error(
              `Smart account ${dest} rejected native transfer probe — its implementation may not expose a payable receive(). ` +
                `Upstream fix needed; sweep native aborted. ` +
                `(${(err as Error).message})`,
            );
          }

          // Budget with generous headroom: actual estimate × 1.5, floored at 40k.
          const gasLimit =
            (estimatedGas * 150n) / 100n > 40000n ? (estimatedGas * 150n) / 100n : 40000n;

          const nativeGasCost = gasLimit * gasPrice;
          if (nativeBal > nativeGasCost) {
            const sendValue = nativeBal - nativeGasCost;
            spinner.text = `Sweeping ${formatEther(sendValue)} ${chainConfig.nativeCurrency.symbol} → smart account...`;
            const txHash = await walletClient.sendTransaction({
              to: dest,
              value: sendValue,
              gas: gasLimit,
              gasPrice,
              nonce: nonce++,
            } as Parameters<typeof walletClient.sendTransaction>[0]);
            await ctx.walletClient.raw.waitForTransactionReceipt({ hash: txHash });
            result.native = {
              amount: `${formatEther(sendValue)} ${chainConfig.nativeCurrency.symbol}`,
              txHash,
            };
          }
        }

        spinner.stop();

        if (result.usdc.length === 0 && !result.native) {
          outputResult({
            status: 'nothing_to_sweep',
            from: subkey.id,
            hint: 'Subkey has no non-dust balance.',
          });
          return;
        }

        outputResult({
          status: 'swept',
          from: subkey.id,
          to: dest,
          usdc: result.usdc,
          native: result.native,
        });
      } catch (err) {
        spinner.stop();
        outputError(ERR_INTERNAL, sanitizeErrorMessage((err as Error).message));
      }
    });
}
