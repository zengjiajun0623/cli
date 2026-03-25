import { Command } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { outputError, outputResult } from '../utils/display';
import { SERVICE_REGISTRY_API } from '../constants/serviceRegistry';

// ─── Types ────────────────────────────────────────────────────────────

interface Pricing {
  type: 'free' | 'fixed' | 'dynamic';
  amount?: string; // present when type='fixed', e.g. "2.000000"
  per?: string; // unit label for fixed, e.g. "charge", "request"
  description?: string; // label for dynamic, e.g. "dynamic charge"
}

interface Endpoint {
  method: string;
  path: string;
  description: string;
  pricing: Pricing;
  note?: string; // extra info shown below description, e.g. "per request"
  docs?: string; // link to endpoint-specific documentation
}

interface ServiceDocs {
  homepage?: string;
  llmsTxt?: string;
}

interface Service {
  id: string;
  name: string;
  description: string;
  categories: string[];
  serviceUrl: string;
  tags: string[];
  docs: ServiceDocs;
  endpoints: Endpoint[];
}

// ─── API ──────────────────────────────────────────────────────────────

const BASE = SERVICE_REGISTRY_API.endsWith('/') ? SERVICE_REGISTRY_API : `${SERVICE_REGISTRY_API}/`;

async function fetchServices(): Promise<Service[]> {
  const res = await fetch(`${BASE}index.json`, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Registry returned HTTP ${res.status}`);
  }
  const data = (await res.json()) as { services: Service[] };
  if (!Array.isArray(data.services)) {
    throw new Error('Unexpected response format from registry');
  }
  return data.services;
}

async function fetchService(id: string): Promise<Service> {
  const res = await fetch(`${BASE}${id}.json`, {
    headers: { Accept: 'application/json' },
  });
  if (res.status === 404) {
    throw new Error(
      `Service "${id}" not found. Run 'elytro services' to see all available services.`,
    );
  }
  if (!res.ok) {
    throw new Error(`Registry returned HTTP ${res.status}`);
  }
  return (await res.json()) as Service;
}

// ─── Formatting helpers ────────────────────────────────────────────────

function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

function formatPricing(pricing: Pricing): string {
  switch (pricing.type) {
    case 'free':
      return 'free';
    case 'fixed': {
      const amount = pricing.amount;
      const per = pricing.per ?? 'charge';
      if (!amount) {
        // Fallback when amount is missing or undefined to avoid "$undefined ..."
        return `fixed price per ${per}`;
      }
      return `$${amount} ${per}`;
    }
    case 'dynamic':
      return pricing.description ?? 'dynamic charge';
  }
}

// ─── Display: list view ───────────────────────────────────────────────

const COL = { id: 22, name: 24, category: 18 };

function printList(services: Service[]): void {
  const header =
    'ID'.padEnd(COL.id) +
    '  ' +
    'Name'.padEnd(COL.name) +
    '  ' +
    'Category'.padEnd(COL.category) +
    '  ' +
    'Service URL';

  console.log();
  console.log('  ' + chalk.bold(header));
  console.log('  ' + chalk.gray('─'.repeat(header.length)));

  for (const svc of services) {
    const row =
      svc.id.padEnd(COL.id) +
      '  ' +
      truncate(svc.name, COL.name).padEnd(COL.name) +
      '  ' +
      truncate(svc.categories.join(', '), COL.category).padEnd(COL.category) +
      '  ' +
      svc.serviceUrl;
    console.log('  ' + row);
  }

  console.log();
  console.log(
    chalk.gray(`  ${services.length} service(s). Run 'elytro services <id>' for details.`),
  );
  console.log();
}

// ─── Display: detail view ─────────────────────────────────────────────

const LABEL_WIDTH = 14; // "Service URL" is 11 chars; 14 gives consistent right-alignment
const METHOD_COL = 7; // right-aligns up to "DELETE" (6 chars)
const PATH_COL = 42; // path column width before pricing label

function field(key: string, value: string): void {
  console.log(`  ${chalk.gray(key.padStart(LABEL_WIDTH) + ':')} ${value}`);
}

function buildExample(method: string, serviceUrl: string, path: string): string {
  const parts = ['elytro request'];
  if (method !== 'GET') parts.push(`--method ${method}`);
  if (method !== 'GET') parts.push(`--json '{}'`);
  parts.push(serviceUrl + path);
  return parts.join(' ');
}

function printDetail(svc: Service): void {
  console.log();
  console.log(chalk.bold(svc.name));
  console.log(chalk.gray('─'.repeat(svc.name.length + 2)));
  console.log(svc.description);
  console.log();

  field('ID', svc.id);
  field('Categories', svc.categories.join(', '));
  field('Service URL', svc.serviceUrl);
  field('Tags', svc.tags.join(', '));

  const docs = svc.docs ?? {};
  if (docs.homepage || docs.llmsTxt) {
    console.log();
    console.log(chalk.bold('Docs:'));
    if (docs.homepage) field('Homepage', docs.homepage);
    if (docs.llmsTxt) field('LLMs.txt', docs.llmsTxt);
  }

  const endpoints = Array.isArray(svc.endpoints) ? svc.endpoints : [];
  if (endpoints.length > 0) {
    console.log();
    console.log(chalk.bold('Endpoints:'));
    const indent = '  ' + ' '.repeat(METHOD_COL + 1);
    for (const ep of endpoints) {
      console.log(
        `  ${chalk.cyan(ep.method.padStart(METHOD_COL))} ${ep.path.padEnd(PATH_COL)}  ${formatPricing(ep.pricing)}`,
      );
      console.log(`${indent}${chalk.gray(ep.description)}`);
      if (ep.note) {
        console.log(`${indent}${chalk.gray(ep.note)}`);
      }
      console.log(
        `${indent}${chalk.gray('example:')} ${buildExample(ep.method, svc.serviceUrl, ep.path)}`,
      );
      if (ep.docs) {
        console.log(`${indent}${chalk.gray('docs:')}    ${ep.docs}`);
      }
    }
  }

  console.log();
}

// ─── Structured (JSON) output ─────────────────────────────────────────

function outputServiceList(services: Service[]): void {
  outputResult({
    services: services.map((svc) => ({
      id: svc.id,
      name: svc.name,
      categories: svc.categories,
      serviceUrl: svc.serviceUrl,
      description: svc.description,
    })),
  });
}

function outputServiceDetail(svc: Service): void {
  outputResult({
    id: svc.id,
    name: svc.name,
    description: svc.description,
    categories: svc.categories,
    serviceUrl: svc.serviceUrl,
    tags: svc.tags,
    docs: svc.docs,
    endpoints: (Array.isArray(svc.endpoints) ? svc.endpoints : []).map((ep) => ({
      method: ep.method,
      path: ep.path,
      description: ep.description,
      pricing: ep.pricing,
      ...(ep.note ? { note: ep.note } : {}),
      ...(ep.docs ? { docs: ep.docs } : {}),
      example: buildExample(ep.method, svc.serviceUrl, ep.path),
    })),
  });
}

// ─── Command registration ─────────────────────────────────────────────

export function registerServicesCommand(program: Command): void {
  program
    .command('services')
    .description('Browse Elytro-verified x402-compatible services')
    .argument('[id]', 'Service ID for detailed information')
    .option('--json', 'Output structured JSON instead of human-readable text')
    .action(async (id?: string, options?: { json?: boolean }) => {
      // Use JSON output when --json is passed or stdout is not a TTY (e.g. pipes, MCP callers)
      const useJson = options?.json || !process.stdout.isTTY;

      const spinner = ora(id ? `Fetching service info…` : 'Fetching service catalog…').start();
      try {
        if (id) {
          const svc = await fetchService(id);
          spinner.stop();
          useJson ? outputServiceDetail(svc) : printDetail(svc);
        } else {
          const services = await fetchServices();
          spinner.stop();
          useJson ? outputServiceList(services) : printList(services);
        }
      } catch (err) {
        spinner.fail('Failed to fetch service catalog.');
        outputError(-32000, (err as Error).message);
      }
    });
}
