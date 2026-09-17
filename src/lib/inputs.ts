/**
 * Every `core.getInput` the setup and post steps make, in one place, so that
 * what this action reads is answerable from one file rather than by grepping
 * the entry points. The report action has its own (report/src/lib/inputs.ts).
 *
 * Read in two calls rather than one because main() needs the engine before it
 * resolves the image and the rules only after: folding them together would
 * move rule validation ahead of image verification, changing which error a
 * run with both problems reports.
 */
import * as core from "@actions/core";

import {
  buildACLRules,
  parseKnownBlockedRulesOrThrow,
  parseRulesOrThrow,
} from "#core/lib/acl/rules.ts";
import { buildUrlRules } from "#core/lib/acl/url-rules.ts";
import { DEFAULT_BUILDER_NAME } from "#core/lib/docker/report-source.ts";
import { resolveProxyEngine, type ProxyEngine } from "./engine.ts";

/** Narrowed to what this module needs, so a test can pass a plain lookup. */
export type GetInput = (name: string) => string;

export function readBuilderName(getInput: GetInput = core.getInput): string {
  return getInput("builder_name") || DEFAULT_BUILDER_NAME;
}

export interface EngineInputs {
  proxyEngine: ProxyEngine;
}

export function readEngineInputs(getInput: GetInput = core.getInput): EngineInputs {
  return { proxyEngine: resolveProxyEngine(getInput("proxy_engine")) };
}

export interface ParsedRuleInputs {
  proxyMode: string;
  httpsRules: string[];
  httpRules: string[];
  ipRules: string[];
  /** The raw text of each compiled URL rule, not the compiled form: only the
   *  container re-compiles them, and only inspect enforces them. */
  urlRules: string[];
  tlsRules: string[];
  knownBlockedRules: string[];
}

/**
 * Parse and validate every rule input.
 *
 * URL and TLS rules are compiled here even on the engines that ignore them,
 * purely so a typo fails at setup rather than silently inside the container.
 *
 * The statement order is the order a malformed-rule error surfaces in, so it
 * is deliberate rather than incidental.
 *
 * @throws {InvalidRulesError} if any rule is malformed
 */
export function readRuleInputs(getInput: GetInput = core.getInput): ParsedRuleInputs {
  const proxyMode = getInput("proxy_mode") || "restrict";
  const rules = buildACLRules({
    httpsRulesInput: getInput("allowed_https_rules"),
    httpRulesInput: getInput("allowed_http_rules"),
    ipRulesInput: getInput("allowed_ip_rules"),
  });
  const knownBlockedRules = parseKnownBlockedRulesOrThrow(getInput("known_blocked_rules"));
  const urlRulesInput = getInput("allowed_url_rules");
  const tlsRules = parseRulesOrThrow(getInput("allowed_tls_rules"));
  const urlRules = buildUrlRules(urlRulesInput).map((r) => r.raw);

  return {
    proxyMode,
    httpsRules: rules.httpsRules,
    httpRules: rules.httpRules,
    ipRules: rules.ipRules,
    urlRules,
    tlsRules,
    knownBlockedRules,
  };
}
