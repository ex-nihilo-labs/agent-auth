import { chromium, type Browser, type Page } from "playwright-core";
import type { BrowserStep } from "./steps.js";
import { InjectionError } from "../errors.js";

/**
 * CDP browser injector.
 * Connects to an existing Chrome instance via CDP and executes steps.
 * Credentials are injected directly into DOM — never returned to the caller.
 */

export interface InjectorConfig {
  /** CDP endpoint URL, e.g. "http://localhost:9222" */
  cdpUrl: string;
  /** Separate user-data-dir for auth browser (isolation from agent's browser) */
  userDataDir?: string;
}

export class BrowserInjector {
  private browser: Browser | null = null;
  private config: InjectorConfig;

  constructor(config: InjectorConfig) {
    this.config = config;
  }

  async connect(): Promise<void> {
    this.browser = await chromium.connectOverCDP(this.config.cdpUrl);
  }

  async disconnect(): Promise<void> {
    if (this.browser) {
      await this.browser.close().catch(() => {});
      this.browser = null;
    }
  }

  /**
   * Execute a sequence of browser steps on the current page.
   * Returns the final page URL (for domain verification after redirects).
   */
  async execute(
    steps: BrowserStep[],
    targetUrl: string
  ): Promise<{ finalUrl: string; success: boolean }> {
    if (!this.browser) {
      throw new InjectionError("not_connected", "Browser not connected. Call connect() first.");
    }

    const contexts = this.browser.contexts();
    const ctx = contexts[0];
    if (!ctx) {
      throw new InjectionError("no_context", "No browser contexts available.");
    }

    const pages = ctx.pages();
    let page: Page;

    if (pages.length === 0) {
      page = await ctx.newPage();
    } else {
      page = pages[0]!;
    }

    // Navigate to target URL if not already there
    const currentUrl = page.url();
    if (!currentUrl.startsWith(targetUrl)) {
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
    }

    for (const step of steps) {
      await this.executeStep(page, step);
    }

    return {
      finalUrl: page.url(),
      success: true,
    };
  }

  private async executeStep(page: Page, step: BrowserStep): Promise<void> {
    switch (step.action) {
      case "fill": {
        const el = await page.waitForSelector(step.selector, { timeout: 5000 });
        if (!el) throw new InjectionError("element_not_found", `Element not found: ${step.selector}`, step.selector);
        await el.fill(step.value);
        break;
      }

      case "type": {
        // Character-by-character typing for React/SPA controlled inputs
        const el = await page.waitForSelector(step.selector, { timeout: 5000 });
        if (!el) throw new InjectionError("element_not_found", `Element not found: ${step.selector}`, step.selector);
        await el.click();
        await page.keyboard.type(step.value, { delay: step.delay });
        break;
      }

      case "click": {
        const el = await page.waitForSelector(step.selector, { timeout: 5000 });
        if (!el) throw new InjectionError("element_not_found", `Element not found: ${step.selector}`, step.selector);
        await el.click();
        break;
      }

      case "wait": {
        if (step.selector) {
          await page.waitForSelector(step.selector, { timeout: step.timeout });
        } else {
          await page.waitForTimeout(step.timeout);
        }
        break;
      }

      case "select": {
        const el = await page.waitForSelector(step.selector, { timeout: 5000 });
        if (!el) throw new InjectionError("element_not_found", `Element not found: ${step.selector}`, step.selector);
        await page.selectOption(step.selector, step.value);
        break;
      }
    }
  }
}
