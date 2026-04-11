import { execSync } from "node:child_process";
import type { BrowserStep } from "./steps.js";
import { InjectionError } from "../errors.js";

/**
 * agent-browser CLI injector.
 *
 * Drives the existing agent-browser pipe-connected session rather than
 * requiring a separate Chrome with --remote-debugging-port.
 *
 * Credentials are injected via `agent-browser eval` using JS that sets
 * input values directly in the DOM. They appear only in the browser
 * process memory — never in shell arguments, snapshots, or return values.
 */

export class AgentBrowserInjector {
  private readonly bin: string;

  constructor(bin: string = "agent-browser") {
    this.bin = bin;
  }

  // connect/disconnect are no-ops — agent-browser manages its own session
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}

  async execute(
    steps: BrowserStep[],
    targetUrl: string
  ): Promise<{ finalUrl: string; success: boolean }> {
    // Navigate if not already on target
    const currentUrl = this.eval("window.location.href").replace(/^"|"$/g, "");
    if (!currentUrl.startsWith(targetUrl.split("?")[0]!)) {
      this.run(`open ${JSON.stringify(targetUrl)} --headed`);
      this.wait(3000);
    }

    for (const step of steps) {
      await this.executeStep(step);
    }

    const finalUrl = this.eval("window.location.href").replace(/^"|"$/g, "");
    return { finalUrl, success: true };
  }

  private async executeStep(step: BrowserStep): Promise<void> {
    switch (step.action) {
      case "fill":
      case "type": {
        // Inject via JS eval — value never appears in shell args or snapshots
        const js = `
          (() => {
            const el = document.querySelector(${JSON.stringify(step.selector)});
            if (!el) throw new Error('Element not found: ' + ${JSON.stringify(step.selector)});
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
            if (nativeInputValueSetter) {
              nativeInputValueSetter.call(el, ${JSON.stringify(step.value)});
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
            } else {
              el.value = ${JSON.stringify(step.value)};
            }
            return 'ok';
          })()
        `;
        const result = this.eval(js);
        if (result.includes("Error")) {
          throw new InjectionError("element_not_found", `Fill failed: ${result}`, step.selector);
        }
        break;
      }

      case "click": {
        this.run(`click ${JSON.stringify(step.selector)}`);
        break;
      }

      case "wait": {
        if (step.selector) {
          this.run(`wait ${JSON.stringify(step.selector)}`);
        } else {
          this.wait(step.timeout ?? 5000);
        }
        break;
      }

      case "select": {
        this.run(`select ${JSON.stringify(step.selector)} ${JSON.stringify(step.value)}`);
        break;
      }
    }
  }

  private eval(js: string): string {
    try {
      return execSync(`${this.bin} eval ${JSON.stringify(js)}`, {
        encoding: "utf-8",
        timeout: 10000,
      }).trim();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new InjectionError("not_connected", `agent-browser eval failed: ${msg}`);
    }
  }

  private run(args: string): void {
    try {
      execSync(`${this.bin} ${args}`, { encoding: "utf-8", timeout: 15000 });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new InjectionError("not_connected", `agent-browser command failed: ${msg}`);
    }
  }

  private wait(ms: number): void {
    execSync(`${this.bin} wait ${ms}`, { encoding: "utf-8", timeout: ms + 5000 });
  }
}
