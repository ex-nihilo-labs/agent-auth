import { spawnSync } from "node:child_process";
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
    // Navigate if not already on target (compare hostname+path, not query)
    const currentUrl = this.evalJs("window.location.href").replace(/^"|"$/g, "");
    const targetHost = new URL(targetUrl).host;
    const currentHost = (() => { try { return new URL(currentUrl).host; } catch { return ""; } })();
    if (currentHost !== targetHost) {
      this.cmd(["open", targetUrl, "--headed"]);
      this.cmd(["wait", "3000"]);
    }

    for (const step of steps) {
      await this.executeStep(step);
    }

    const finalUrl = this.evalJs("window.location.href").replace(/^"|"$/g, "");
    return { finalUrl, success: true };
  }

  private async executeStep(step: BrowserStep): Promise<void> {
    switch (step.action) {
      case "fill":
      case "type": {
        // Inject via JS eval — value passed as a single argv item, not via shell
        const js =
          `(()=>{` +
          `const el=document.querySelector(${JSON.stringify(step.selector)});` +
          `if(!el)throw new Error('Element not found: '+${JSON.stringify(step.selector)});` +
          `const setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;` +
          `setter.call(el,${JSON.stringify(step.value)});` +
          `el.dispatchEvent(new Event('input',{bubbles:true}));` +
          `el.dispatchEvent(new Event('change',{bubbles:true}));` +
          `return 'ok';` +
          `})()`;
        this.evalJs(js);
        break;
      }

      case "click": {
        this.cmd(["click", step.selector]);
        break;
      }

      case "wait": {
        if (step.selector) {
          this.cmd(["wait", step.selector]);
        } else {
          this.cmd(["wait", String(step.timeout ?? 5000)]);
        }
        break;
      }

      case "select": {
        this.cmd(["select", step.selector, step.value]);
        break;
      }
    }
  }

  /** Run agent-browser eval <js>. Returns stdout. */
  private evalJs(js: string): string {
    return this.cmd(["eval", js]);
  }

  /** Run an agent-browser subcommand. Argv passed directly — no shell. */
  private cmd(args: string[]): string {
    const result = spawnSync(this.bin, args, {
      encoding: "utf-8",
      timeout: 30000,
    });
    if (result.error) {
      throw new InjectionError("not_connected", `agent-browser spawn failed: ${result.error.message}`);
    }
    if (result.status !== 0) {
      const stderr = (result.stderr || "").trim();
      throw new InjectionError("not_connected", `agent-browser ${args[0]} failed: ${stderr}`);
    }
    return (result.stdout || "").trim();
  }
}
