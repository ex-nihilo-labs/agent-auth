import { z } from "zod";

/**
 * Browser automation step types.
 * Each step is an action the injector executes via CDP.
 * Values may contain {{placeholders}} resolved before execution.
 */

const selectorSchema = z
  .string()
  .max(500)
  .refine(
    (s) =>
      !s.includes("javascript:") &&
      !s.includes("onclick=") &&
      !s.includes("<script") &&
      !s.includes("data:"),
    { message: "Selector contains blocked pattern" }
  );

export const FillStep = z.object({
  action: z.literal("fill"),
  selector: selectorSchema,
  value: z.string().max(1000),
});

export const TypeStep = z.object({
  action: z.literal("type"),
  selector: selectorSchema,
  value: z.string().max(1000),
  delay: z.number().int().min(10).max(200).default(50),
});

export const ClickStep = z.object({
  action: z.literal("click"),
  selector: selectorSchema,
});

export const WaitStep = z.object({
  action: z.literal("wait"),
  selector: selectorSchema.optional(),
  timeout: z.number().int().min(100).max(30000).default(5000),
});

export const SelectStep = z.object({
  action: z.literal("select"),
  selector: selectorSchema,
  value: z.string().max(500),
});

export const BrowserStep = z.discriminatedUnion("action", [
  FillStep,
  TypeStep,
  ClickStep,
  WaitStep,
  SelectStep,
]);

export type BrowserStep = z.infer<typeof BrowserStep>;

export const BrowserSteps = z
  .array(BrowserStep)
  .min(1)
  .max(20);

export type BrowserSteps = z.infer<typeof BrowserSteps>;
