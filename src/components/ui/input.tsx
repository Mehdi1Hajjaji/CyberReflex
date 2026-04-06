import * as React from "react";
import { cn } from "@/lib/utils";

export const Input = React.forwardRef<
  HTMLInputElement,
  React.ComponentProps<"input">
>(({ className, ...props }, ref) => {
  return (
    <input
      ref={ref}
      className={cn(
        "flex h-14 w-full rounded-2xl border border-line bg-slate-950/60 px-4 font-mono text-sm text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] outline-none placeholder:text-muted/70 focus:border-accent/60 focus:ring-2 focus:ring-accent/15",
        className,
      )}
      {...props}
    />
  );
});

Input.displayName = "Input";
