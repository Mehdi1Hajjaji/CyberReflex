import * as React from "react";
import { cn } from "@/lib/utils";

type ButtonProps = React.ComponentProps<"button"> & {
  variant?: "default" | "outline" | "ghost";
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", type = "button", ...props }, ref) => {
    return (
      <button
        ref={ref}
        type={type}
        className={cn(
          "inline-flex h-12 items-center justify-center rounded-2xl px-5 text-sm font-medium shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 disabled:pointer-events-none disabled:opacity-50",
          variant === "default" &&
            "bg-accent text-slate-950 hover:-translate-y-0.5 hover:bg-accent/90",
          variant === "outline" &&
            "border border-line bg-white/5 text-white hover:bg-white/8",
          variant === "ghost" && "bg-transparent text-muted hover:text-white",
          className,
        )}
        {...props}
      />
    );
  },
);

Button.displayName = "Button";
