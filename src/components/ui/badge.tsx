import * as React from "react";
import { cn } from "@/lib/utils";

type BadgeProps = React.ComponentProps<"div"> & {
  variant?: "default" | "outline" | "success" | "warning" | "destructive";
};

export function Badge({
  className,
  variant = "default",
  ...props
}: BadgeProps) {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full px-3 py-1 text-xs font-medium tracking-wide",
        variant === "default" && "bg-white/8 text-white/90",
        variant === "outline" && "border border-line bg-transparent text-muted",
        variant === "success" && "bg-success/15 text-success",
        variant === "warning" && "bg-warning/15 text-warning",
        variant === "destructive" && "bg-danger/15 text-danger",
        className,
      )}
      {...props}
    />
  );
}
