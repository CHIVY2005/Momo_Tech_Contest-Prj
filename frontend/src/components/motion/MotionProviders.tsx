"use client";

import { domAnimation, LazyMotion, MotionConfig } from "motion/react";
import type { ReactNode } from "react";

import { SmoothScrollProvider } from "./SmoothScrollProvider";

export function MotionProviders({ children }: { children: ReactNode }) {
  return (
    <LazyMotion features={domAnimation} strict>
      <MotionConfig reducedMotion="user">
        <SmoothScrollProvider>{children}</SmoothScrollProvider>
      </MotionConfig>
    </LazyMotion>
  );
}
