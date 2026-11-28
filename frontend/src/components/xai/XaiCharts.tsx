"use client";

import * as echarts from "echarts/core";
import { BarChart, GaugeChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import type { ClassifierClassItem } from "@/lib/explainableAi";
import type { VerdictLevel } from "@/lib/types";

echarts.use([GaugeChart, BarChart, GridComponent, TooltipComponent, CanvasRenderer]);

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

const VERDICT_ACCENT: Record<VerdictLevel, string> = {
  SAFE: "#10b981",
  SUSPICIOUS: "#f59e0b",
  HIGH_RISK: "#f97316",
  CRITICAL_SCAM: "#ef4444",
};

interface RiskScoreGaugeChartProps {
  score: number;
  verdict: VerdictLevel;
  verdictLabel: string;
}

export function RiskScoreGaugeChart({
  score,
  verdict,
  verdictLabel,
}: RiskScoreGaugeChartProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const chart = echarts.init(el, undefined, { renderer: "canvas" });
    const reduced = prefersReducedMotion();
    const activeColor = VERDICT_ACCENT[verdict];

    chart.setOption({
      animation: !reduced,
      animationDuration: reduced ? 0 : 480,
      animationEasing: "cubicOut",
      series: [
        {
          type: "gauge",
          startAngle: 205,
          endAngle: -25,
          min: 0,
          max: 100,
          splitNumber: 4,
          radius: "94%",
          center: ["50%", "64%"],
          axisLine: {
            lineStyle: {
              width: 14,
              color: [
                [0.24, "rgba(16, 185, 129, 0.35)"],
                [0.49, "rgba(245, 158, 11, 0.35)"],
                [0.74, "rgba(249, 115, 22, 0.35)"],
                [1, "rgba(239, 68, 68, 0.4)"],
              ],
            },
          },
          progress: {
            show: true,
            width: 14,
            roundCap: true,
            itemStyle: {
              color: activeColor,
            },
          },
          pointer: {
            show: true,
            length: "54%",
            width: 4,
            itemStyle: {
              color: "#f1f5f9",
            },
          },
          anchor: {
            show: true,
            size: 10,
            itemStyle: {
              color: "#0b101b",
              borderColor: activeColor,
              borderWidth: 2.5,
            },
          },
          axisTick: {
            distance: -20,
            length: 4,
            lineStyle: { color: "#475569", width: 1 },
          },
          splitLine: {
            distance: -22,
            length: 8,
            lineStyle: { color: "#64748b", width: 1.5 },
          },
          axisLabel: {
            distance: -36,
            color: "#94a3b8",
            fontSize: 10,
            fontFamily: "var(--font-mono), monospace",
          },
          detail: {
            valueAnimation: !reduced,
            offsetCenter: [0, "28%"],
            formatter: "{value}/100",
            color: activeColor,
            fontSize: 22,
            fontWeight: 700,
            fontFamily: "var(--font-mono), monospace",
          },
          data: [{ value: Math.max(0, Math.min(100, score)) }],
        },
      ],
    });

    const ro =
      typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(() => {
            chart.resize();
          })
        : null;
    ro?.observe(el);

    return () => {
      ro?.disconnect();
      chart.dispose();
    };
  }, [score, verdict]);

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label={`Đồng hồ chỉ số rủi ro tổng hợp: ${score} trên 100 (${verdictLabel})`}
      className="h-[196px] w-full"
    />
  );
}

interface ClassifierDistributionChartProps {
  items: ClassifierClassItem[];
}

const TONE_COLOR: Record<ClassifierClassItem["tone"], string> = {
  safe: "#10b981",
  advisory: "#0ea5e9",
  risk: "#f59e0b",
  injection: "#ef4444",
};

export function ClassifierDistributionChart({ items }: ClassifierDistributionChartProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || items.length === 0) return;
    const chart = echarts.init(el, undefined, { renderer: "canvas" });
    const reduced = prefersReducedMotion();
    const reversed = [...items].reverse();

    chart.setOption({
      animation: !reduced,
      animationDuration: reduced ? 0 : 420,
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: "#070b14",
        borderColor: "#364761",
        borderWidth: 1,
        textStyle: { color: "#f1f5f9", fontSize: 11 },
        formatter: (params: unknown) => {
          const arr = Array.isArray(params) ? params : [params];
          const first = arr[0] as { name?: string; value?: number } | undefined;
          if (!first) return "";
          return `${first.name ?? ""}: <strong>${first.value ?? 0}%</strong>`;
        },
      },
      grid: {
        left: 8,
        right: 44,
        top: 8,
        bottom: 8,
        containLabel: true,
      },
      xAxis: {
        type: "value",
        min: 0,
        max: 100,
        axisLabel: {
          color: "#94a3b8",
          fontSize: 10,
          formatter: "{value}%",
        },
        splitLine: {
          lineStyle: { color: "rgba(39, 52, 73, 0.7)", type: "dashed" },
        },
      },
      yAxis: {
        type: "category",
        data: reversed.map((item) => item.labelVi),
        axisLine: { lineStyle: { color: "#273449" } },
        axisTick: { show: false },
        axisLabel: {
          color: "#cbd5e1",
          fontSize: 11,
          width: 158,
          overflow: "truncate",
        },
      },
      series: [
        {
          type: "bar",
          barMaxWidth: 16,
          data: reversed.map((item) => ({
            value: item.percent,
            itemStyle: {
              color: item.isPredicted
                ? TONE_COLOR[item.tone]
                : `${TONE_COLOR[item.tone]}88`,
              borderRadius: [0, 5, 5, 0],
            },
          })),
          label: {
            show: true,
            position: "right",
            formatter: "{c}%",
            color: "#cbd5e1",
            fontSize: 10,
            fontFamily: "var(--font-mono), monospace",
          },
        },
      ],
    });

    const ro =
      typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(() => {
            chart.resize();
          })
        : null;
    ro?.observe(el);

    return () => {
      ro?.disconnect();
      chart.dispose();
    };
  }, [items]);

  const summary = items
    .slice(0, 3)
    .map((item) => `${item.labelVi}: ${item.percent}%`)
    .join(", ");

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label={`Phân bố điểm đầu ra 7 lớp của bộ phân loại E5 ONNX. Cao nhất: ${summary}`}
      style={{ height: `${Math.max(180, items.length * 34)}px` }}
      className="w-full"
    />
  );
}
