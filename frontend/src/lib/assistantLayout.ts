export const DEFAULT_ASSISTANT_WIDTH = 620;

export function assistantWidthBounds(viewport: number) {
  const max = Math.max(1, Math.floor(viewport * 0.85));
  return { min: Math.min(400, max), max };
}

export function clampAssistantWidth(width: number, viewport: number): number {
  const { min, max } = assistantWidthBounds(viewport);
  return Math.max(min, Math.min(max, Math.round(width)));
}

export function nextAssistantWidth(key: string, width: number, viewport: number): number | null {
  const { min, max } = assistantWidthBounds(viewport);
  switch (key) {
    case "ArrowLeft": return clampAssistantWidth(width + 24, viewport);
    case "ArrowRight": return clampAssistantWidth(width - 24, viewport);
    case "Home": return min;
    case "End": return max;
    case "Enter": return clampAssistantWidth(DEFAULT_ASSISTANT_WIDTH, viewport);
    default: return null;
  }
}
