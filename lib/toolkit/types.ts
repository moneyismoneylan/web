export type ToolCategory = 'Recon'|'Web'|'Crypto'|'Forensics'|'OSINT'|'Utils';

export interface ToolMeta {
  id: string;
  name: string;
  category: ToolCategory;
  description: string;
  offline: boolean;
  inputs: Array<{
    key: string;
    label: string;
    type: 'text'|'textarea'|'file'|'select'|'toggle'|'number';
    required?: boolean;
    options?: Array<{label:string; value:string|number}>;
  }>;
}

export interface ToolResult {
  ok: boolean;
  data?: unknown;
  error?: string;
  artifacts?: Array<{name:string; blob:Blob; mime:string}>;
  insights?: Array<{label:string; value:string|number; severity?:'info'|'warn'|'crit'}>;
  score?: number;
}

export interface ToolDefinition {
  meta: ToolMeta;
  run: (input: Record<string, unknown>, signal: AbortSignal) => Promise<ToolResult>;
  component?: React.ComponentType;
}
