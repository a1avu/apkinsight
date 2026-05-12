const BASE_URL = 'http://localhost:8000';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function analyzeFile(
  file: File,
  llmProvider: string,
  apiKey: string,
): Promise<unknown> {
  const form = new FormData();
  form.append('file', file);
  form.append('llm_provider', llmProvider);
  form.append('api_key', apiKey);

  const res = await fetch(`${BASE_URL}/analyze`, {
    method: 'POST',
    body: form,
  });
  return handleResponse<unknown>(res);
}

export async function getStatus(): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/status`);
  return handleResponse<unknown>(res);
}

export async function getResult(): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/result`);
  return handleResponse<unknown>(res);
}

export async function getAnalysisList(): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/analysis/list`);
  return handleResponse<unknown>(res);
}

export async function getAnalysis(id: string): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/analysis/${id}`);
  return handleResponse<unknown>(res);
}

export async function getAnalysisOsv(id: string): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/analysis/${id}/osv`);
  return handleResponse<unknown>(res);
}

export async function deleteAnalysis(id: string): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/analysis/${id}`, { method: 'DELETE' });
  return handleResponse<unknown>(res);
}

export async function getReport(id: string): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/report/${id}`);
  return handleResponse<unknown>(res);
}
