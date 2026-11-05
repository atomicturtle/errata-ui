import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

export function useTrackerParams() {
  const [params, setParams] = useSearchParams();

  const update = useCallback(
    (next: Record<string, string | string[] | null>, resetPage = true) => {
      const updated = new URLSearchParams(params);
      for (const [key, value] of Object.entries(next)) {
        updated.delete(key);
        if (value == null || value === "") continue;
        if (Array.isArray(value)) {
          value.filter(Boolean).forEach((item) => updated.append(key, item));
        } else {
          updated.set(key, value);
        }
      }
      if (resetPage) updated.delete("page");
      setParams(updated, { replace: true });
    },
    [params, setParams]
  );

  return {
    params,
    update,
    page: Math.max(1, Number(params.get("page") || "1") || 1),
    limit: Number(params.get("limit") || "20") || 20,
  };
}

export function useDebouncedQuery(
  params: URLSearchParams,
  update: (next: Record<string, string | string[] | null>, resetPage?: boolean) => void
) {
  const urlQuery = params.get("q") ?? "";
  const [draft, setDraft] = useState(urlQuery);

  useEffect(() => {
    setDraft(urlQuery);
  }, [urlQuery]);

  useEffect(() => {
    if (draft === urlQuery) return;
    const handle = window.setTimeout(() => {
      update({ q: draft || null });
    }, 400);
    return () => window.clearTimeout(handle);
  }, [draft, urlQuery, update]);

  return { draft, setDraft };
}
