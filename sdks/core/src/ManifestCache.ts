import type { SdkManifest } from './types';

interface CacheEntry {
    manifest: SdkManifest;
    fetchedAt: number;
    etag?: string;
}

const TTL_MS = 60 * 1000; // 60 seconds — matches server Cache-Control max-age

/**
 * In-memory manifest cache with a 60-second TTL.
 *
 * Usage:
 * ```ts
 * const cache = new ManifestCache();
 * const manifest = await cache.get('my-org', () => client.getManifest('my-org'));
 * ```
 */
export class ManifestCache {
    private readonly store = new Map<string, CacheEntry>();

    /**
     * Return the cached manifest for `orgId`, fetching via `fetcher` when
     * the cache is empty or stale.
     */
    async get(orgId: string, fetcher: () => Promise<SdkManifest>): Promise<SdkManifest> {
        const entry = this.store.get(orgId);
        if (entry && Date.now() - entry.fetchedAt < TTL_MS) {
            return entry.manifest;
        }

        const manifest = await fetcher();
        this.store.set(orgId, { manifest, fetchedAt: Date.now() });
        return manifest;
    }

    /**
     * Forcibly remove the cached entry for `orgId`.
     * The next call to `get()` will fetch fresh data.
     */
    invalidate(orgId: string): void {
        this.store.delete(orgId);
    }

    /** Remove all cached entries. */
    clear(): void {
        this.store.clear();
    }
}
