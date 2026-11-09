"""Resolve (country ISO2, region, city) -> (lon, lat) using the Mapbox Geocoding v6 API.

Results are cached in memory and on disk (geocache.json) so each place is looked up once.
City lookups fall back to the country centroid when the city can't be resolved.
Only answers are cached: a place Mapbox does not know is stored as "no location", but a failed look-up (no network,
missing or refused token, rate limit) is not stored, so it is tried again next time instead of staying blank.
"""
import json
import os
import threading
import time
import urllib.parse
import urllib.request

GEOCODE_URL = "https://api.mapbox.com/search/geocode/v6/forward"
FAILED = object()          # the look-up itself failed: do not cache
RETRY_AFTER = 300          # seconds without new look-ups after a failure (no hammering when offline)


class Geocoder:
    def __init__(self, token, cache_path="geocache.json"):
        self.token = token
        self.cache_path = cache_path
        self.lock = threading.RLock()
        self.cache = {}
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except (OSError, ValueError):
                self.cache = {}
        self._dirty = 0
        self._down_until = 0.0
        # older versions cached failed look-ups as "no location": forget those once, so they are looked up again
        if any(v is None for v in self.cache.values()) and not self.cache.get("__v2__"):
            self.cache = {k: v for k, v in self.cache.items() if v is not None}
            self.cache["__v2__"] = True
            self._dirty = 1

    @staticmethod
    def _key(cc, region, city):
        return f"{(cc or '').upper()}|{(region or '').upper()}|{(city or '').upper()}"

    def _query(self, q, cc, types):
        """[lon, lat], None when Mapbox has no such place, or FAILED when the look-up did not work."""
        if not self.token or time.time() < self._down_until:
            return FAILED
        params = {
            "q": q,
            "types": types,
            "limit": 1,
            "access_token": self.token,
        }
        if cc:
            params["country"] = cc.lower()
        url = GEOCODE_URL + "?" + urllib.parse.urlencode(params)
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.load(resp)
            feats = data.get("features") or []
            if feats:
                lon, lat = feats[0]["geometry"]["coordinates"][:2]
                return [round(lon, 4), round(lat, 4)]
            return None
        except Exception:
            self._down_until = time.time() + RETRY_AFTER
            return FAILED

    def _country(self, cc):
        key = self._key(cc, "", "")
        if key in self.cache:
            return self.cache[key]
        coords = self._query(cc, cc, "country")
        if coords is FAILED:
            return None
        self._store(key, coords)
        return coords

    def _store(self, key, coords):
        with self.lock:
            self.cache[key] = coords
            self._dirty += 1
            if self._dirty >= 25:
                self.flush()

    def flush(self):
        with self.lock:
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cache, f)
            os.replace(tmp, self.cache_path)
            self._dirty = 0

    def lookup(self, cc, region, city):
        """Return [lon, lat] or None. Never raises."""
        if not cc:
            return None
        key = self._key(cc, region, city)
        if key in self.cache:
            return self.cache[key] or self._country(cc)
        coords = None
        if city:
            q = ", ".join(p for p in (city, region) if p)
            coords = self._query(q, cc, "place,locality,district,region")
        elif region:
            coords = self._query(region, cc, "region")
        if coords is None and not city and not region:
            return self._country(cc)
        if coords is FAILED:
            return self._country(cc)
        self._store(key, coords)
        return coords or self._country(cc)
