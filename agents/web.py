---
*** Begin Patch
*** Update File: agents/web.py
@@
     def _get(self, path="", params=None, timeout=8):
         url = path if str(path).startswith(("http://", "https://")) else f"{self.base_url}{path}"
         if not self.is_in_scope(url):
             return 0, "", {}
         if self.dry_run:
             self.logger.info(f"[DRY RUN] GET {url}", "Web")
             return 200, "<html>dry-run</html>", {}
         self._rate_limit()
         try:
             r = self._session.get(url, params=params, timeout=timeout,
                                    allow_redirects=False)
             return r.status_code, r.text[:16384], dict(r.headers)
-        except requests.exceptions.HTTPError as e:
-            return e.response.status_code if e.response else 0, "", {}
-        except Exception:
-            return 0, "", {}
+        except requests.exceptions.HTTPError as e:
+            # Return status code when available, otherwise log and return 0
+            code = e.response.status_code if e.response else 0
+            try:
+                self.logger.warning(f"HTTP error GET {url}: {e}", "Web")
+            except Exception:
+                pass
+            return code, "", {}
+        except requests.exceptions.RequestException as e:
+            # Network-level errors (connection, timeout, SSL)
+            try:
+                self.logger.warning(f"Request failed GET {url}: {e}", "Web")
+            except Exception:
+                pass
+            return 0, "", {}
+        except Exception as e:
+            try:
+                self.logger.error(f"Unexpected error GET {url}: {e}", "Web")
+            except Exception:
+                pass
+            return 0, "", {}
@@
     def _post(self, path="", data=None, timeout=8):
         url = f"{self.base_url}{path}"
         if not self.is_in_scope(url):
             return 0, "", {}
         if self.dry_run:
             self.logger.info(f"[DRY RUN] POST {url}", "Web")
             return 200, "", {}
         self._rate_limit()
         try:
             r = self._session.post(url, data=data or {}, timeout=timeout,
                                     allow_redirects=False)
             return r.status_code, r.text[:8192], dict(r.headers)
-        except Exception:
-            return 0, "", {}
+        except requests.exceptions.RequestException as e:
+            try:
+                self.logger.warning(f"Request failed POST {url}: {e}", "Web")
+            except Exception:
+                pass
+            return 0, "", {}
+        except Exception as e:
+            try:
+                self.logger.error(f"Unexpected error POST {url}: {e}", "Web")
+            except Exception:
+                pass
+            return 0, "", {}
*** End Patch
