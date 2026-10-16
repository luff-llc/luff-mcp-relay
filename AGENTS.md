# Repository instructions

Keep changes in this standalone repo and preserve unrelated work. Use focused
tests, then `npm run check` and `npm run demo` before release. Never test with
production traffic or credentials. Keep package allowlists and public history
explicit. Preserve MIT attribution and NOTICE.md.

Do not change crypto domain separators or wire headers as branding. Review OAuth
audiences, client/redirect binding, scopes and root catalog together. Provider
OAuth is a separate adapter. Distinguish synthetic from real-client evidence.
CI does not authorize npm publication or production deployment.
