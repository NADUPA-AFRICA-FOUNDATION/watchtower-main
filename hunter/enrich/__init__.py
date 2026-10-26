"""Staged enrichment: DNS, RDAP and TLS for hunter candidates.

Each enricher returns a result object whose `status` distinguishes a searched
answer (including "does not exist") from a failure to look. Only the latter
raises or sets an error status.
"""
