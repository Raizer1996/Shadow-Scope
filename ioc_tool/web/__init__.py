"""ShadowScope REST API package.

Thin FastAPI layer over the existing async enrichment pipeline. The CLI
``shadowscope serve`` subcommand launches ``ioc_tool.web.api.app`` via
uvicorn. External consumers (notably the homelab secops dashboard) talk
to this app over HTTP — see :mod:`ioc_tool.web.api` for routes.
"""
