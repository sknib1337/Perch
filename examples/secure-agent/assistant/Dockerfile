# Minimal demo agent for the secure-agent example -- replace with your real agent.
# stdlib-only on purpose: no `pip install`, so the build is fast and there's
# nothing extra to audit. Perch runs this under a non-root user, a read-only root
# filesystem, all Linux capabilities dropped, and (with `egress:`) default-deny
# outbound -- see the security defaults in perch/manifest.py.
FROM python:3.12-slim
WORKDIR /app
COPY agent.py /app/agent.py
ENTRYPOINT ["python", "/app/agent.py"]
