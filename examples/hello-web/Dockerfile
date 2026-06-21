# Tiny static site on a hardened nginx-unprivileged base (listens on 8080, non-root).
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 8080
