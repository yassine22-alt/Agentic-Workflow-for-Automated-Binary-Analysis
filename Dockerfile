FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    radare2 \
    binutils \
    file \
    upx-ucl \
  && rm -rf /var/lib/apt/lists/*

RUN r2 -v \
  && readelf --version \
  && objdump --version \
  && file --version \
  && upx -V

WORKDIR /app
