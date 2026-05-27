# --- Stage 1: Builder ---
# 使用目標平台的原生 Rust Alpine 映像檔
FROM --platform=$BUILDPLATFORM rust:1.85-alpine AS builder

# 安裝編譯所需的工具
RUN apk add --no-cache \
    musl-dev \
    gcc \
    make \
    cmake \
    perl \
    build-base \
    ca-certificates

WORKDIR /usr/src/doh-relay

# 1. 複製 Cargo 檔案以利用快取
COPY Cargo.toml Cargo.lock ./

# 2. 建立空專案並編譯依賴 (這部分會自動偵測架構)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/doh_relay*

# 3. 編譯實際的程式碼
COPY src ./src
RUN cargo build --release

# --- Stage 2: Runtime (Scratch) ---
FROM scratch

# 複製根憑證
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# 從正確的路徑複製二進位檔 (不再有硬編碼的架構路徑)
COPY --from=builder /usr/src/doh-relay/target/release/doh-relay /doh-relay

# 設定環境變數
ENV NUMA_URL=""
ENV DEBUG="false"

EXPOSE 5381

ENTRYPOINT ["/doh-relay"]
