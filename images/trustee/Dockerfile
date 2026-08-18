# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BUILDPLATFORM=linux/amd64
ARG TARGETPLATFORM=linux/amd64

FROM --platform=${BUILDPLATFORM} mirror.gcr.io/library/rust@sha256:bbde3ca426faeebab3eb58b8005d3d6da70607817a14bb92a55c94611d4d905f AS builder

ARG DCAP_VERSION=1_27_100
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git gpg gnupg-agent \
    && curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
        | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg \
    && curl -fsSL \
        "https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg" \
        > /etc/apt/preferences.d/99dcap \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' \
        > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libclang-dev \
        libprotobuf-dev \
        libsgx-dcap-quote-verify-dev \
        libssl-dev \
        libtss2-dev \
        make \
        perl \
        pkg-config \
        protobuf-compiler \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/trustee
COPY . .

RUN --mount=type=cache,id=qualification-trustee-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=qualification-trustee-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=qualification-trustee-target,target=/usr/src/trustee/target \
    cargo build -p kbs --locked --release --no-default-features --features coco-as-builtin \
    && install -D -m0755 target/release/kbs /out/kbs

FROM --platform=${TARGETPLATFORM} mirror.gcr.io/library/ubuntu@sha256:019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467

ARG DCAP_VERSION=1_27_100
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gpg gnupg-agent \
    && curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
        | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg \
    && curl -fsSL \
        "https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg" \
        > /etc/apt/preferences.d/99dcap \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' \
        > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libsgx-dcap-quote-verify \
        libtss2-dev \
        libtss2-esys-3.0.2-0 \
        libtss2-tctildr0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*

COPY --from=builder /out/kbs /usr/local/bin/kbs

ENV DEBIAN_FRONTEND=""
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kbs"]
