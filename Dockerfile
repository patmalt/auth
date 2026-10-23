FROM swift:6.2-jammy AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Package.swift ./
COPY Package.resolved ./
RUN swift package resolve
COPY Sources ./Sources
COPY Tests ./Tests
RUN swift build -c release --product AuthService

FROM swift:6.2-jammy-slim

RUN useradd --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app
COPY --from=build /app/.build/release/AuthService /app/AuthService
USER appuser
EXPOSE 8080
CMD ["/app/AuthService"]

