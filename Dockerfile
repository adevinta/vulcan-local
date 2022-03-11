# Copyright 2021 Adevinta

FROM docker:20.10.13-alpine3.15

RUN apk add git

WORKDIR /app

COPY vulcan-local .

ENTRYPOINT [ "/app/vulcan-local" ]
