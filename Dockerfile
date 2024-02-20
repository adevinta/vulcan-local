# Copyright 2021 Adevinta

FROM docker:25.0-git

WORKDIR /app

COPY vulcan-local .

ENTRYPOINT [ "/app/vulcan-local" ]
