# Copyright 2021 Adevinta

FROM docker:20.10-git

WORKDIR /app

COPY vulcan-local .

ENTRYPOINT [ "/app/vulcan-local" ]
