FROM mariadb:10.11

# Copy initialization scripts
COPY ./docker-entrypoint-initdb.d/ /docker-entrypoint-initdb.d/

# Ensure correct permissions for the mysql user
RUN chown -R mysql:mysql /docker-entrypoint-initdb.d/ && \
    chmod -R 755 /docker-entrypoint-initdb.d/
