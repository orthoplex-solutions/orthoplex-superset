
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: superset_cache
    restart: unless-stopped
    volumes:
      - redis:/data
    networks:
      - superset-net

  db:
    image: postgres:16-alpine
    container_name: superset_db
    restart: unless-stopped
    environment:
      POSTGRES_DB: superset
      POSTGRES_USER: superset
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - db_home:/var/lib/postgresql/data
    networks:
      - superset-net

  superset:
    image: apache/superset:latest
    container_name: superset_app
    restart: unless-stopped
    environment:
      # Superset's native environment variables (from docker/.env)
      SUPERSET_SECRET_KEY: ${SUPERSET_SECRET_KEY}
      
      # Database - these are used by docker-init.sh script
      DATABASE_DIALECT: postgresql
      DATABASE_HOST: db
      DATABASE_PORT: 5432
      DATABASE_DB: superset
      DATABASE_USER: superset
      DATABASE_PASSWORD: ${POSTGRES_PASSWORD}
      
      # Redis
      REDIS_HOST: redis
      REDIS_PORT: 6379
      
      # Examples
      SUPERSET_LOAD_EXAMPLES: no
      
      # Admin user (for initial setup)
      SUPERSET_ADMIN_USERNAME: ${ADMIN_USERNAME:-admin}
      SUPERSET_ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      SUPERSET_ADMIN_FIRSTNAME: Admin
      SUPERSET_ADMIN_LASTNAME: User
      SUPERSET_ADMIN_EMAIL: ${ADMIN_EMAIL:-admin@superset.com}
    
    volumes:
      - superset_home:/app/superset_home
    
    networks:
      - superset-net
    
    ports:
      - "8088:8088"
    
    depends_on:
      - db
      - redis
    
    command: >
      /bin/sh -c "
      superset db upgrade &&
      superset fab create-admin \
        --username $${SUPERSET_ADMIN_USERNAME} \
        --firstname $${SUPERSET_ADMIN_FIRSTNAME} \
        --lastname $${SUPERSET_ADMIN_LASTNAME} \
        --email $${SUPERSET_ADMIN_EMAIL} \
        --password $${SUPERSET_ADMIN_PASSWORD} || true &&
      superset init &&
      /usr/bin/run-server.sh
      "

  superset-worker:
    image: apache/superset:latest
    container_name: superset_worker
    command: celery --app=superset.tasks.celery_app:app worker --pool=prefork -O fair -c 4
    restart: unless-stopped
    environment:
      DATABASE_DIALECT: postgresql
      DATABASE_HOST: db
      DATABASE_PORT: 5432
      DATABASE_DB: superset
      DATABASE_USER: superset
      DATABASE_PASSWORD: ${POSTGRES_PASSWORD}
      REDIS_HOST: redis
      REDIS_PORT: 6379
      SUPERSET_SECRET_KEY: ${SUPERSET_SECRET_KEY}
    volumes:
      - superset_home:/app/superset_home
    networks:
      - superset-net
    depends_on:
      - superset

  superset-worker-beat:
    image: apache/superset:latest
    container_name: superset_worker_beat
    command: celery --app=superset.tasks.celery_app:app beat --pidfile /tmp/celerybeat.pid --schedule /tmp/celerybeat-schedule
    restart: unless-stopped
    environment:
      DATABASE_DIALECT: postgresql
      DATABASE_HOST: db
      DATABASE_PORT: 5432
      DATABASE_DB: superset
      DATABASE_USER: superset
      DATABASE_PASSWORD: ${POSTGRES_PASSWORD}
      REDIS_HOST: redis
      REDIS_PORT: 6379
      SUPERSET_SECRET_KEY: ${SUPERSET_SECRET_KEY}
    volumes:
      - superset_home:/app/superset_home
    networks:
      - superset-net
    depends_on:
      - superset-worker

volumes:
  superset_home:
  db_home:
  redis:

networks:
  superset-net:
