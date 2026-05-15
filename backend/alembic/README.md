# RegentClaw — Alembic Migrations

## First-time setup (DB already created by `create_all`)

```bash
# Inside Docker (recommended):
docker compose exec backend alembic stamp 0001

# Locally (ensure DB is accessible):
cd backend && alembic stamp 0001
```

This tells Alembic "the database already has all the tables from the baseline —
don't try to create them again."

## Applying migrations to a fresh database

```bash
docker compose exec backend alembic upgrade head
```

## Adding a new migration after a schema change

1. Edit or add a model in `app/models/`
2. Generate the migration:
   ```bash
   docker compose exec backend alembic revision --autogenerate -m "add_user_table"
   ```
3. Review the generated file in `alembic/versions/`
4. Apply it:
   ```bash
   docker compose exec backend alembic upgrade head
   ```

## Rolling back

```bash
# Roll back one step
docker compose exec backend alembic downgrade -1

# Roll back to a specific revision
docker compose exec backend alembic downgrade 0001
```

## Checking status

```bash
docker compose exec backend alembic current   # current DB version
docker compose exec backend alembic history   # full migration history
```
