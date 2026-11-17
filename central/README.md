# Central server

## Creating migrations

1. Ensure sea-orm-cli is installed:
```sh
which sea-orm-cli
# if doesn't exist
cargo install sea-orm-cli@^2.0
```

2. Generate a migration with the appropriate name
```sh
sea-orm-cli migrate generate add_cool_new_table
```

3. Open the newly generated file in `migration/src` and put your migration code
4. Run the migration:

```sh
# change this if your database is in a different place
export DATABASE_URL=sqlite://db.sqlite?mode=rwc
sea-orm-cli migrate up
```

**If you need to revert the migration**, e.g. you forgot something or made a mistake, run the down script so you can rerun your migration again later:
```sh
sea-orm-cli migrate down
```

5. Upon success, generate new entities:
```sh
./generate-entities.sh
```
