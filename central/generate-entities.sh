# Run this script after adding new migrations AND applying the migrations by either:
# * restarting the server
# * applying manually via `sea-orm-cli migrate up`

sea-orm-cli generate entity --output-dir ./src/db/entity