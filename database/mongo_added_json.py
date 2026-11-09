import os
import csv
import asyncio
import aiofiles
import hashlib
import datetime
import json
import gc
from pymongo import MongoClient, InsertOne
from async_lru import alru_cache
import math
from pathlib import Path

from shadowserver_pipeline import PROJECT_DIR, load_env_file

# Settings come from the project's .env (the same file the pipeline uses; see .env.example). Nothing secret is
# written in this file. Environment variables that are already set win over .env.
load_env_file(PROJECT_DIR / ".env")
mongo_host = os.environ.get("MONGO_HOST", "127.0.0.1")
mongo_port = int(os.environ.get("MONGO_PORT", "27017"))
mongo_username = os.environ.get("MONGO_USER", "")
mongo_password = os.environ.get("MONGO_PASSWORD", "")
mongo_auth_source = os.environ.get("MONGO_AUTH_SOURCE", "admin")
mongo_db_name = os.environ.get("MONGO_DB", "shadowserver")

# Directory to scan: <DATA_DIR>/sorting_backup (DATA_DIR empty = the project folder)
root_directory = str(Path(os.environ.get("DATA_DIR") or PROJECT_DIR) / "sorting_backup")

# Performance tuning
BUFFER_SIZE = 1024
BATCH_SIZE = 500

async def hash_line(line):
    return hashlib.sha256(line.encode()).hexdigest()

async def create_database_and_collections(category, db):
    db_collection = db[category]
    db_collection.create_index(
        [("filename", 1), ("category", 1), ("line_hash", 1)], unique=True
    )
    discovered_fields_collection = db[f"discovered_fields_{category}"]
    files_collection = db[f"files_{category}"]
    return db_collection, discovered_fields_collection, files_collection

def create_shadowserver_database():
    mongo_client = MongoClient(
        mongo_host,
        mongo_port,
        username=mongo_username,
        password=mongo_password,
        authSource=mongo_auth_source
    )
    return mongo_client[mongo_db_name]

async def count_total_files(category_path):
    return sum(len(files) for _, _, files in os.walk(category_path))

@alru_cache(maxsize=1024)
async def get_file_hash(filename):
    async with aiofiles.open(filename, 'rb') as f:
        contents = await f.read()
        return hashlib.sha256(contents).hexdigest()

def update_discovered_fields(collection, category, field_name):
    return collection.update_one(
        {"category": category, "field_name": field_name},
        {"$setOnInsert": {"category": category, "field_name": field_name}},
        upsert=True
    )

async def flush_bulk(db_collection, bulk_operations):
    """Flush bulk operations with a retry in smaller chunks if needed."""
    if not bulk_operations:
        return
    try:
        db_collection.bulk_write(bulk_operations, ordered=False)
    except Exception as e:
        print(f"Bulk write failed with {len(bulk_operations)} ops, retrying in smaller chunks: {e}")
        chunk_size = max(100, len(bulk_operations) // 4)
        for i in range(0, len(bulk_operations), chunk_size):
            try:
                db_collection.bulk_write(bulk_operations[i:i + chunk_size], ordered=False)
            except Exception as sub_e:
                print(f"Sub-batch failed ({i}–{i+chunk_size}): {sub_e}")

async def upload_files_to_database(directory, category, db_collection, discovered_fields_collection, files_collection, total_files):
    bulk_operations = []
    file_counter = 0
    file_batch_counter = 0
    total_batch_counter = 0

    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)

            files_collection.insert_one({
                "filename": filename,
                "category": category,
                "path": file_path
            })

            existing_file = db_collection.find_one({
                "filename": filename,
                "category": category
            })
            if existing_file:
                continue

            file_docs = []

            if filename.endswith('.csv'):
                async with aiofiles.open(file_path, 'r', buffering=BUFFER_SIZE) as csvfile:
                    file_contents = await csvfile.read()
                file_contents_lines = file_contents.splitlines()
                reader = csv.DictReader(file_contents_lines)
                if reader.fieldnames is None:
                    continue
                headers = reader.fieldnames
                lines_to_hash = set()

                for row in reader:
                    line = ','.join([str(row.get(field, "")) for field in headers])
                    line_hash = await hash_line(line)
                    if line_hash in lines_to_hash:
                        continue
                    row["filename"] = filename
                    row["category"] = category
                    row["line_hash"] = line_hash

                    if "extracted_date" not in row:
                        timestamp_str = row.get("timestamp")
                        if timestamp_str:
                            try:
                                date_entry = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                row.setdefault("logged_date", date_entry.strftime("%Y-%m-%d %H:%M:%S"))
                                row["extracted_date"] = date_entry
                            except ValueError:
                                continue

                    file_docs.append(InsertOne(row))
                    lines_to_hash.add(line_hash)
                del lines_to_hash

                for field_name in headers:
                    await loop.run_in_executor(None, update_discovered_fields, discovered_fields_collection, category, field_name)

            elif filename.endswith('.json'):
                async with aiofiles.open(file_path, 'r', buffering=BUFFER_SIZE) as jsonfile:
                    try:
                        json_data = await jsonfile.read()
                        json_object = json.loads(json_data)
                        line_hash = await hash_line(json_data)

                        doc = {
                            "filename": filename,
                            "category": category,
                            "line_hash": line_hash,
                            **json_object
                        }

                        if "extracted_date" not in doc:
                            timestamp_str = json_object.get("timestamp")
                            if timestamp_str:
                                try:
                                    date_entry = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                    doc.setdefault("logged_date", date_entry.strftime("%Y-%m-%d %H:%M:%S"))
                                    doc["extracted_date"] = date_entry
                                except ValueError:
                                    pass

                        file_docs.append(InsertOne(doc))
                    except Exception as e:
                        print(f"Error processing JSON file {filename}: {e}")
                        continue

            bulk_operations.extend(file_docs)

            file_counter += 1
            file_batch_counter += 1

            calculated_batches = math.ceil(file_counter / BATCH_SIZE)

            if file_batch_counter >= BATCH_SIZE:
                await flush_bulk(db_collection, bulk_operations)
                bulk_operations.clear()
                total_batch_counter += 1
                #print(f"\nFlushed batch #{total_batch_counter} ({file_batch_counter} files). Total batches so far (calc): {calculated_batches}")
                file_batch_counter = 0

            print(f"Category: {category}, Files processed: {file_counter}/{total_files} | Batches (calc): {calculated_batches}", end="\r")

    if bulk_operations:
        await flush_bulk(db_collection, bulk_operations)
        total_batch_counter += 1
        calculated_batches = math.ceil(file_counter / BATCH_SIZE)
        print(f"\nFlushed final batch #{total_batch_counter} ({file_batch_counter} files). Total batches (calc): {calculated_batches}")

    return file_counter


async def main():
    total_file_counter = 0
    completed_categories = []
    total_categories = len(os.listdir(root_directory))
    processed_categories = 0

    for category in os.listdir(root_directory):
        category_path = os.path.join(root_directory, category)
        if os.path.isdir(category_path):
            db_client = MongoClient(
                mongo_host,
                mongo_port,
                username=mongo_username,
                password=mongo_password,
                authSource=mongo_auth_source
            )
            db = db_client[mongo_db_name]

            db_collection, discovered_fields_collection, files_collection = await create_database_and_collections(category, db)
            total_files = await count_total_files(category_path)

            file_counter = await upload_files_to_database(
                category_path, category, db_collection, discovered_fields_collection, files_collection, total_files
            )

            total_file_counter += file_counter
            completed_categories.append(category)
            processed_categories += 1

            print(f"\nCategory {category} done: {file_counter}/{total_files} files.")
            print(f"Categories processed: {processed_categories}/{total_categories}")

            db_client.close()
            del db, db_collection, discovered_fields_collection, files_collection
            gc.collect()  # force memory cleanup

    print(f"\nTotal files processed: {total_file_counter}")
    print("Completed Categories:", completed_categories)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
