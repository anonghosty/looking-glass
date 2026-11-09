import os
import re
import ssl
import imaplib
import email
import zipfile
import datetime
import requests
import shutil
from email.header import decode_header
from urllib.parse import urlparse
from tqdm import tqdm
from zipfile import BadZipFile

import shadowserver_pipeline as pipeline
from mail_sources import imap_quote
from shadowserver_pipeline import PROJECT_DIR, load_env_file

# === Config ===
# Everything comes from the project's .env (the same file the pipeline uses; see .env.example). Nothing secret is
# written in this file. Environment variables that are already set win over .env.
load_env_file(PROJECT_DIR / ".env")
roundcube_server = os.environ.get("IMAP_SERVER", "")
email_address = os.environ.get("IMAP_USER", "")
password = os.environ.get("IMAP_PASSWORD", "")
imap_folder = os.environ.get("IMAP_FOLDER", "inbox")
verify_tls = os.environ.get("IMAP_VERIFY_TLS", "false").strip().lower() in ("1", "true", "yes", "on")
if not (roundcube_server and email_address and password):
    raise SystemExit("IMAP_SERVER / IMAP_USER / IMAP_PASSWORD missing in .env (copy .env.example to .env)")

data_dir = os.environ.get("DATA_DIR") or str(PROJECT_DIR)
attachments_dir = os.path.join(data_dir, "attachments_backup")
unzipped_dir = os.path.join(data_dir, "unzipped_backup")
sorting_dir = os.path.join(data_dir, "sorting_backup")

# === Helpers ===
def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def get_filename_from_headers_or_url(url, headers):
    cd = headers.get("Content-Disposition", "")
    match = re.findall(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd)
    if match:
        return match[0]
    parsed_path = os.path.basename(urlparse(url).path)
    return parsed_path if parsed_path else f"download_{hash(url)}.bin"

def download_file(url, download_dir):
    ensure_dir(download_dir)
    resp = requests.get(url, stream=True)
    if resp.status_code == 200:
        filename = get_filename_from_headers_or_url(url, resp.headers)
        file_path = os.path.join(download_dir, filename)
        if os.path.exists(file_path):
            print(f"[SKIP] Already exists (link): {filename}")
            return False
        print(f"[LINK] Downloading: {filename}")
        with open(file_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    print(f"[FAIL] Could not download link: {url}")
    return None

# === IMAP Connect ===
context = ssl.create_default_context()
if not verify_tls:  # IMAP_VERIFY_TLS=false: the mail server's certificate is not checked (as before)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

imap = imaplib.IMAP4_SSL(roundcube_server, ssl_context=context)

attachment_counter = 0
skipped_counter = 0
link_download_counter = 0
link_skipped_counter = 0

try:
    imap.login(email_address, password)
    imap.select(imap_quote(imap_folder))   # quoted: folder names with spaces work

    ensure_dir(attachments_dir)
    ensure_dir(unzipped_dir)
    ensure_dir(sorting_dir)

    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=1)
    today_str = today.strftime("%d-%b-%Y")
    yesterday_str = yesterday.strftime("%d-%b-%Y")

    search_criteria = f'OR (SINCE "{yesterday_str}") (SINCE "{today_str}")'
    status, email_ids = imap.search(None, search_criteria)


    for email_id in email_ids[0].split():
        status, email_data = imap.fetch(email_id, "(RFC822)")

        if status != "OK":
            print(f"[ERROR] Failed to fetch email ID {email_id}")
            continue

        msg = None

        # Extract raw email bytes safely
        for response_part in email_data:
            if isinstance(response_part, tuple):
                try:
                    msg = email.message_from_bytes(response_part[1])
                except Exception as e:
                    print(f"[ERROR] Failed to parse email ID {email_id}: {e}")
                break

        if msg is None:
            print(f"[SKIP] No valid email content for ID {email_id}")
            continue

        email_body = ""
        local_attachment_count = 0

        for part in msg.walk():
            # Skip multipart containers
            if part.get_content_maintype() == "multipart":
                continue

            # Handle plain text and HTML parts
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    email_body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception as e:
                    print(f"[ERROR] Failed to decode email body part: {e}")
                    continue

            # Handle attachments
            if part.get("Content-Disposition"):
                filename = part.get_filename()
                if filename:
                    try:
                        decoded_header = decode_header(filename)
                        filename = decoded_header[0][0]
                        if isinstance(filename, bytes):
                            filename = filename.decode(errors="ignore")
                    except Exception as e:
                        print(f"[WARNING] Failed to decode filename: {e}")
                        continue

                    attachment_path = os.path.join(attachments_dir, filename)

                    if not os.path.exists(attachment_path):
                        print(f"[ATTACHMENT] Downloading: {filename}")
                        try:
                            with open(attachment_path, "wb") as attachment:
                                payload = part.get_payload(decode=True)
                                attachment.write(payload)
                            attachment_counter += 1
                            local_attachment_count += 1
                        except Exception as e:
                            print(f"[ERROR] Failed to save attachment '{filename}': {e}")
                    else:
                        print(f"[SKIP] Already exists (attachment): {filename}")
                        skipped_counter += 1





        # === Fallback: Download from Shadowserver links if no attachment ===
        if local_attachment_count == 0 and email_body:
            shadowserver_links = list(set(re.findall(r'https://dl\.shadowserver\.org/[^\s"<]+', email_body)))
            for link in shadowserver_links:
                result = download_file(link, attachments_dir)
                if result is True:
                    link_download_counter += 1
                elif result is False:
                    link_skipped_counter += 1

except KeyboardInterrupt:
    print("\nProcess interrupted. Closing connection...")
finally:
    imap.logout()
    print(f"\nDownloaded {attachment_counter} attachments, Skipped {skipped_counter}")
    print(f"Downloaded {link_download_counter} links, Skipped {link_skipped_counter}")

# === Step 2: Unzip valid zip files ===
unzipped_counter = 0
skipped_unzipped_counter = 0
deleted_bad_zip_counter = 0

for root, dirs, files in os.walk(attachments_dir):
    for file in sorted(files):
        if not file.lower().endswith(".zip"):
            continue  # Only process zip files

        zip_file_path = os.path.join(root, file)
        unzip_dir = os.path.join(unzipped_dir, file)

        if not os.path.exists(unzip_dir):
            os.makedirs(unzip_dir)
            print(f"[UNZIP] Extracting: {zip_file_path} → {unzip_dir}")
            try:
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    zip_ref.extractall(unzip_dir)
                unzipped_counter += 1
            except BadZipFile:
                print(f"[DELETE] Corrupt or mislabeled zip: {zip_file_path}")
                os.remove(zip_file_path)
                deleted_bad_zip_counter += 1
        else:
            print(f"[SKIP] Already unzipped: {zip_file_path}")
            skipped_unzipped_counter += 1

print(f"\n✅ Unzipped {unzipped_counter} valid zips")
print(f"⏩ Skipped {skipped_unzipped_counter} already extracted")
print(f"❌ Deleted {deleted_bad_zip_counter} bad zips")


# === Step 3: Sort & Move CSVs by Service Name ===
search_dirs = [unzipped_dir, attachments_dir]  # Search in both
move_counter = 0

# Report file names (numbered/unnumbered and _as#### variants, any country): the pipeline's pattern
pattern = pipeline.SERVICE_RE

for search_dir in search_dirs:
    for root, _, files in os.walk(search_dir):
        for filename in sorted(files):
            if re.match(pattern, filename):
                service_name = re.search(pattern, filename).group(1)

                service_dir = os.path.join(sorting_dir, service_name)
                if not os.path.exists(service_dir):
                    os.makedirs(service_dir)

                src_path = os.path.join(root, filename)
                dest_path = os.path.join(service_dir, filename)

                if os.path.exists(dest_path):
                    print(f"[OVERWRITE] {filename} → {service_name}")
                    os.remove(dest_path)
                else:
                    print(f"[MOVE] {filename} → {service_name}")

                shutil.move(src_path, dest_path)
                move_counter += 1

print(f"\n✅ Step 3 completed: {move_counter} file(s) sorted into {sorting_dir}")

# === Step 4: Summary of Service Folders ===
print("\n📂 Service folders populated:")
for service_name in sorted(os.listdir(sorting_dir)):
    service_path = os.path.join(sorting_dir, service_name)
    if os.path.isdir(service_path):
        file_count = len([f for f in os.listdir(service_path) if f.endswith(".csv")])
        if file_count > 0:
            print(f"  - {service_name}: {file_count} file(s)")
