# Upload file

```bash
curl -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "file=@${FILE}" \
  -F "workoutSport=1" \
  -F "workoutTitle=workout title" \
  -F "workoutDesc=workout description" \
  -F "workoutNotes=additional notes" \
  https://fittrackee-upload.mydomain.com/upload" # or locally using http://127.0.0.1:5001/upload
```

# Send .gpx or .tcx download url

```bash
curl -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://domain.com/fake.tcx",
    "workoutSport": "1",
    "workoutTitle": "workout title",
    "workoutDesc": "workout description",
    "workoutNotes": "additional notes"
  }' \
  https://fittrackee-upload.mydomain.com/upload_from_url
```

.venv contents
```
UPLOAD_DIR="/home/username/upload_dir"
LOG_DIR="/home/username/log_dir"
SECRET_TOKEN=USE_THE_SAME_IN_APP
PUSHOVER_TOKEN=
PUSHOVER_USER=
FITTRACKEE_URL="https://fittrackee.yourdomain.com"
FITTRACKEE_EMAIL=""
FITTRACKEE_PASSWORD=""
```
