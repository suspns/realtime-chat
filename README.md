# Realtime Chat — deployment bundle

This bundle includes your Flask/Socket.IO backend plus a basic browser UI so the root page has a template.

## Deploy on Render

1. Unzip this bundle and push the folder contents to a new GitHub repository.
2. In Render, choose **New + → Blueprint** and connect that repository. Render will read `render.yaml`.
3. Add a managed PostgreSQL database in Render, then set the web service's `DATABASE_URL` to its **internal** connection URL. Keep the generated `SECRET_KEY` and `JWT_SECRET_KEY` values.
4. Deploy. Open the service's public `onrender.com` URL.

## Notes

- This app uses Flask-SQLAlchemy and Socket.IO. The included Render start command uses Gunicorn's threaded worker.
- `FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `FIREBASE_PROJECT_ID`, and `FIREBASE_APP_ID` are optional and only needed if you configure Firebase phone/OTP login.
- The uploaded backend allows image uploads up to 5 MB. For production, configure persistent storage for uploads or move them to object storage; ephemeral host filesystems can lose uploaded images on redeploy.
- Review security, database backups, CORS, rate limiting, and upload handling before using this with real users.
- The basic UI supports username/password registration and login, direct text chat, and group chat. Phone OTP requires Firebase configuration.
