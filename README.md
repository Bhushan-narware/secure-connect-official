# Secure-Connect – Website + Admin Panel

Public website + secure admin panel (login, live enquiry notifications, site content editor).

## Chalane ka tareeka (local)
1. Node.js 18 ya naya install karein (https://nodejs.org).
2. Is folder me terminal kholein:
   ```
   npm install
   npm start
   ```
3. Website: http://localhost:3000   |   Admin: http://localhost:3000/admin
4. Pehli baar start par console me admin **username aur password** print hota hai
   (ya `ADMIN_USER` / `ADMIN_PASSWORD` environment variable se khud set karein, `.env.example` dekhein).
   Login ke baad **Password** tab se password badal lein.

## Admin panel me kya hai
- **Enquiries:** visitors ke forms yahan turant aate hain (live). Naya enquiry aate hi alert + beep.
  "Enable alerts" dabane par browser notification bhi aati hai (jab tab background me ho).
- **Site content:** phone, WhatsApp, email, address, banner, hero text, FAQ, frameworks, services aur
  har service ke form ke sawal, sab yahan se badlein. Save karte hi website update.
- **Password:** admin password badalna.

## Live karna (hosting)
- Kisi VPS / Render / Railway / DigitalOcean par ye folder upload karein, `npm install && npm start` chalayein.
- **HTTPS zaroor lagayein** (Caddy / nginx + Let's Encrypt, ya hosting ka built-in HTTPS), phir
  `COOKIE_SECURE=1` set karein. Proxy ke peeche ho to `TRUST_PROXY=1`.
- Admin ka rasta chhupane ke liye `ADMIN_PATH=/kuch-private-naam` set karein.
- `data/` folder me enquiries, site content aur admin login save hota hai. Iska **backup** rakhein
  aur hosting par is folder ko persistent disk par rakhein (`DATA_DIR`).

## Security notes
- Password scrypt se hash hota hai; login par rate-limit (15 min me 8 koshish).
- Cookie HttpOnly + SameSite=Strict. Enquiry form par bhi rate-limit aur size limit hai.
- Sirf ek admin user hai.

## Files
- `server.js` – backend (Express)  |  `public/index.html` – website  |  `public/admin.html` – admin panel
