Thư mục dự án hiện tại \*\*đã có đủ 3 file\*\*:



\* `domain\_api\_server.js` (Node backend)

\* `index.html` (frontend)

\* `package.json` (mô tả dự án Node)





---



\## \*\*1. Đặt thư mục đúng cho subdomain\*\*



Trên VPS, tạo đường dẫn gắn với subdomain, ví dụ:



```bash

sudo mkdir -p /var/www/domainchecking.nguyencongluc.site

sudo chown -R $USER:$USER /var/www/domainchecking.nguyencongluc.site

```



Sau đó \*\*copy tất cả file dự án (`domain\_api\_server.js`, `index.html`, `package.json`)\*\* vào:



```bash

cd /var/www/domainchecking.nguyencongluc.site

```



---



\## \*\*2. Cài đặt dependencies\*\*



Nếu bạn có `package.json` sẵn, chỉ cần chạy:



```bash

npm install

```



Lệnh này sẽ cài tất cả thư viện cần thiết từ `package.json`.

(Nếu thiếu, có thể tự thêm bằng: `npm install express cors axios helmet`).



---



\## \*\*3. Chạy thử server\*\*



```bash

node domain\_api\_server.js

```



Kiểm tra trong terminal có log như:



```

✅ API running at http://127.0.0.1:3001

```



Nếu OK, dừng bằng \*\*Ctrl + C\*\*.



---



\## \*\*4. Chạy nền bằng PM2\*\*



```bash

sudo npm install -g pm2

pm2 start /var/www/domainchecking.nguyencongluc.site/domain\_api\_server.js --name domain-api

pm2 save

pm2 startup

```



---



\## \*\*5. Cấu hình Nginx\*\*



Tạo file cấu hình cho subdomain:



```bash

sudo nano /etc/nginx/sites-available/domainchecking.nguyencongluc.site

```



Dán nội dung:



```nginx

server {

&nbsp;   listen 80;

&nbsp;   listen \[::]:80;

&nbsp;   server\_name domainchecking.nguyencongluc.site;



&nbsp;   root /var/www/domainchecking.nguyencongluc.site;

&nbsp;   index index.html;



&nbsp;   location / {

&nbsp;       try\_files $uri $uri/ =404;

&nbsp;   }



&nbsp;   location /api/ {

&nbsp;       proxy\_pass http://localhost:3001/;

&nbsp;       proxy\_http\_version 1.1;

&nbsp;       proxy\_set\_header Host $host;

&nbsp;       proxy\_set\_header X-Forwarded-For $remote\_addr;

&nbsp;       proxy\_set\_header X-Forwarded-Proto $scheme;

&nbsp;       proxy\_set\_header Upgrade $http\_upgrade;

&nbsp;       proxy\_set\_header Connection "upgrade";

&nbsp;   }



&nbsp;   add\_header X-Content-Type-Options nosniff always;

}

```



Kích hoạt site:



```bash

sudo ln -s /etc/nginx/sites-available/domainchecking.nguyencongluc.site /etc/nginx/sites-enabled/

sudo nginx -t

sudo systemctl reload nginx

```



---



\## \*\*6. Thêm SSL miễn phí\*\*



```bash

sudo apt install -y certbot python3-certbot-nginx

sudo certbot --nginx -d domainchecking.nguyencongluc.site

```



---



\## \*\*7. Kiểm tra\*\*



\* Truy cập `https://domainchecking.nguyencongluc.site` → Hiển thị trang `index.html`.

\* Truy cập API thử:



&nbsp; ```bash

&nbsp; curl https://domainchecking.nguyencongluc.site/api/ip/google.com

&nbsp; curl https://domainchecking.nguyencongluc.site/api/ssl-summary/pavietnam.vn

&nbsp; ```



---



Bạn có muốn mình \*\*tạo script auto-setup\*\* để bạn chỉ cần copy-paste 1 lệnh chạy không?



