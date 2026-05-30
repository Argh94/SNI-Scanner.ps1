# SNI-Scanner.ps1

![PowerShell](https://img.shields.io/badge/PowerShell-7.4+-blue?style=for-the-badge&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**ابزار اسکنر SNI و Port Checker قدرتمند برای ویندوز** با قابلیت تشخیص IP واقعی پشت Cloudflare و نمایش وضعیت پورت‌ها.

---

## ✨ قابلیت‌ها

- **اسکن همزمان چندین دامنه و IP**
- نمایش IPهای رزولوشده در کنار دامنه
- بررسی چندین پورت مهم (به صورت پیش‌فرض ۶ پورت)
- علامت‌گذاری هوشمند: `✔` (باز) و `✖` (بسته)
- تشخیص **IP واقعی** سرور (IP✔ / IP✖) از طریق `cdn-cgi/trace`
- پشتیبانی از ورودی مستقیم IP و دامنه
- فیلتر خودکار IPهای خصوصی (Private IP)
- خروجی کامل **Log** و **CSV** برای تحلیل
- لاگ‌گیری با timestamp
- رابط کاربری رنگی و خوانا
- Parallel Processing با مدیریت بهینه

---

## 📋 پیش‌نیازها

- **Windows 10 / 11**
- **PowerShell 7.4 یا بالاتر** (الزامی)

### نصب یا ارتقا PowerShell 7+

PowerShell را **به عنوان Administrator** باز کنید و دستور زیر را اجرا کنید:

```powershell
winget install --id Microsoft.PowerShell -e --source winget
```


### پس از نصب، نسخه را بررسی کنید:

```powershell
$PSVersionTable.PSVersion
```

---

## 🚀 روش اجرای SNI Scanner

### روش ۱: نصب سریع (توصیه شده)

در PowerShell معمولی دستور زیر را اجرا کنید:

```powershell
cd $HOME\Desktop
irm "https://raw.githubusercontent.com/Argh94/SNI-Scanner.ps1/main/SNI-Scanner-Windows.ps1" -OutFile "SNI-Scanner.ps1"
pwsh -ExecutionPolicy Bypass -File .\SNI-Scanner.ps1 -IPCheck
```

### روش ۲: اجرای دستی

1. فایل `SNI-Scanner.ps1` را دانلود و در دسکتاپ قرار دهید.
2. دستور زیر را اجرا کنید:

```powershell
pwsh -ExecutionPolicy Bypass -File .\SNI-Scanner.ps1 -IPCheck
```

---

## 📝 نحوه استفاده

### اولین اجرا

در اجرای اول، اسکریپت فایل‌های زیر را روی دسکتاپ ایجاد می‌کند:

- `SNI-Scanner.ps1` → فایل اصلی اسکریپت
- `targets.txt` → فایل مقصد دامنه‌ها و آی‌پی‌ها
- `scan_log.txt` → گزارش کامل اسکن
- `scan_results.csv` → گزارش مرتب برای اکسل

### اضافه کردن تارگت (دامنه یا IP)

فایل `targets.txt` را با Notepad باز کنید و دامنه‌ها یا آی‌پی‌ها را هر کدام در یک خط بنویسید:

```txt
# مثال‌های مجاز
1.1.1.1
cloudflare.com
google.com
example.com
185.22.34.56
yourdomain.ir
sub.domain.com
```

> خطوطی که با `#` شروع شوند، کامنت محسوب شده و نادیده گرفته می‌شوند.

---

## ⚙️ پارامترهای قابل تنظیم

| پارامتر | توضیح | مقدار پیش‌فرض |
|----------|----------|----------|
| `-IPCheck` | فعال کردن تشخیص IP واقعی | غیرفعال |
| `-Ports` | لیست پورت‌ها | `443,2053,2083,2087,2096,8443` |
| `-Timeout` | زمان انتظار برای هر پورت (ثانیه) | `4` |
| `-Retries` | تعداد تلاش مجدد | `1` |
| `-ManualIP` | وارد کردن دستی IP عمومی | خودکار |

### مثال

```powershell
pwsh -File .\SNI-Scanner.ps1 -IPCheck -Timeout 3 -Retries 2
```

---

## 📊 نمونه خروجی

```text
[OK] cloudflare.com -> 104.16.133.229 -> 443✔ 2053✔ 2083✔ 2087✔ 2096✔ 8443✔ IP✔
[FAIL] example.com -> 93.184.216.34 -> 443✖ 2053✖ ...
[ERROR] invalid-domain.com (Could not resolve)
```

---

## ⚠️ نکات مهم

- VPN را هنگام اسکن خاموش کنید (ممکن است باعث مشکل در Resolve و اتصال شود).
- برای اسکن سریع‌تر: `Timeout=3` و `Retries=1` پیشنهاد می‌شود.
- برای اسکن دقیق‌تر: `Timeout=5` و `Retries=2` استفاده کنید.

---

## 📄 لایسنس

این پروژه تحت **MIT License** منتشر شده است.

### 👨‍💻 توسعه‌دهنده

**A.r.Gh-94**

### 📦 نسخه

**1.3.0 (بهینه و پایدار)**

---

⭐ اگر پروژه برایتان مفید بود، به آن ستاره بدهید.
