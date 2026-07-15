# SQLi Automation Toolkit

A collection of Python scripts for automating detection and exploitation of three classic SQL Injection techniques: **Boolean-Based Blind**, **Union-Based**, and **Time-Based Blind**.

مجموعه‌ای از اسکریپت‌های پایتون برای خودکارسازی تشخیص و بهره‌برداری از سه تکنیک کلاسیک تزریق SQL: **Boolean-Based Blind**، **Union-Based** و **Time-Based Blind**.

> ⚠️ **Disclaimer / سلب مسئولیت**
> This project is for educational purposes and authorized security testing only. Do not use it against systems you don't have explicit permission to test.
> این پروژه صرفاً برای اهداف آموزشی و تست امنیتی مجاز است. از آن علیه سیستم‌هایی که اجازه‌ی تست ندارید استفاده نکنید.

---

## 📁 Project Structure / ساختار پروژه

```
sqli-automation/
├── Boolean-Based Blind SQLi/
│   ├── payloads/
│   └── main.py
├── Union-Based SQLi/
│   ├── payloads/
│   └── sqli.py
└── time based blind sqli/
    ├── payloads/
    └── main.py
```

---

## 1️⃣ Time-Based Blind SQLi

### English

**How it works:**

This script has two phases: **discovery** and **exploitation**.

1. **Payload loading (`load_order_by_payloads`)** — Reads a `payloads/blind.txt` file where each line is prefixed with `single_quote:`, `double_quote:`, or `no_quote:`. This groups payloads by which quote-breaking context they assume the injection point sits in (e.g. `' `, `" `, or no quote at all).

2. **Discovery (`discovery_vulnerability`)** — For each quote-type group, the script sends each payload appended to the target URL through a SOCKS5 proxy, and records the response time (`r.elapsed.total_seconds()`) using `requests`. It retries up to 3 times on connection errors. A parameter is flagged **vulnerable** if the first payload responds quickly (under 1s) while a later payload (which triggers `SLEEP(3)`) takes over 2.5s — meaning the injected `SLEEP()` actually executed on the database.

3. **Exploitation (`exploit`)** — For every vulnerable quote-type, it performs blind character-by-character extraction using conditional time delays (`IF(condition, SLEEP(3), 0)`):
   - **Database name length**: brute-forces `LENGTH(DATABASE())` from 1–50 by checking which length value causes a 3-second delay.
   - **Database name**: for each character position, it tries every letter/digit/punctuation character (`string.ascii_letters + punctuation + digits`) with `SUBSTRING(DATABASE(), i, 1) = 'char'`, until the delay confirms a match.
   - **Table names**: queries `information_schema.tables` and extracts `GROUP_CONCAT(table_name)` character-by-character using `ASCII(SUBSTRING(...))` comparisons (more reliable than string comparison for special characters).
   - **User interaction**: after tables are found, the user is prompted to pick one table name from the list.
   - **Column names**: same ASCII-based character extraction against `information_schema.columns` for the chosen table.
   - **User interaction**: user picks a column name from the discovered list.
   - **Data dump**: finally extracts the actual value from `SELECT {column} FROM {table} LIMIT 0,1`, again one ASCII character at a time, and prints the final flag/data.

**Key techniques:** blind time-based inference, retry logic on network failures, SOCKS5 proxy routing, quote-context-aware payload building, character-set brute force with early-exit on match.

### فارسی

**نحوه‌ی کارکرد:**

این اسکریپت دو فاز داره: **کشف (Discovery)** و **بهره‌برداری (Exploitation)**.

1. **بارگذاری پیلودها (`load_order_by_payloads`)** — فایل `payloads/blind.txt` رو می‌خونه که هر خطش با `single_quote:`، `double_quote:` یا `no_quote:` شروع شده. این باعث میشه پیلودها بر اساس نوع کوتیشن (بستن با `'`، `"` یا بدون هیچ کوتیشنی) گروه‌بندی بشن.

2. **مرحله‌ی کشف (`discovery_vulnerability`)** — برای هر گروه، پیلودها رو یکی‌یکی به انتهای URL اضافه می‌کنه و از طریق پروکسی SOCKS5 ارسال می‌کنه و زمان پاسخ رو ثبت می‌کنه. اگر خطای اتصال رخ بده تا ۳ بار تلاش مجدد می‌کنه. یک پارامتر **آسیب‌پذیر** تشخیص داده میشه اگر پاسخ اول سریع باشه (زیر ۱ ثانیه) ولی پاسخ بعدی (که `SLEEP(3)` رو فعال می‌کنه) بیش از ۲.۵ ثانیه طول بکشه — یعنی دستور `SLEEP()` واقعاً روی دیتابیس اجرا شده.

3. **مرحله‌ی بهره‌برداری (`exploit`)** — برای هر نوع کوتیشن آسیب‌پذیر، استخراج کاراکتر به کاراکتر با استفاده از تاخیر شرطی (`IF(condition, SLEEP(3), 0)`) انجام میده:
   - **طول نام دیتابیس**: از ۱ تا ۵۰ حدس می‌زنه تا مقداری که باعث تاخیر ۳ ثانیه‌ای بشه پیدا بشه.
   - **نام دیتابیس**: برای هر پوزیشن، تک‌تک کاراکترها (حروف، اعداد، نمادها) رو با `SUBSTRING(DATABASE(), i, 1) = 'char'` تست می‌کنه تا کاراکتر درست پیدا بشه.
   - **نام جدول‌ها**: از `information_schema.tables` استفاده می‌کنه و `GROUP_CONCAT(table_name)` رو با مقایسه‌ی کد ASCII کاراکتر به کاراکتر استخراج می‌کنه.
   - **تعامل با کاربر**: بعد از پیدا شدن جدول‌ها، از کاربر خواسته میشه یکی رو انتخاب کنه.
   - **نام ستون‌ها**: همون روش ASCII برای `information_schema.columns` روی جدول انتخاب‌شده اجرا میشه.
   - **تعامل با کاربر**: کاربر یک ستون از لیست انتخاب می‌کنه.
   - **استخراج داده**: در نهایت مقدار واقعی از `SELECT {column} FROM {table} LIMIT 0,1` کاراکتر به کاراکتر استخراج و چاپ میشه (فلگ/داده نهایی).

**تکنیک‌های کلیدی:** استنتاج بلایند مبتنی بر زمان، مکانیزم تلاش مجدد در برابر خطای شبکه، مسیریابی از طریق پروکسی SOCKS5، ساخت پیلود متناسب با نوع کوتیشن، بروت‌فورس مجموعه کاراکترها با توقف زودهنگام هنگام یافتن مقدار درست.

---

## 2️⃣ Union-Based SQLi

### English

**How it works:**

This script is a **fingerprint-based discovery tool** — it does not extract data yet, it only determines whether a Union-Based (or generally structural) SQL injection point exists and how the server reacts.

1. **Startup / banner** — Prints an ASCII banner and asks the user to choose an SQLi type (`T`/`B`/`U`), though only the `U` (Union) path is currently implemented in `discovery_vulnerability`.

2. **`fingerprint(res)`** — Classifies an HTTP response into one of three states based on its body text:
   - `SQL_ERROR` — if the response contains strings like "sql syntax", "unknown column", or "order clause" (typical DB error leakage).
   - `BLOCKED` — if it contains "blocked", "forbidden", "waf", or "access denied" (a WAF/firewall likely intercepted it).
   - `OK` — otherwise (normal-looking response).

3. **`classify_pattern(e0, e1, e2)`** — Takes the fingerprints of 3 payload responses and decides what pattern they form:
   - If the three responses differ, and at least one is `SQL_ERROR` while another is `OK`, that's flagged `POSSIBLE_VULNERABLE` (the injection changed backend behavior — a strong signal).
   - If they differ but don't fit that exact pattern, it's `UNCERTAIN`.
   - If all three are identical: `NO_SIGNAL` (all normal → likely not exploitable this way), `BLOCKED_OR_NOISE` (all errored — possibly unrelated noise), or `WAF_DETECTED` (all blocked — a firewall is filtering everything).

4. **`load_order_by_payloads`** — Same payload-loading logic as the Time-Based script, reading `payloads/union.txt` and grouping payloads by quote type (single/double/no quote). These are typically `ORDER BY` / `UNION SELECT` column-count probing payloads.

5. **`discovery_vulnerability`** — For the Union (`u`) method, it takes the first 3 payloads of each quote-type group, sends all 3 to the target URL, fingerprints each response, and classifies the 3-response pattern using the function above. Results are printed with color-coded status (red = possibly vulnerable, yellow = uncertain, green = no signal, cyan = blocked/noise, magenta = WAF detected).

**Key techniques:** response fingerprinting via keyword matching, differential analysis across multiple payloads, WAF/error detection heuristics — this is a reconnaissance step that would typically precede full Union-Based column/data extraction (which isn't implemented here yet).

### فارسی

**نحوه‌ی کارکرد:**

این اسکریپت یک ابزار **کشف مبتنی بر فینگرپرینت** هست — هنوز داده استخراج نمی‌کنه، فقط تشخیص میده که آیا نقطه‌ی تزریق Union-Based (یا به‌طور کلی‌تر، ساختاری) وجود داره و سرور چطور واکنش نشون میده.

1. **شروع برنامه / بنر** — یک بنر ASCII چاپ می‌کنه و از کاربر می‌خواد نوع SQLi رو انتخاب کنه (`T`/`B`/`U`)، هرچند فعلاً فقط مسیر `U` (یونیون) در `discovery_vulnerability` پیاده‌سازی شده.

2. **`fingerprint(res)`** — پاسخ HTTP رو بر اساس متن بدنه به یکی از سه حالت دسته‌بندی می‌کنه:
   - `SQL_ERROR` — اگر پاسخ شامل عباراتی مثل "sql syntax"، "unknown column" یا "order clause" باشه (نشتی معمول خطای دیتابیس).
   - `BLOCKED` — اگر شامل "blocked"، "forbidden"، "waf" یا "access denied" باشه (احتمالاً یک WAF/فایروال جلوش رو گرفته).
   - `OK` — در غیر این صورت (پاسخ عادی).

3. **`classify_pattern(e0, e1, e2)`** — فینگرپرینت ۳ پاسخ از ۳ پیلود رو می‌گیره و الگوی اونا رو تعیین می‌کنه:
   - اگر هر سه پاسخ متفاوت باشن، و حداقل یکی `SQL_ERROR` و یکی دیگه `OK` باشه، وضعیت `POSSIBLE_VULNERABLE` تشخیص داده میشه (یعنی تزریق رفتار بک‌اند رو تغییر داده — سیگنال قوی).
   - اگر متفاوت باشن ولی دقیقاً همین الگو رو نداشته باشن، `UNCERTAIN` میشه.
   - اگه هر سه یکسان باشن: `NO_SIGNAL` (همه عادی → احتمالاً از این روش قابل بهره‌برداری نیست)، `BLOCKED_OR_NOISE` (همه خطا دادن — احتمالاً نویز بی‌ربط)، یا `WAF_DETECTED` (همه بلاک شدن — یک فایروال همه‌چیز رو فیلتر می‌کنه).

4. **`load_order_by_payloads`** — دقیقاً همون منطق بارگذاری پیلود اسکریپت Time-Based، که فایل `payloads/union.txt` رو می‌خونه و پیلودها رو بر اساس نوع کوتیشن (تک/دابل/بدون کوتیشن) گروه‌بندی می‌کنه. این پیلودها معمولاً برای شناسایی تعداد ستون‌ها (`ORDER BY` / `UNION SELECT`) استفاده میشن.

5. **`discovery_vulnerability`** — برای متد Union (`u`)، سه پیلود اول هر گروه کوتیشن رو برمی‌داره، هر سه رو به URL هدف می‌فرسته، فینگرپرینت هر پاسخ رو می‌گیره و الگوی سه‌تایی رو با تابع بالا دسته‌بندی می‌کنه. نتایج با کد رنگی چاپ میشن (قرمز = احتمالاً آسیب‌پذیر، زرد = نامشخص، سبز = بدون سیگنال، فیروزه‌ای = بلاک/نویز، بنفش = WAF شناسایی شد).

**تکنیک‌های کلیدی:** فینگرپرینت‌گیری از پاسخ با تطبیق کلمات کلیدی، تحلیل تفاضلی روی چند پیلود، هیوریستیک تشخیص WAF/خطا — این یک مرحله‌ی شناسایی (Recon) هست که معمولاً قبل از استخراج کامل ستون‌ها/داده در روش Union-Based انجام میشه (که هنوز در این اسکریپت پیاده‌سازی نشده).

---

## 3️⃣ Boolean-Based Blind SQLi 

### English

**How it typically works:**

Boolean-Based Blind SQLi doesn't rely on visible error messages or timing — it relies on the application returning a **different page** (different content, length, or status) depending on whether an injected condition evaluates to `TRUE` or `FALSE`.

Given this repo's shared payload structure, the expected flow is:

1. **Payload loading** — same `single_quote` / `double_quote` / `no_quote` grouping from a `payloads/` file, so the tool can adapt the injected condition to the actual injection context.
2. **Discovery** — send a pair of payloads per quote-type, e.g. `AND 1=1` (always true) and `AND 1=2` (always false). If the responses differ (in length, specific keywords, or HTTP status), the parameter is flagged vulnerable — the app is "leaking" a true/false signal through its content.
3. **Exploitation** — once a working TRUE/FALSE oracle is found, the same character-by-character extraction pattern as Time-Based is used, but the "oracle" is a content/length comparison instead of a sleep delay:
   `AND ASCII(SUBSTRING((SELECT ...), i, 1)) = X` → if the "true" page is returned, the guessed character/ASCII value is correct.
   This is repeated to recover database name, table names, column names, and finally data — identical logical structure to the Time-Based script, just with a different oracle (content diff vs. delay).

**Key techniques:** true/false differential page comparison, no timing dependency (faster and more WAF-resistant than time-based in some cases), same brute-force character extraction pipeline.

### فارسی

**نحوه‌ی کارکرد معمول:**

Boolean-Based Blind SQLi به پیام خطای قابل مشاهده یا تاخیر زمانی وابسته نیست — بلکه به این تکیه داره که اپلیکیشن بسته به `TRUE` یا `FALSE` بودن یک شرط تزریق‌شده، **صفحه‌ی متفاوتی** (محتوا، طول یا کد وضعیت متفاوت) برمی‌گردونه.

با توجه به ساختار مشترک پیلودهای این مخزن، جریان مورد انتظار اینه:

1. **بارگذاری پیلود** — همون گروه‌بندی `single_quote` / `double_quote` / `no_quote` از فایل `payloads/`، تا ابزار بتونه شرط تزریق‌شده رو با کانتکست واقعی نقطه‌ی تزریق تطبیق بده.
2. **مرحله‌ی کشف** — یک جفت پیلود برای هر نوع کوتیشن ارسال میشه، مثلاً `AND 1=1` (همیشه درست) و `AND 1=2` (همیشه غلط). اگر پاسخ‌ها فرق کنن (در طول، کلمات کلیدی خاص یا کد وضعیت HTTP)، پارامتر آسیب‌پذیر تشخیص داده میشه — یعنی اپلیکیشن یک سیگنال درست/غلط از طریق محتوای خودش لو میده.
3. **مرحله‌ی بهره‌برداری** — به محض پیدا شدن یک اوراکل TRUE/FALSE کارآمد، همون الگوی استخراج کاراکتر به کاراکتر شبیه Time-Based استفاده میشه، با این تفاوت که «اوراکل» به‌جای تاخیر زمانی، مقایسه‌ی محتوا/طول صفحه است:
   `AND ASCII(SUBSTRING((SELECT ...), i, 1)) = X` → اگر صفحه‌ی «درست» برگردونده بشه، یعنی کاراکتر/مقدار ASCII حدس‌زده‌شده صحیحه.
   این روند برای بازیابی نام دیتابیس، نام جدول‌ها، نام ستون‌ها و در نهایت داده تکرار میشه — دقیقاً همون ساختار منطقی اسکریپت Time-Based، فقط با اوراکل متفاوت (تفاوت محتوا به‌جای تاخیر).

**تکنیک‌های کلیدی:** مقایسه‌ی تفاضلی صفحه بر اساس درست/غلط، بدون وابستگی به زمان‌سنجی (در برخی موارد سریع‌تر و مقاوم‌تر در برابر WAF نسبت به روش زمانی)، همون پایپ‌لاین بروت‌فورس کاراکتر به کاراکتر.

---

## 🛠️ Requirements / پیش‌نیازها

```
requests
urllib3
colorama
```

Install with / نصب با:
```bash
pip install requests urllib3 colorama
```

> Note: the Time-Based and Union-Based scripts route traffic through a local SOCKS5 proxy (`127.0.0.1:12334`, e.g. Tor). Make sure this proxy is running, or edit the `proxies` dict in the code to match your setup / point to `None` to disable it.
> توجه: اسکریپت‌های Time-Based و Union-Based ترافیک رو از طریق یک پروکسی SOCKS5 محلی (`127.0.0.1:12334`، مثلاً Tor) عبور می‌دن. مطمئن شو این پروکسی در حال اجراست، یا دیکشنری `proxies` رو در کد متناسب با تنظیمات خودت ویرایش کن / برای غیرفعال کردنش مقدار `None` بذار.

## ▶️ Usage / نحوه‌ی اجرا

```bash
python main.py
# Enter URL: http://target.com/page.php?id=
```

---

*README generated for the `sqli-automation` repository.*
