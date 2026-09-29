# 關鍵字主控台（keyword-console）

MaKarma 瑪卡鎷行銷的多客戶 SEO 關鍵字選題系統。部署在 Railway（專案 seo-keyword-console），網址：
- 主控台：https://keyword-console-production.up.railway.app/admin
- 客戶頁：https://keyword-console-production.up.railway.app/c/<客戶 token>（需 PIN 碼）

## 架構

- Bun + Hono，單一檔案伺服器；資料庫為 Railway Postgres（Bun.sql）。
- Railway Function 只跑 `boot.tsx`（啟動器）。實際程式碼存在資料庫 `app_code` 表，啟動時載入。
- 更新程式：執行 `python build.py` 產生 `index.tsx`，再 POST 到 `/__deploy`，header 帶 `x-deploy-token`（值在 Railway 變數 DEPLOY_TOKEN），立即生效、不需重啟。

```
python build.py
curl -X POST https://keyword-console-production.up.railway.app/__deploy \
  -H "x-deploy-token: <DEPLOY_TOKEN>" --data-binary @index.tsx
```

## 原始檔

| 檔案 | 內容 |
|---|---|
| src/server.part.ts | 後端：資料表、API、Notion 同步、Telegram 通知 |
| src/client.html | 客戶頁（關鍵字選題／關鍵字報告／產業訪談表），`/*CSS*/` 會被 common.css 取代後再接上頁內樣式 |
| src/admin.html | 主控台（客戶列表、關鍵字、期別與合約、報告內容、訪談表、設定） |
| src/common.css | 兩頁共用樣式 |
| src/build.py | 把 HTML/CSS 嵌入 server.part.ts，輸出 index.tsx |
| src/boot.tsx | Railway 上實際執行的啟動器 |

## 資料表

- clients：name、token（客戶連結）、pin_hash、contract_total（合約總篇數）、report（JSON）、interview（JSON）、notion_page_id
- periods：每一期，name、quota（本期上限）、status（open／submitted）
- categories：每家客戶自訂分類
- keywords：kw、vol（月搜尋量）、hi（頁首出價上限）、comp、intent（為什麼選）、content（建議文章）、path（可導向）、note、rec（優先推薦）、hidden
- selections：period_id × keyword_id

## 規則

- 本期可選數量 = min(合約總數 − 過往各期已選, 本期上限)；未設合約總數時用本期上限。
- 過往期別選過的字標示「已選過」，不能重複選。
- 客戶按兩下「送出確認」後鎖定並發 Telegram 通知；主控台可解鎖。
- Notion 同步：讀「專案資料庫」中名稱相符的專案，「關鍵字」欄位 = 已選字，「文章數量」= 合約總數（單向，Notion → 系統）。

## Railway 變數

ADMIN_PASSWORD、DATABASE_URL、DEPLOY_TOKEN、SEED_TOKEN、TELEGRAM_BOT_TOKEN、TELEGRAM_CHAT_ID、NOTION_TOKEN、NOTION_DB_ID。
這些值不在程式碼裡，請勿把它們貼進任何對話或檔案。

## 設計規範

- 所有給客戶看的文字用繁體中文，不使用 emoji（改用 ◆ ▸ 【】 等符號）。
- 客戶頁的選題畫面沿用「華邑食品 SEO 關鍵字候選題庫」的版型：深藍 hero 卡片、數據說明框、黏頂篩選列、雙欄題目卡片、右側已選清單。
