"""
보안/정보보안 뉴스 & 법령 카카오톡 자동 알림 프로그램 v3.5
─────────────────────────────────────────────────────────────────
[v3.5 주요 변경]
  1. 스케줄러 시간 변경: 매일 오전 08:40 및 오후 12:00 하루 2회
  2. 카카오 토큰 자동 갱신(Refresh) 도입
  3. 무한 대기 방어망(timeout=30) 포함
[버그 수정]
  - SEND_CHUNK_SIZE 5→2 (카카오 400자 제한 초과 원인 수정)
  - _make_template 제목 40자 truncate + 400자 안전망
  - _send_channel 성공 판정 수정 (result_code 없는 경우 대응)
  - _send_memo/_send_channel HTTP 상태코드 확인 + 실패 로그 추가
"""

import os
import sys
import json
import logging
import xml.etree.ElementTree as ET
import requests
import schedule
import time
import re
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# ══════════════════════════════════════════════════════════
# 로깅 및 환경변수
# ══════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("security_alert.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

NEWS_API_KEY              = os.environ.get("NEWS_API_KEY", "")
LAW_API_KEY               = os.environ.get("LAW_API_KEY", "")
SERPAPI_API_KEY           = os.environ.get("SERPAPI_API_KEY", "")
KAKAO_ACCESS_TOKEN        = os.environ.get("KAKAO_ACCESS_TOKEN", "")
KAKAO_REFRESH_TOKEN       = os.environ.get("KAKAO_REFRESH_TOKEN", "")
KAKAO_CHANNEL_PROFILE_KEY = os.environ.get("KAKAO_CHANNEL_PROFILE_KEY", "")
KAKAO_REST_API_KEY        = os.environ.get("KAKAO_REST_API_KEY", "")
NAVER_CLIENT_ID           = os.environ.get("NAVER_CLIENT_ID", "")
NAVER_CLIENT_SECRET       = os.environ.get("NAVER_CLIENT_SECRET", "")

def _check_env() -> None:
    keys = [
        "NEWS_API_KEY", "LAW_API_KEY", "SERPAPI_API_KEY",
        "KAKAO_ACCESS_TOKEN", "KAKAO_REFRESH_TOKEN",
        "KAKAO_REST_API_KEY", "KAKAO_CHANNEL_PROFILE_KEY",
        "NAVER_CLIENT_ID", "NAVER_CLIENT_SECRET",
    ]
    for k in keys:
        status = "✅ 설정됨" if os.environ.get(k) else "⚠️  미설정"
        logger.info(f"  {status}  {k}")

LAW_RECENCY_DAYS = 30
LAW_CACHE_FILE = "law_seen.json"
NEWS_MAX_PER_CATEGORY = 10
SEND_CHUNK_SIZE = 5

def _news_cutoff() -> datetime:
    """전일 자정부터 현재까지 (전일+당일 뉴스만)"""
    return (datetime.now() - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

# ══════════════════════════════════════════════════════════
# 🔑 카카오 토큰 자동 갱신
# ══════════════════════════════════════════════════════════
def refresh_kakao_token():
    global KAKAO_ACCESS_TOKEN
    if not KAKAO_REST_API_KEY or not KAKAO_REFRESH_TOKEN:
        logger.warning("REST_API_KEY 또는 REFRESH_TOKEN이 설정되지 않아 토큰 갱신을 건너뜁니다.")
        return KAKAO_ACCESS_TOKEN

    url = "https://kauth.kakao.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": KAKAO_REST_API_KEY,
        "refresh_token": KAKAO_REFRESH_TOKEN
    }
    try:
        resp = requests.post(url, data=payload, timeout=30)
        if resp.status_code == 200:
            new_token = resp.json().get("access_token")
            if new_token:
                KAKAO_ACCESS_TOKEN = new_token
                logger.info("✅ 카카오 토큰이 자동으로 성공적으로 갱신되었습니다.")
                return new_token
        logger.error(f"❌ 토큰 갱신 실패 [{resp.status_code}]: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"❌ 토큰 갱신 중 예외 발생: {e}")
    return KAKAO_ACCESS_TOKEN

# ══════════════════════════════════════════════════════════
# 키워드 정의
# ══════════════════════════════════════════════════════════
NEWS_PRIVACY_KEYWORDS = ["개인정보", "개인정보보호", "개인정보 유출", "개인정보유출", "개인정보 침해", "개인정보침해", "개인정보 처리", "개인정보처리방침", "정보주체", "가명정보", "익명정보", "민감정보", "고유식별정보", "개인정보보호위원회", "개인정보위", "PIPC", "GDPR", "CCPA", "개인정보 보호법", "개인정보보호법", "주민등록번호", "여권번호", "운전면허번호", "바이오정보", "생체정보", "위치정보", "CCTV", "영상정보", "의료정보", "금융정보", "정보 유출", "정보유출", "데이터 유출", "데이터유출", "해킹 유출", "고객정보 유출", "회원정보 유출", "Privacy", "Personal data", "Data protection", "PII", "Data breach", "Data leak"]
NEWS_INFOSEC_KEYWORDS = ["해킹", "해커", "사이버공격", "사이버 공격", "랜섬웨어", "악성코드", "바이러스", "트로이목마", "스파이웨어", "애드웨어", "루트킷", "피싱", "스피어피싱", "스미싱", "보이스피싱", "파밍", "DDoS", "디도스", "APT", "공급망공격", "공급망 공격", "제로데이", "제로 데이", "워터링홀", "드라이브바이", "SQL인젝션", "XSS", "CSRF", "취약점", "보안취약점", "보안 취약점", "CVE", "익스플로잇", "보안패치", "보안 패치", "업데이트 권고", "긴급패치", "침해사고", "침해 사고", "보안사고", "보안 사고", "사이버침해", "사이버 침해", "계정탈취", "계정 탈취", "자격증명 탈취", "정보보안", "사이버보안", "정보보호", "보안솔루션", "방화벽", "백신", "EDR", "XDR", "SIEM", "SOC", "위협인텔리전스", "제로트러스트", "망분리", "접근통제", "암호화", "정보통신기반보호", "국가사이버", "핵심기반시설", "ICS", "SCADA", "버그바운티", "침투테스트", "모의해킹", "취약점 분석", "보안인증", "CC인증", "ISMS", "ISMS-P", "Security", "Cybersecurity", "Hacking", "Malware", "Vulnerability", "Ransomware", "Phishing", "Exploit", "Zero-day", "Patch", "Breach", "Cyber attack"]
LAW_PRIVACY_KEYWORDS = ["개인정보", "프라이버시", "가명정보", "익명정보", "정보주체", "위치정보", "의료정보", "신용정보", "금융정보"]
LAW_INFOSEC_KEYWORDS = ["정보보호", "정보보안", "사이버", "사이버보안", "사이버침해", "취약점", "정보통신망", "전자서명", "공인인증", "공동인증", "클라우드", "인터넷", "정보통신기반보호", "디지털", "소프트웨어", "네트워크", "해킹", "암호"]
LAW_EXCLUDE_KEYWORDS = ["광산", "항만", "총포", "도검", "화약", "소방", "건축", "산업안전", "선박", "항공", "철도", "원자력", "도로교통"]

def _classify_news(title: str):
    title_lower = title.lower()
    if any(kw.lower() in title_lower for kw in NEWS_INFOSEC_KEYWORDS): return "infosec"
    if any(kw.lower() in title_lower for kw in NEWS_PRIVACY_KEYWORDS): return "privacy"
    return None

# ══════════════════════════════════════════════════════════
# 뉴스 수집 엔진
# ══════════════════════════════════════════════════════════
SECURITY_RSS_FEEDS = [
    {"name": "데일리시큐",  "url": "https://www.dailysecu.com/rss/allArticle.xml",    "xpath": ".//item"},
    {"name": "데이터넷",   "url": "https://www.datanet.co.kr/rss/allArticle.xml",     "xpath": ".//item"},
    {"name": "보안뉴스",   "url": "https://www.boannews.com/rss/totalRss.xml",         "xpath": ".//item"},
    {"name": "전자신문",   "url": "https://rss.etnews.com/Section901.xml",             "xpath": ".//item"},
    {"name": "ZDNet",     "url": "https://zdnet.co.kr/rss/news/news_tech.xml",        "xpath": ".//item"},
    {"name": "아이뉴스24", "url": "https://www.inews24.com/rss/rss_it.xml",           "xpath": ".//item"},
]

NEWS_COLLECT_DAYS = 3  # 최근 N일치 뉴스 수집

def _parse_rss_date(date_str: str):
    if not date_str: return None
    fmts = ["%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"]
    for fmt in fmts:
        try: return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=None)
        except ValueError: continue
    return None

def _strip_html(text: str) -> str:
    text = re.sub(r"<!\[CDATA\[|\]\]>", "", text)
    text = re.sub(r"<[^>]+>", "", text)
    for entity, char in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"), ("&apos;", "'"), ("&nbsp;", " ")]:
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text).strip()

def _clean_naver_text(text: str) -> str:
    if not text: return ""
    text = re.sub(r"<[^>]+>", "", text)
    for entity, char in [("&quot;", '"'), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&apos;", "'"), ("&#39;", "'"), ("&nbsp;", " ")]:
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text).strip()

NAVER_INFOSEC_QUERIES = ["정보보안 해킹", "사이버공격 랜섬웨어", "보안 취약점 CVE"]
NAVER_PRIVACY_QUERIES = ["개인정보 유출", "개인정보보호 침해", "개인정보위원회"]

def _fetch_naver(query: str) -> list:
    headers = {"X-Naver-Client-Id": NAVER_CLIENT_ID, "X-Naver-Client-Secret": NAVER_CLIENT_SECRET, "User-Agent": "Mozilla/5.0"}
    params = {"query": query, "display": 15, "start": 1, "sort": "date"}
    try:
        resp = requests.get("https://openapi.naver.com/v1/search/news.json", headers=headers, params=params, timeout=30)
        results = []
        cutoff = _news_cutoff()
        for item in resp.json().get("items", []):
            title = _clean_naver_text(item.get("title", ""))
            url   = (item.get("link") or item.get("originallink", "")).strip()
            pub_dt = _parse_rss_date(item.get("pubDate", ""))
            if pub_dt and pub_dt < cutoff: continue
            if title and url: results.append({"title": title, "url": url, "source": "네이버뉴스"})
        return results
    except Exception as e:
        logger.warning(f"네이버 쿼리 실패 ({query}): {e}")
        return []

def fetch_naver_news() -> list:
    if not NAVER_CLIENT_ID or not NAVER_CLIENT_SECRET: return []
    articles = []
    for q in NAVER_INFOSEC_QUERIES + NAVER_PRIVACY_QUERIES:
        articles.extend(_fetch_naver(q))
    return articles

def fetch_rss_security_news() -> list:
    cutoff = _news_cutoff()
    articles = []
    for feed in SECURITY_RSS_FEEDS:
        try:
            resp = requests.get(feed["url"], timeout=30, headers={"User-Agent": "Mozilla/5.0"})
            root = ET.fromstring(resp.content)
            count = 0
            for item in root.findall(feed["xpath"]):
                title = _strip_html(item.findtext("title") or "")
                url   = _strip_html(item.findtext("link") or "")
                pub_dt = _parse_rss_date(item.findtext("pubDate") or "")
                if pub_dt and pub_dt < cutoff: continue
                if title and url:
                    articles.append({"title": title, "url": url, "source": feed["name"]})
                    count += 1
            logger.info(f"RSS({feed['name']}): {count}건 수집")
        except Exception as e: logger.warning(f"RSS 실패 [{feed['name']}]: {e}")
    return articles

def fetch_newsapi() -> list:
    if not NEWS_API_KEY: return []
    today_str = datetime.now().strftime("%Y-%m-%d")
    params = {"q": " OR ".join(["보안", "정보보안", "개인정보", "사이버"]), "language": "ko", "from": today_str, "sortBy": "publishedAt", "pageSize": 30, "apiKey": NEWS_API_KEY}
    try:
        resp = requests.get("https://newsapi.org/v2/everything", params=params, timeout=30)
        articles = []
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        for item in resp.json().get("articles", []):
            title = (item.get("title") or "").strip()
            url   = (item.get("url") or "").strip()
            published_at = item.get("publishedAt", "")
            try:
                pub_dt = datetime.strptime(published_at[:19], "%Y-%m-%dT%H:%M:%S")
                if pub_dt < today_start: continue
            except: pass
            if title and url and "[Removed]" not in title:
                articles.append({"title": title, "url": url, "source": "NewsAPI"})
        return articles
    except Exception as e:
        logger.error(f"NewsAPI 실패: {e}")
        return []

def fetch_serpapi_news() -> list:
    if not SERPAPI_API_KEY: return []
    articles = []
    for q in ["정보보안 해킹", "개인정보 유출", "사이버공격 보안", "개인정보보호 침해"]:
        params = {"engine": "google", "q": q, "tbm": "nws", "tbs": "qdr:d2", "hl": "ko", "gl": "kr", "num": 10, "api_key": SERPAPI_API_KEY}
        try:
            resp = requests.get("https://serpapi.com/search", params=params, timeout=30)
            for item in resp.json().get("news_results", []):
                title = (item.get("title") or "").strip()
                url   = (item.get("link") or "").strip()
                if title and url: articles.append({"title": title, "url": url, "source": "Google뉴스"})
        except Exception as e: logger.warning(f"SerpApi 실패: {e}")
    return articles

def _deduplicate_news(articles: list) -> list:
    seen_urls, seen_titles, unique = set(), set(), []
    for a in articles:
        url = (a.get("url") or "").strip()
        title_norm = re.sub(r"\s+", "", (a.get("title") or "").lower())
        if url in seen_urls or title_norm in seen_titles: continue
        seen_urls.add(url)
        seen_titles.add(title_norm)
        unique.append(a)
    return unique

def collect_news():
    combined = fetch_rss_security_news() + fetch_newsapi() + fetch_serpapi_news() + fetch_naver_news()
    infosec_raw, privacy_raw = [], []
    for a in combined:
        cat = _classify_news(a.get("title", ""))
        if cat == "infosec": infosec_raw.append(a)
        elif cat == "privacy": privacy_raw.append(a)
    return _deduplicate_news(infosec_raw)[:NEWS_MAX_PER_CATEGORY], _deduplicate_news(privacy_raw)[:NEWS_MAX_PER_CATEGORY]

# ══════════════════════════════════════════════════════════
# 법령 수집 엔진
# ══════════════════════════════════════════════════════════
def _load_law_cache():
    if os.path.exists(LAW_CACHE_FILE):
        try:
            with open(LAW_CACHE_FILE, encoding="utf-8") as f: return set(json.load(f))
        except: pass
    return set()

def _save_law_cache(seen_ids):
    try:
        with open(LAW_CACHE_FILE, "w", encoding="utf-8") as f: json.dump(list(seen_ids), f, ensure_ascii=False)
    except: pass

def _is_recent(date_str: str) -> bool:
    if not date_str: return False
    try: return datetime.strptime(date_str.replace("-", "").strip(), "%Y%m%d") >= (datetime.now() - timedelta(days=LAW_RECENCY_DAYS))
    except: return False

def _classify_law(title: str):
    if any(ex in title for ex in LAW_EXCLUDE_KEYWORDS): return None
    if any(kw in title for kw in LAW_PRIVACY_KEYWORDS): return "privacy"
    if any(kw in title for kw in LAW_INFOSEC_KEYWORDS): return "infosec"
    return None

_LAW_TARGET_META = {
    # (root_tag, item_tag, name_field, id_field, date_field, url_template)
    "law":    ("LawSearch",    "law",    "법령명한글",    "법령ID",          "공포일자",  "https://www.law.go.kr/lsInfoP.do?lsiSeq={id}"),
    "admrul": ("AdmRulSearch", "admrul", "행정규칙명",    "행정규칙일련번호", "발령일자",  "https://www.law.go.kr/admRulInfoP.do?admRulSeq={id}"),
    "ppc":    ("PpcSearch",    "ppc",    "사건명",        "일련번호",        "결정일자",  "https://www.law.go.kr/crdInfoP.do?crdSeq={id}"),
    "prec":   ("PrecSearch",   "prec",   "사건명",        "판례일련번호",    "선고일자",  "https://www.law.go.kr/precInfoP.do?precSeq={id}"),
}

def _fetch_law_target(target: str, query: str, max_retries: int = 3):
    if not LAW_API_KEY: return [], False
    if target not in _LAW_TARGET_META:
        logger.warning(f"지원하지 않는 법령 target: {target}")
        return [], False
    root_tag, item_tag, name_field, id_field, date_field, url_tmpl = _LAW_TARGET_META[target]
    params = {"OC": LAW_API_KEY, "target": target, "query": query, "type": "XML", "display": 20, "page": 1, "sort": "lasc"}
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get("https://www.law.go.kr/DRF/lawSearch.do", params=params, timeout=30)
            if resp.status_code == 200 and f"<{root_tag}>" in resp.text:
                is_updated = "<totalCnt>0</totalCnt>" not in resp.text
                root = ET.fromstring(resp.content)
                results = []
                for item in root.findall(f".//{item_tag}"):
                    title_el = item.find(name_field)
                    id_el    = item.find(id_field)
                    date_el  = item.find(date_field)
                    if title_el is None: continue
                    title  = (title_el.text or "").strip()
                    law_id = (id_el.text if id_el is not None else "").strip()
                    if title and law_id:
                        url = url_tmpl.format(id=law_id)
                        results.append({"title": title, "url": url, "date": (date_el.text if date_el is not None else "").strip(), "id": law_id, "target": target})
                return results, is_updated
            logger.warning(f"법령 API 응답 오류 ({target}/{query}) [{resp.status_code}] 시도 {attempt}/{max_retries}")
        except Exception as e:
            logger.warning(f"법령 API 실패 ({target}/{query}) 시도 {attempt}/{max_retries}: {e}")
        if attempt < max_retries:
            time.sleep(2 ** attempt)  # 2초, 4초 대기 후 재시도
    return [], False

PREC_RECENCY_DAYS = 90
PREC_CACHE_FILE = "prec_seen.json"
PREC_KEYWORDS = ["개인정보", "정보보호", "사이버", "해킹", "개인정보침해", "정보보안", "CCTV", "위치정보", "생체정보"]

def _load_prec_cache():
    if os.path.exists(PREC_CACHE_FILE):
        try:
            with open(PREC_CACHE_FILE, encoding="utf-8") as f: return set(json.load(f))
        except: pass
    return set()

def _save_prec_cache(seen_ids):
    try:
        with open(PREC_CACHE_FILE, "w", encoding="utf-8") as f: json.dump(list(seen_ids), f, ensure_ascii=False)
    except: pass

def collect_precedents() -> list:
    """판례(prec) + 개인정보보호위원회 결정(ppc) 수집"""
    if not LAW_API_KEY: return []
    raw_all = []
    for target, queries in [
        ("prec", ["개인정보", "정보보호", "사이버", "해킹"]),
        ("ppc",  ["개인정보", "정보보호", "개인정보침해"]),
    ]:
        for query in queries:
            items, _ = _fetch_law_target(target, query)
            raw_all.extend(items)

    seen_titles, deduped = set(), []
    for r in raw_all:
        if r["title"] not in seen_titles:
            seen_titles.add(r["title"])
            deduped.append(r)

    sent_cache = _load_prec_cache()
    result, new_ids = [], set()
    cutoff_dt = datetime.now() - timedelta(days=PREC_RECENCY_DAYS)
    for r in deduped:
        if r["id"] in sent_cache: continue
        date_str = r.get("date", "").replace("-", "").strip()
        try:
            if datetime.strptime(date_str, "%Y%m%d") < cutoff_dt: continue
        except: continue
        if any(kw in r["title"] for kw in PREC_KEYWORDS):
            r["category"] = "prec"
            result.append(r)
            new_ids.add(r["id"])
    _save_prec_cache(sent_cache | new_ids)
    logger.info(f"판결/결정문: {len(result)}건 수집")
    return result[:5]

def collect_laws():
    if not LAW_API_KEY: return [], [], False
    raw_all, any_law_updated = [], False
    for target in ["law", "admrul"]:
        for query in ["정보보호", "개인정보", "정보보안", "사이버"]:
            laws, has_update = _fetch_law_target(target, query)
            raw_all.extend(laws)
            if has_update: any_law_updated = True
    seen_titles, deduped = set(), []
    for r in raw_all:
        if r["title"] not in seen_titles:
            seen_titles.add(r["title"])
            deduped.append(r)
    sent_cache = _load_law_cache()
    newly_changed, new_sent_ids = [], set()
    for r in deduped:
        if not _is_recent(r["date"]) or r["id"] in sent_cache: continue
        cat = _classify_law(r["title"])
        if cat:
            r["category"] = cat
            newly_changed.append(r)
            new_sent_ids.add(r["id"])
    _save_law_cache(sent_cache | new_sent_ids)
    return [r for r in newly_changed if r["category"] == "infosec"][:5], [r for r in newly_changed if r["category"] == "privacy"][:5], any_law_updated

# ══════════════════════════════════════════════════════════
# 카카오톡 메시지 핸들러
# ══════════════════════════════════════════════════════════
KAKAO_CHANNEL_URL = "https://kapi.kakao.com/v1/api/talk/channels/message/send"
KAKAO_MEMO_URL    = "https://kapi.kakao.com/v2/api/talk/memo/default/send"

def _sanitize(text: str) -> str:
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text).strip()

def _make_template(header: str, chunk: list, start_idx: int, has_law_update: bool) -> dict:
    last_url = "https://www.pipc.go.kr"
    lines = [header]
    for rank, item in enumerate(chunk, start=start_idx):
        title = _sanitize(item.get("title") or "")
        if len(title) > 22:
            title = title[:21] + "…"
        url = _sanitize(item.get("url") or "")
        if url:
            last_url = url
        lines.append(f"\n{rank}. {title}\n{url}")
    text_content = "\n".join(lines).strip()
    return {
        "object_type": "text",
        "text": text_content,
        "link": {"web_url": last_url, "mobile_web_url": last_url},
        "button_title": "기사 보기"
    }

def _send_channel(template: dict) -> bool:
    if not KAKAO_CHANNEL_PROFILE_KEY: return False
    headers = {"Authorization": f"Bearer {KAKAO_ACCESS_TOKEN}", "Content-Type": "application/x-www-form-urlencoded"}
    payload = {"template_object": json.dumps(template, ensure_ascii=False), "channel_public_id": KAKAO_CHANNEL_PROFILE_KEY}
    try:
        resp = requests.post(KAKAO_CHANNEL_URL, headers=headers, data=payload, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("result_code") == 0 or data.get("msg") == "OK":
                return True
        logger.error(f"채널 발송 실패 [{resp.status_code}]: {resp.text[:300]}")
        return False
    except Exception as e:
        logger.error(f"채널 발송 예외: {e}")
        return False

def _send_memo(template: dict) -> bool:
    if not KAKAO_ACCESS_TOKEN: return False
    headers = {"Authorization": f"Bearer {KAKAO_ACCESS_TOKEN}", "Content-Type": "application/x-www-form-urlencoded"}
    payload = {"template_object": json.dumps(template, ensure_ascii=True)}
    try:
        resp = requests.post(KAKAO_MEMO_URL, headers=headers, data=payload, timeout=30)
        if resp.status_code == 200 and resp.json().get("result_code") == 0:
            return True
        logger.error(f"메모 발송 실패 [{resp.status_code}]: {resp.text[:300]}")
        return False
    except Exception as e:
        logger.error(f"메모 발송 예외: {e}")
        return False

def send_alert(header: str, items: list, has_law_update: bool) -> bool:
    if not items: return False
    chunks = [items[i:i + SEND_CHUNK_SIZE] for i in range(0, len(items), SEND_CHUNK_SIZE)]
    all_ok = True
    for idx, chunk in enumerate(chunks, start=1):
        chunk_header = f"{header} ({idx}/{len(chunks)})" if len(chunks) > 1 else header
        start_idx = (idx - 1) * SEND_CHUNK_SIZE + 1
        template = _make_template(chunk_header, chunk, start_idx, has_law_update)
        logger.info(f"템플릿 텍스트 길이: {len(template['text'])}자")
        ok = _send_channel(template) or _send_memo(template)
        if ok:
            logger.info(f"✅ 발송 성공: {chunk_header}")
        else:
            logger.error(f"❌ 발송 실패: {chunk_header}")
            all_ok = False
        time.sleep(1)
    return all_ok

def run_daily_alert() -> None:
    refresh_kakao_token()
    logger.info("=======================================================")
    logger.info(f"  보안 알림 시작: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    logger.info("=======================================================")
    _check_env()
    today = datetime.now().strftime("%m/%d")

    infosec_news, privacy_news = collect_news()
    infosec_laws, privacy_laws, has_law_update = collect_laws()
    precedents = collect_precedents()

    logger.info(f"수집 결과 — 정보보안뉴스:{len(infosec_news)} 개인정보뉴스:{len(privacy_news)} "
                f"정보보안법령:{len(infosec_laws)} 개인정보법령:{len(privacy_laws)} 판결/결정:{len(precedents)}")

    if infosec_news:
        send_alert(f"🔒 정보보안 뉴스 ({today})", infosec_news, has_law_update)
    else:
        logger.info("📭 오늘 정보보안 뉴스 없음")

    if privacy_news:
        send_alert(f"🔐 개인정보 뉴스 ({today})", privacy_news, has_law_update)
    else:
        logger.info("📭 오늘 개인정보 뉴스 없음")

    if infosec_laws: send_alert(f"🛡️ 정보보호 법령 변경 ({today})", infosec_laws, has_law_update)
    if privacy_laws: send_alert(f"👤 개인정보 법령 변경 ({today})", privacy_laws, has_law_update)
    if precedents:   send_alert(f"⚖️ 주요 판결/결정문 ({today})", precedents, False)

    logger.info(f"  보안 알림 완료: {datetime.now().strftime('%H:%M:%S')}")

def main() -> None:
    schedule.every().day.at("08:40").do(run_daily_alert)
    schedule.every().day.at("12:00").do(run_daily_alert)
    logger.info("스케줄러 작동 시작 (08:40 / 12:00 예약 완료)")
    while True:
        schedule.run_pending()
        time.sleep(30)

def run_law_sample() -> None:
    """법령 발송 기능 테스트용 — LAW_API_KEY 없이 샘플 데이터로 카카오톡 발송"""
    refresh_kakao_token()
    today = datetime.now().strftime("%m/%d")

    sample_infosec_laws = [
        {
            "title": "정보통신기반 보호법 시행령",
            "url": "https://www.law.go.kr/법령/정보통신기반보호법시행령",
            "date": "20260101",
            "category": "infosec",
        },
        {
            "title": "정보보호산업의 진흥에 관한 법률",
            "url": "https://www.law.go.kr/법령/정보보호산업의진흥에관한법률",
            "date": "20260115",
            "category": "infosec",
        },
        {
            "title": "사이버보안기본법",
            "url": "https://www.law.go.kr/법령/사이버보안기본법",
            "date": "20260201",
            "category": "infosec",
        },
    ]
    sample_privacy_laws = [
        {
            "title": "개인정보 보호법 시행령",
            "url": "https://www.law.go.kr/법령/개인정보보호법시행령",
            "date": "20260101",
            "category": "privacy",
        },
        {
            "title": "신용정보의 이용 및 보호에 관한 법률",
            "url": "https://www.law.go.kr/법령/신용정보의이용및보호에관한법률",
            "date": "20260120",
            "category": "privacy",
        },
    ]

    logger.info("=== 법령 샘플 발송 테스트 시작 ===")
    send_alert(f"🛡️ 정보보호 법령 변경 ({today})", sample_infosec_laws, has_law_update=True)
    send_alert(f"👤 개인정보 법령 변경 ({today})", sample_privacy_laws, has_law_update=True)
    logger.info("=== 법령 샘플 발송 완료 ===")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_daily_alert()
    elif len(sys.argv) > 1 and sys.argv[1] == "--test-law":
        run_law_sample()
    else:
        main()
