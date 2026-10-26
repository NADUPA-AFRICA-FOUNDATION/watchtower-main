"""Fraud-lure vocabulary for indexed social leads (Kenya / M-PESA focus).

PROVENANCE: COMMON_PATTERN. These are phrasings that recur in public scam advisories
(Safaricom, CA Kenya, DCI, fact-checkers) and in the lures reviewed for this project. They
are NOT yet checked against this repo's confirmed cases, so every entry is UNVERIFIED in
the sense `CLAUDE.md` uses for the scamscan Sheng bucket: a hit is a reason to look, never
a verdict. Swahili and Sheng entries are the thinnest and should be rebuilt from confirmed
cases first.

Matching rules (see `core/sources.py::_bait_signals`):
  * literal phrases, case-insensitive, any run of spaces/hyphens between words
  * `\\b` is asserted only where the phrase's own edge is a word character
  * a category counts once however many of its phrases hit, so ten synonyms of
    "guaranteed" are one signal, not ten
  * an advisory marker ("scam", "fake", "beware", ...) suppresses everything, because a
    warning quotes the bait verbatim

Keep phrases multi-word unless the single word is unambiguous. "loan" alone is not a lure.
"""
from __future__ import annotations

import re

LEXICON: dict[str, list[str]] = {
    # Money asked for before anything is delivered. The strongest single family.
    "advance_fee": [
        "registration fee", "activation fee", "processing fee", "access fee", "upgrade fee",
        "verification fee", "clearance fee", "release fee", "withdrawal fee", "unlock fee",
        "admin fee", "service fee", "handling fee", "facilitation fee", "commitment fee",
        "refundable deposit", "security deposit", "insurance fee", "tax fee", "legal fee",
        "pay a small fee", "pay a fee first", "small fee required", "minimal fee",
        "pay before you receive", "pay to receive", "pay to unlock", "pay to activate",
        "pay to upgrade", "pay to withdraw", "send a token", "send token fee",
        "send ksh to receive", "send kes to receive", "deposit to qualify", "deposit to unlock",
        "deposit to withdraw", "deposit first", "top up to qualify", "top up to unlock",
        "pay then get", "pay and get", "pay and receive", "pay upfront", "payment upfront",
        "advance payment", "advance fee", "prepay", "pre-pay", "prepaid charges",
        "ready with the charges", "be ready with charges", "charges apply before",
        "charges are payable", "fee is refundable", "fee will be refunded",
        "get your money back after", "refunded after approval", "one-time fee",
        "one time payment", "one-off fee", "once off payment", "cost of the service",
        "our charges are", "our fee is", "commission upfront", "pay commission first",
    ],
    # Certainty no legitimate lender or broker can offer.
    "guarantee_claims": [
        "guaranteed", "guarantee you", "100% guaranteed", "100 percent guaranteed",
        "100% sure", "100% working", "100% legit", "100% success", "100% safe",
        "assured", "fully assured", "assured results", "assured increase", "assured returns",
        "sure win", "sure deal", "sure thing", "sure profit", "sure returns", "sure increment",
        "no risk", "zero risk", "risk free", "risk-free", "no loss", "no loss guarantee",
        "cannot lose", "can't lose", "never lose", "money back guarantee",
        "guaranteed approval", "guaranteed increase", "guaranteed limit", "guaranteed profit",
        "guaranteed daily", "guaranteed weekly", "guaranteed monthly", "instant approval",
        "approval guaranteed", "everyone qualifies", "anyone can qualify", "no crb check",
        "no crb needed", "no credit check", "no collateral", "no security required",
        "without crb", "even if blacklisted", "blacklisted accepted", "we deliver 100%",
        "works for everyone", "never fails", "proven method", "proven system", "legit and trusted", "we are legit",
        "we do legitimate business", "100% genuine",
    ],
    # Manufactured time pressure.
    "urgency_pressure": [
        "hurry up", "hurry now", "act now", "act fast", "act today", "limited slots",
        "limited slot", "limited time", "limited offer", "limited spots", "slots almost full",
        "slots are full", "few slots left", "only few slots", "last chance", "last slots",
        "final call", "final warning", "offer ends today", "offer expires", "expires in",
        "ends tonight", "ends soon", "today only", "only today", "this week only",
        "while stocks last", "don't miss out", "do not miss out", "dont miss out",
        "don't delay", "do not delay", "apply now", "register now", "join now",
        "claim now", "claim today", "claim yours", "click now", "click here now",
        "respond immediately", "reply immediately", "immediate action", "urgent action",
        "urgent response", "within 24 hours", "within 12 hours", "within 1 hour",
        "within 30 minutes", "within 20 minutes", "within 10 minutes", "in the next 20 minutes",
        "delivered within", "processed instantly", "instantly boosted", "instant boost",
        "instant increase", "instant loan", "instant cash", "instant payout",
        "get it instantly", "get paid instantly", "receive instantly", "immediately boosted",
        "inbox now", "dm now", "message now", "whatsapp now", "chat now",
    ],
    # Asking for the secrets that move money. Any of these is a hard red flag.
    "credential_theft": [
        "send your pin", "share your pin", "give me your pin", "enter your pin",
        "confirm your pin", "provide your pin", "m-pesa pin", "mpesa pin", "your mpesa pin",
        "your m-pesa pin", "send otp", "share otp", "send the otp", "share the otp",
        "give the otp", "enter otp", "confirm otp", "provide otp", "your otp",
        "one time password", "one-time password", "verification code", "send the code",
        "share the code", "confirmation code", "send me the code", "forward the code",
        "forward the message", "forward the sms", "send your password", "share your password",
        "your password", "your id number", "send your id", "id number and phone",
        "send id photo", "photo of your id", "selfie with your id", "send your selfie",
        "bank details", "send your account number", "your account details",
        "card number", "cvv", "card pin", "card details", "expiry date and cvv",
        "login details", "log in details", "your credentials", "your username and password",
        "confirm your identity", "verify your identity", "update your kyc", "kyc update",
        "kyc verification", "account verification", "verify your account", "verify your number",
        "sim swap", "sim verification", "sim registration update", "unlock your account",
        "your account will be blocked", "your account will be suspended",
        "your account has been suspended", "account suspended", "account blocked",
        "account will be closed", "reactivate your account", "re-activate your account",
    ],
    # Pretending to be the institution.
    "impersonation": [
        "safaricom official", "official safaricom", "safaricom agent", "safaricom promo", "safaricom promotion",
        "safaricom giveaway", "safaricom loans", "safaricom soft loans", "safaricom upgrade",
        "safaricom partner", "safaricom approved", "safaricom authorised", "safaricom authorized",
        "affiliated with safaricom", "partnered with safaricom", "in partnership with safaricom",
        "m-pesa official", "official m-pesa", "mpesa official", "m-pesa agent", "m-pesa promo", "m-pesa promotion",
        "mpesa promotion", "m-pesa support", "mpesa support", "fuliza official",
        "official fuliza", "fuliza customer care", "fuliza support", "fuliza agent",
        "fuliza assistant", "fuliza portal", "m-shwari official",
        "m-shwari support", "kcb official", "kcb m-pesa support", "ziidi official",
        "ziidi support", "ziidi agent", "ziidi customer care", "ziidi portal",
        "ziidi partner", "nse official", "cma approved", "cma licensed", "cbk approved",
        "cbk licensed", "licensed by cbk", "licensed by cma", "regulated by cbk",
        "regulated by cma", "central bank approved", "government approved",
        "government programme", "government program", "government loan", "government grant",
        "hustler fund official", "hustler fund agent", "hustler fund upgrade",
        "hustler fund limit", "kra official", "kra refund", "sha official", "ntsa fine",
        "dci official", "ecitizen official", "huduma official", "equity official",
    ],
    # The core lure for this investigation: paying to raise a mobile loan limit.
    "loan_limit_boost": [
        "fuliza limit increase", "fuliza limit boost", "fuliza limit upgrade",
        "fuliza limit increment", "fuliza limit increament", "fuliza increase",
        "fuliza boost", "fuliza increment", "fuliza upgrade", "fuliza top up",
        "fuliza limit hack", "fuliza limit trick", "fuliza limit code",
        "fuliza limit secret", "fuliza limit from zero", "fuliza from 0",
        "fuliza limit to 70k", "fuliza limit to 50k", "fuliza limit to 100k",
        "fuliza up to 75k", "boost your fuliza", "increase your fuliza",
        "upgrade your fuliza", "raise your fuliza", "unlock your fuliza", "refresh fuliza limit",
        "fuliza limit refresh", "fuliza loan increase", "fuliza loan limit",
        "fuliza loan increment", "fuliza loan boost", "fuliza overdraft increase",
        "overdraft limit increase", "overdraft boost", "overdraft upgrade",
        "m-shwari limit increase", "m-shwari limit boost", "m-shwari loan increase",
        "m-shwari loan limit", "m-shwari upgrade", "mshwari limit increase",
        "mshwari loan boost", "kcb mpesa limit increase", "kcb m-pesa limit boost",
        "kcb mpesa loan increase", "hustler fund limit increase", "hustler fund boost",
        "hustler fund top up", "okoa jahazi limit", "okoa jahazi increase",
        "loan limit increase", "loan limit boost", "loan limit upgrade",
        "loan limit increment", "loan limit increament", "loan limit hack",
        "loan limit top up", "loan increment", "loan increase service",
        "loan booster", "loan boost service", "credit limit increase", "credit limit boost",
        "credit limit upgrade", "increase your loan limit", "boost your loan limit",
        "upgrade your loan limit", "increase mpesa loan limit", "increase mobile loan limit",
        "limit increase service", "limit boosting service", "limit upgrade service",
        "limit increment service", "limit increase agent", "limit increase assistant",
        "limit increase app", "limit increase portal", "limit increase website",
        "limit increase code", "limit increase trick", "limit increase hack",
        "get a higher limit", "get higher fuliza", "higher limit instantly",
        "from 500 to", "from ksh 500 to", "from 1000 to 20000", "limit from 0 to",
        "limit up to 75k", "limit up to 100k", "limit up to 70,000", "limit upto 70k",
        "boosted today upto", "boosted upto", "increment here", "increments here",
        "we increase fuliza", "we boost fuliza", "we upgrade fuliza", "we increase limits",
        "we increase your limit", "we boost your limit", "we upgrade your limit",
        "hit admin inbox to get the same", "we make it happen", "thumbs up for great fuliza",
    ],
    # Returns that beat any legitimate product.
    "investment_returns": [
        "double your money", "triple your money", "multiply your money", "money doubling",
        "money multiplication", "turn 1000 into", "turn ksh 1000 into", "turn 5000 into",
        "turn 10000 into", "invest 1000 and get", "invest 5000 and get", "invest 10000 and get",
        "invest ksh 1000", "daily returns", "daily profit", "daily income", "daily payout",
        "daily roi", "weekly returns", "weekly profit", "weekly payout", "monthly returns of",
        "10% daily", "5% daily", "20% daily", "30% weekly", "50% weekly", "100% weekly",
        "100% monthly", "200% returns", "300% returns", "500% returns", "1000% returns",
        "high returns", "huge returns", "massive returns", "extraordinary returns",
        "fixed returns", "fixed daily", "fixed profit", "guaranteed returns", "make money while you sleep", "earn while you sleep", "get rich quick", "get rich fast", "quick money",
        "fast money", "easy money", "easy cash", "free money",
        "earn up to", "earn daily", "earn weekly", "earn from home", "earn on your phone",
        "start with ksh", "start with as little as", "minimum investment of",
        "minimum deposit of", "invest and earn", "invest and double", "invest today and", "vip package",
        "vip plan", "vip level", "upgrade vip", "ponzi", "pyramid", "multi-level",
        "referral bonus", "referral commission", "refer and earn", "refer friends and earn",
        "recruit and earn", "downline", "upline", "team commission", "level 1 commission",
        "withdraw daily", "instant withdrawals", "instant withdrawal", "withdrawals every",
        "money market fund fake", "mmf returns of", "ziidi returns of", "ziidi guaranteed",
        "ziidi daily returns", "ziidi trading signals", "ziidi trader signals",
        "nse stock tips guaranteed", "stock tips guaranteed", "share tips guaranteed",
        "prices rising every two seconds", "prices rising every second",
    ],
    # Crypto, forex and "signals" funnels that route to Telegram/WhatsApp.
    "crypto_forex_signals": [
        "forex signals", "free signals", "vip signals", "premium signals", "signal group",
        "signals telegram", "join our telegram", "join my telegram", "join telegram",
        "telegram channel for signals", "forex trading mentor", "forex mentor",
        "forex account manager", "managed forex account", "account management service",
        "forex investment", "forex robot", "trading robot", "trading bot", "ai trading bot",
        "ai trading", "auto trading", "copy trading", "copy my trades", "mt4 signals",
        "mt5 signals", "binary options", "binary trading", "gold signals", "xauusd signals",
        "100 to 1k", "100 to 1000", "10 to 1000", "turn $100 into", "turn $50 into",
        "crypto doubling", "crypto investment", "crypto mining", "cloud mining",
        "bitcoin investment", "bitcoin doubling", "bitcoin flash", "flash usdt",
        "usdt flash", "usdt investment", "usdt staking", "staking rewards guaranteed",
        "airdrop claim", "claim airdrop", "claim your airdrop", "connect your wallet",
        "wallet validation", "validate your wallet", "seed phrase", "recovery phrase",
        "private key", "trust wallet support", "metamask support", "binance support",
        "binance promo", "binance giveaway", "recover your funds", "fund recovery",
        "recover lost money", "recovery agent", "hacker for hire", "hack account for",
        "pip profit", "daily pips", "profit screenshots", "proof of profit",
        "withdrawal proof", "payment proof", "trade proof", "dm for mentorship",
        "dm to join", "dm for signals", "dm for details", "inbox for details",
    ],
    # Fake jobs and fake registration drives.
    "job_offer": [ "urgent vacancy", "work from your phone", "online job offer",
        "data entry job", "typing jobs", "typing job", "captcha typing", "like and earn",
        "like and get paid", "like videos and earn", "watch videos and earn",
        "watch and earn", "click and earn", "follow and earn", "rate products and earn",
        "task and earn", "complete tasks and earn", "simple tasks", "easy tasks",
        "no experience needed", "no experience required", "no interview", "no cv needed",
        "no qualifications", "hiring immediately", "immediate hiring",
        "direct hiring", "recruitment fee", "recruitment agent", "training fee",
        "uniform fee", "medical fee", "application fee", "interview fee",
        "pay to be employed", "pay for the job", "visa processing fee",
        "jobs in dubai", "jobs in qatar", "jobs in saudi", "jobs in canada", "jobs in usa",
        "overseas jobs guaranteed", "kenya power jobs", "kra jobs",
        "safaricom jobs", "safaricom recruitment", "recruitment drive", "shortlisted for",
        "you have been shortlisted", "you have been selected", "you have been hired",
        "congratulations you are hired", "send your cv to whatsapp", "send cv via whatsapp",
        "whatsapp for job", "telegram for job", "register to work", "registration to work",
    ],
    # Prizes, grants and giveaways that need a "release" payment.
    "prize_giveaway": [
        "you have won", "you've won", "you are a winner", "you are the winner",
        "congratulations you have won", "congratulations you won", "lucky winner",
        "lucky draw", "lucky number", "raffle winner", "promo winner", "jackpot winner",
        "winning notification", "winning number", "claim your prize", "claim your reward",
        "claim your gift", "claim your bonus", "claim your cash", "claim your money",
        "claim your grant", "claim your refund", "prize money", "prize claim",
        "cash prize", "cash reward", "cash giveaway", "cash gift", "free airtime",
        "free data bundles", "free bundles", "free safaricom data",
        "free tokens", "free okoa", "free fuliza", "free loan", "free money giveaway",
        "giveaway ksh", "giveaway of ksh", "we are giving away", "giving out money",
        "giving out free", "sharing money", "sharing free money", "sponsored giveaway",
        "anniversary promo", "anniversary giveaway", "birthday giveaway", "festive promo",
        "christmas promo", "easter promo", "mashujaa promo", "promo ends", "bonus airtime",
        "bonga points", "redeem bonga points", "redeem your points", "points expiring",
        "your number was selected", "your number has been selected", "selected number",
        "random selection", "randomly selected", "you were selected", "you have been chosen",
        "chosen to receive", "eligible to receive", "eligible for a grant", "youth grant",
        "women grant", "business grant", "covid grant", "world bank grant", "un grant",
        "inheritance fund", "unclaimed funds", "unclaimed inheritance", "dormant account funds",
    ],
    # "Sent to the wrong number" and reversal tricks.
    "reversal_wrong_transaction": [
        "sent to the wrong number", "sent to wrong number", "wrong number sent",
        "sent by mistake", "sent in error", "transferred by mistake", "mistakenly sent",
        "mistakenly transferred", "please reverse", "kindly reverse", "reverse the money",
        "reverse the transaction", "reverse the amount", "return the money", "return my money",
        "return the amount", "send it back", "send back the money", "refund me",
        "kindly refund", "please refund", "i sent you ksh", "i have sent you ksh",
        "you received ksh", "confirmed you have received", "confirmed. you have received",
        "ksh received from", "failed transaction", "transaction failed refund",
        "pending reversal", "reversal pending", "reversal fee", "reversal charges",
        "reverse by sending", "pay to reverse", "airtime sent by mistake",
        "wrong paybill", "wrong till", "wrong till number", "paid to wrong", "overpayment refund",
        "refund of ksh", "claim refund", "refund fee",
    ],
    # The hand-off into a private channel where the payment happens.
    "contact_funnel": [
        "dm admin", "dm the admin", "dm our admin", "message admin", "message the admin",
        "message our admin", "inbox admin", "inbox the admin", "hit admin", "hit the admin",
        "hit admin inbox", "hit my inbox", "hit my dm", "hit me up", "hit our agent",
        "contact admin", "contact the admin", "contact our admin", "contact our agent",
        "contact the agent", "contact agent", "contact my agent", "talk to admin",
        "talk to our agent", "chat admin", "chat with admin", "chat with our agent",
        "chat on whatsapp", "chat on telegram", "whatsapp us", "whatsapp me",
        "whatsapp admin", "whatsapp agent", "whatsapp on",
        "telegram admin", "telegram agent", "telegram me", "join our group",
        "join the group", "join our channel", "join the channel", "link in my bio", "click the link in bio", "click link in bio",
        "click the link below", "click link below", "link below", "link in comments",
        "link in the comments", "link in description", "link in the description",
        "tap the link", "tap link", "click to apply", "click to register", "click to claim",
        "click here to apply", "click here to claim",
        "apply via the link", "apply using the link", "submit your details", "send your details",
        "send your number", "drop your number", "drop your phone number", "leave your number",
        "comment your number", "comment done", "comment yes", "comment interested",
        "comment 'yes'", "type yes", "type interested", "interested? inbox", "interested inbox",
        "interested dm", "inbox me", "inbox to apply", "inbox to join", "inbox for more",
    ],
    # Fabricated social proof.
    "fake_social_proof": [ "happy members",
        "real testimonies", "see testimonials", "check testimonials", "proof of payment",
        "proof of success", "proof of withdrawal", "payment screenshots", "screenshots of payments",
        "screenshot proof", "see the proof", "see proof", "check proof",
        "results speak for themselves",
        "congratulations to", "congrats to", "thumbs up for", "thumbs up to",
        "what a fine morning for", "what a great day for", "what a fine day for",
        "another happy client", "another satisfied client", "another success story", "trusted by thousands", "trusted by over",
        "thousands of kenyans", "join thousands", "join over", "over 10,000 members",
        "over 5,000 members", "verified agent", "verified agents", "verified admin",
        "verified service", "verified and trusted", "trusted agent", "trusted admin",
        "trusted service", "most trusted", "number one in kenya", "#1 in kenya",
        "best service in kenya", "kenya's best", "kenyas best",
    ],
    # Wording that points at throwaway hosting and link tricks.
    "link_hosting": [
        "vercel.app", "netlify.app", "pages.dev", "github.io", "blogspot.com",
        "weebly.com", "wixsite.com", "wordpress.com", "000webhostapp", "herokuapp.com",
        "web.app", "firebaseapp.com", "glitch.me", "replit.app", "onrender.com",
        "bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.ly", "shorturl.at",
        "ow.ly", "linktr.ee", "lnk.bio", "beacons.ai", "carrd.co", "sites.google.com",
        "forms.gle", "docs.google.com/forms", "tiny.cc", "shorte.st", "adf.ly",
    ],
    # Kiswahili lures. UNVERIFIED against confirmed cases.
    "swahili": [
        "ongeza limit", "ongeza kikomo", "ongeza fuliza", "kuongeza fuliza",
        "kuincrease fuliza", "kuongeza limit ya fuliza", "limit ya fuliza",
        "pata mkopo", "mkopo wa haraka", "mkopo bila", "mkopo bila dhamana",
        "mkopo bila crb", "mkopo papo hapo", "mkopo wa papo hapo", "mkopo wa simu",
        "pata pesa", "pata pesa haraka", "pata pesa leo", "pesa za haraka",
        "pesa bure", "pesa za bure", "pesa kwa urahisi", "tengeneza pesa", "tengeneza pesa mtandaoni",
        "faida ya uhakika", "faida kila siku", "faida ya haraka", "uhakika asilimia mia",
        "uhakika wa asilimia 100", "bila hatari", "hakuna hatari", "hakuna hasara",
        "lipa ada", "lipa kidogo", "ada ndogo", "ada ya usajili", "ada ya uanachama",
        "tuma pesa kwanza", "tuma ada", "tuma kiasi kidogo", "tuma pin", "tuma namba ya siri",
        "nambari ya siri", "namba ya siri ya mpesa", "tuma otp", "tuma msimbo",
        "tuma namba ya kitambulisho", "tuma kitambulisho", "tuma picha ya kitambulisho",
        "umeshinda", "umeshinda zawadi", "umechaguliwa", "umebahatika", "bahati nasibu",
        "zawadi ya pesa", "dai zawadi yako", "dai pesa yako", "wasiliana nasi",
        "wasiliana na admin", "tuma ujumbe", "tuma ujumbe inbox", "inbox kwa maelezo",
        "jiunge sasa", "jiunge na group", "jiunge na channel", "usikose nafasi",
        "nafasi chache", "nafasi zimebaki", "haraka sasa", "leo tu", "ofa ya leo",
        "ofa inaisha", "ofa ya muda mfupi", "tuma kwa namba hii", "tuma kwa till",
        "tuma kwa paybill", "nimetuma pesa kwa makosa", "nimetumiwa kwa makosa",
        "rudisha pesa", "tafadhali rudisha", "naomba unirudishie", "pesa zimetumwa kimakosa",
        "kazi ya mtandaoni", "kazi bila uzoefu", "kazi za nje", "kazi ya serikali",
    ],
    # Sheng / street-register lures. The thinnest bucket; UNVERIFIED.
    "sheng": [
        "ongeza fuliza kwa dakika", "tunaincrease limit", "tunaboost fuliza",
        "tunaupgrade limit", "tunaongeza limit", "kuincrease limit ni very easy",
        "ni very easy", "ni ezzy", "ni easy tu", "mambo ni poa tu", "pesa ni nyingi",
        "pesa ya haraka sana", "chapa pesa", "kuchapa pesa", "tengeneza doh",
        "doh ya haraka", "doh ya bure", "doh bila stress", "bila stress", "bila ID",
        "bila crb", "bila form", "bila kuchelewa", "ndani ya dakika tano",
        "dakika chache tu", "dm tu", "inbox tu", "ingia inbox", "twende inbox",
        "tuma kakitu kidogo", "tuma kidogo kwanza", "tuma ata 200", "tuma ata 500",
        "deposit kidogo", "weka kidogo", "weka deposit", "weka hela kwanza",
        "hela ya haraka", "hela bila stress", "hela imeingia", "hela inakuja",
        "jipatie hela", "jipe boost", "boost ya limit", "limit imeongezeka",
        "limit imepanda", "limit inapanda", "umepewa limit", "umepatiwa mkopo",
        "mteja wetu", "wateja wetu wamepata", "wamepata limit", "tumewasaidia",
        "mtu wangu", "bro tuma", "sis tuma", "mambo vipi tuma", "niko na deal",
        "deal ya fuliza", "deal ya mkopo", "kuna deal", "tuko na connect", "connect ya fuliza",
        "connect ya safaricom", "mtu wa ndani", "insider ya safaricom", "inside man safaricom",
        "nina connection safaricom", "contact wa safaricom", "ninaweza kuongeza limit yako",
    ],
    # Betting, "fixed match" and gambling funnels.
    "betting_fixed_match": [
        "fixed match", "fixed matches", "sure odds", "sure tips", "sure bet", "sure bets",
        "guaranteed odds", "guaranteed tips", "guaranteed win", "guaranteed winnings",
        "insider tips", "insider odds", "insider info", "vip tips", "vip odds",
        "rollover tips", "correct score tips", "correct score fixed", "ht ft fixed",
        "ht/ft fixed", "betting tips whatsapp", "betting tips telegram", "tips group",
        "jackpot tips", "sportpesa jackpot", "mega jackpot tips", "betika jackpot",
        "aviator signals", "aviator predictor", "aviator hack", "aviator tricks",
        "aviator sure", "aviator bot", "crash game hack", "crash predictor",
        "betting bot", "betting hack", "betting trick", "bet and win", "win big daily",
        "double your stake", "triple your stake", "stake multiplication", "bonus code",
        "promo code gives", "free bet", "free bets", "free spins", "free stake",
    ],
    # Romance / sympathy / emergency framings that precede a money request.
    "emotional_pretext": [
        "i am stranded", "i'm stranded", "stuck at the airport", "need urgent help", "need help urgently", "my child is sick",
        "my mother is sick", "my father is sick", "bail money", "police bail", "arrested and need",
        "i am a widow", "i am an orphan", "i am a soldier", "i am an engineer",
        "oil rig", "military officer", "us army", "my late husband", "my late father",
        "i want to invest in your country", "send me your details", "i will send you a gift",
        "parcel is held", "parcel held at customs", "customs clearance fee", "delivery fee",
        "courier fee", "package waiting", "undelivered parcel",
    ],
    # Fake charity / fundraising / "support" messages.
    "fake_support_charity": [
        "help me raise", "help raise funds", "send support to", "send your support",
        "donate to this paybill", "donate to this till", "kuchangia", "changia kwa", "send contributions", "burial fundraising", "funeral contributions",
        "school fees fundraising", "medical fundraising", "orphanage donation",
        "children's home donation", "sow a seed", "sow your seed",
        "send your seed", "miracle money", "financial breakthrough",
        "breakthrough miracle", "blessing money", "send a blessing", "tithe to this",
        "tithe via", "offering via m-pesa", "anointed oil",
    ],
}

# Single regex per category, compiled once. A phrase's edges are anchored with \b only where
# the phrase itself ends in a word character, so "t.me/" and "'yes'" still match literally.
def _phrase_pattern(phrase: str) -> str:
    parts = [re.escape(p) for p in re.split(r"[\s\-]+", phrase.strip()) if p]
    body = r"[\s\-]+".join(parts)
    head = r"\b" if re.match(r"\w", phrase.strip()[:1] or " ") else ""
    tail = r"\b" if re.match(r"\w", phrase.strip()[-1:] or " ") else ""
    return f"{head}{body}{tail}"


# Families that describe what the search is ABOUT rather than how a lure behaves. Every on-topic
# result matches them, so they are reported but never count toward the two-signal boost.
SUBJECT_FAMILIES = frozenset({"loan_limit_boost"})

# Exact handles of the real brand accounts. An official post about limits quotes lure wording
# ("increase your Fuliza limit"); it is the thing being impersonated, not an impersonator.
# Matched on the whole handle only, so a lookalike (safaricom_plc_ke) is not excused.
OFFICIAL_HANDLES = frozenset({"safaricomplc", "safaricom", "safaricom_care", "safaricomnews",
                              "safaricomethiopia", "mpesa", "mpesafoundation", "nse_plc",
                              "cmakenya", "centralbankkenya"})

COMPILED: dict[str, re.Pattern[str]] = {
    cat: re.compile("|".join(sorted((_phrase_pattern(p) for p in set(terms)), key=len, reverse=True)), re.I)
    for cat, terms in LEXICON.items()
}


def term_count() -> int:
    """Distinct phrases across all categories (after case-folding)."""
    return len({t.lower() for terms in LEXICON.values() for t in terms})


def match(text: str) -> dict[str, list[str]]:
    """Category -> distinct phrases found. Empty for text with no hits."""
    found: dict[str, list[str]] = {}
    for cat, rx in COMPILED.items():
        hits = {m.group(0).lower() for m in rx.finditer(text)}
        if hits:
            found[cat] = sorted(hits)
    return found
