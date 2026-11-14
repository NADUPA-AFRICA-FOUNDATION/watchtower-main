"""How lure posts dodge keyword filters, and the detector reading through each trick.

Each case is a disguise seen on (or modelled on) limit-boost and impersonation lures. The
assertion is always the same question: does the detector still see the lure, and does it
still leave the legitimate look-alike alone?
"""
import pytest

from core.deobfuscate import normalise, squeeze, variants
from core.sources import _bait_analysis, _lure_identity, is_likely_lure


def lure(title, text="", platform="facebook.com", path="/somepage/posts/1", kind="post"):
    fam, _, adv = _bait_analysis(title, text)
    ident = "" if adv else _lure_identity(platform, path, kind, title, text)
    return is_likely_lure({"bait_signals": fam, "advisory": adv, "lure_identity": ident})


@pytest.mark.parametrize("disguised,plain", [
    ("𝗙𝗨𝗟𝗜𝗭𝗔 𝗟𝗜𝗠𝗜𝗧 𝗜𝗡𝗖𝗥𝗘𝗔𝗦𝗘", "FULIZA LIMIT INCREASE"),        # styled Unicode
    ("Ｆｕｌｉｚａ", "Fuliza"),                                            # full-width
    ("Fulizа", "Fuliza"),                                                # Cyrillic а
    ("Fu​li‍za", "Fuliza"),                                    # zero-width characters
    ("F.u.l.i.z.a limit", "Fuliza limit"),                               # spaced-out letters
    ("M - P - E - S - A", "MPESA"),
])
def test_normalise_reads_through_disguises(disguised, plain):
    assert normalise(disguised) == plain


def test_digit_decoding_only_touches_words_with_letters():
    assert variants("Fuliz@ l1mit b00st") == ["Fuliz@ l1mit b00st", "Fuliza limit boost"]
    assert variants("WhatsApp 0712 345 678 till 123456") == ["WhatsApp 0712 345 678 till 123456"]   # numbers untouched
    assert squeeze("fulizzaa") == "fuliza"


@pytest.mark.parametrize("title,text", [
    ("𝗙𝗨𝗟𝗜𝗭𝗔 𝗟𝗜𝗠𝗜𝗧 𝗜𝗡𝗖𝗥𝗘𝗔𝗦𝗘", "Hit admin inbox, pay a small registration fee"),
    ("Fuliz@ l1mit b00st", "DM for details. Whatsapp 0712345678"),
    ("F.u.l.i.z.a increment", "send your details to our agent"),
])
def test_disguised_lures_are_still_flagged(title, text):
    assert lure(title, text)


def test_a_personal_number_or_till_next_to_the_scam_subject_is_enough():
    assert lure("Fuliza limit increase from Ksh 0 upto ksh 70,000", "Whatsapp 0141828922")
    assert lure("Fuliza limit increase", "pay through till number 123456")
    assert lure("Fuliza limit increase", "wa.me/254712345678")
    assert not lure("Fuliza limit increase explained", "Dial *334# to refresh your limit")   # official instructions


def test_offers_without_fee_words_are_flagged():
    assert lure("Fuliza limit boost available, strictly for safaricom lines older than 6 months", platform="instagram.com")
    assert lure("Do you need a legit fuliza increment", "just hit my dm", platform="instagram.com")
    assert lure("Fuliza increment", "Those who want fuliza increment make sure you provide the correct details", platform="t.me")


def test_account_names_built_from_brand_plus_amount_or_an_offer_bio():
    assert lure("Fuliza Upto 75k - Facebook", "13 followers", path="/p/Fuliza-Upto-75k-61593524833424/", kind="profile")
    assert lure("KCB MPESA (@kcb.mpesa7) | TikTok", "1148 Followers. Click on the link below to Apply.",
                platform="tiktok.com", path="/@kcb.mpesa7", kind="profile")
    assert lure("Hustler fund (@hustler_fund_ke)", "Huster fund increment kenya", platform="instagram.com",
                path="/hustler_fund_ke/", kind="profile")
    assert lure("FULIZA, KCB LOANS AND HUSTLER FUND INCREMENT",
                "You are invited to the channel FULIZA, KCB LOANS AND HUSTLER FUND INCREMENT . Click above to join.",
                platform="t.me", path="/+abcdef", kind="invite_link")


def test_legitimate_look_alikes_are_left_alone():
    # Real M-PESA agents are licensed shops.
    assert not lure("Genz M- pesa Agent (@naomycheruto)'s videos", "395 Likes, TikTok video from Genz M - pesa Agent",
                    platform="tiktok.com", path="/@naomycheruto/video/1")
    # Safaricom's own campaign line, on its own account.
    assert not lure("Safaricom PLC | Kuincrease fuliza limit ni very easy", "Swipe to get more information",
                    platform="instagram.com", path="/safaricomplc_/p/1")
    # A news post about the scam, and an official explainer.
    assert not lure("Pages claiming to increase your Fuliza limit are scams", "Beware! Don't click their links")
    assert not lure("How to increase KCB M-Pesa loan limit: The bank explains", platform="x.com",
                    path="/PeopleDailyKe/status/1")
    # A brand-named post (not an account) whose text happens to mention applying.
    assert not lure("M-Pesa agent business: how to apply for an agency", "Requirements and steps",
                    platform="tiktok.com", path="/@someone/video/1")


def test_naming_tricks_and_weak_pairs_found_on_unseen_data():
    # "hack" or "software" next to the brand sells something that cannot exist.
    assert lure("Hack money in mpesa - Facebook", "574 likes. Personal blog", path="/p/Hack-money-in-mpesa-1000665/", kind="profile")
    assert lure("Fuliza safaricom (@fuliza_software)", "Increase your fuliza limit with simple steps",
                platform="instagram.com", path="/fuliza_software/", kind="profile")
    # A Telegram preview that names the channel only as "view and join X right away".
    assert lure("Telegram: View @alliancegirls",
                "If you have Telegram, you can view and join FULIZA , KCB & M-SHWARI LOANS. (partners)GRADE UPGRADE 2026 right away.",
                platform="t.me", path="/alliancegirls", kind="channel")
    # A Facebook video is a post: its title is not an account name.
    assert not lure("Want to increase your Fuliza limit? Use Fuliza regularly and repay on time",
                    path="/watch/", kind="post")
    # Coverage of a real promotion: brand + "winner", and nothing about the scam.
    assert not lure("Malaba Town Lucky Winner | Safaricom Shangwe@25", "Safaricom prize, lucky draw, Safaricom promotion",
                    platform="tiktok.com", path="/@emuriafmtv/video/1")
    # ...but success stories and urgency beside the scam's subject are a lure.
    assert lure("Fuliza Increment", "From KSh 500 to over KSh 50,000! Thousands of Kenyans have already boosted. Apply now",
                platform="instagram.com", path="/p/DZE7Aw3ABeH/")
